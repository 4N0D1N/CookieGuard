"""Módulo de análisis heurístico de firmas y patrones en extensiones instaladas.

Detecta extensiones maliciosas o inyectadas que actúan como ladrones de cookies (Cookie Stealers),
inyecciones de scripts de C2 (Discord Webhooks, Telegram Bots) y técnicas de evasión
(MITRE ATT&CK T1176 / T1059.007).
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from .browsers import discover
from .common import log

MALICIOUS_PATTERNS = [
    (
        r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+",
        "Canal de exfiltración C2 vía Webhook de Discord",
        "Crítica"
    ),
    (
        r"https?://api\.telegram\.org/bot\d+:[A-Za-z0-9_\-]+/(?:sendMessage|sendDocument)",
        "Canal de exfiltración C2 vía Bot de Telegram",
        "Crítica"
    ),
    (
        r"\b(?:chrome|browser)\.cookies\.getAll\b",
        "Lectura masiva de todas las cookies del navegador (API cookies.getAll)",
        "Alta"
    ),
    (
        r"\beval\s*\(\s*(?:unescape|atob|decodeURIComponent)\b",
        "Ejecución de código dinámico ofuscado (eval con atob/unescape)",
        "Alta"
    ),
    (
        r"\b(?:chrome|browser)\.debugger\.attach\b",
        "Uso de API de depuración (debugger.attach) para interceptar sesiones",
        "Crítica"
    ),
    (
        r"document\.cookie.*?navigator\.sendBeacon",
        "Exfiltración asíncrona de document.cookie vía sendBeacon",
        "Alta"
    ),
]


def scan_extension_directory(ext_dir: Path) -> dict[str, Any]:
    """Escanea el código fuente (manifest.json, scripts .js) de una carpeta de extensión."""
    res: dict[str, Any] = {
        "ruta": str(ext_dir),
        "extension_id": ext_dir.name,
        "nombre": ext_dir.name,
        "version": None,
        "archivos_analizados": 0,
        "hallazgos": []
    }

    if not ext_dir.exists() or not ext_dir.is_dir():
        return res

    manifest_p = ext_dir / "manifest.json"
    if manifest_p.exists():
        try:
            m_data = json.loads(manifest_p.read_text(encoding="utf-8", errors="ignore"))
            res["nombre"] = m_data.get("name", ext_dir.name)
            res["version"] = m_data.get("version")
        except Exception:
            pass

    # Escanear archivos .js, .json y .html
    try:
        for f in ext_dir.rglob("*"):
            if f.is_file() and f.suffix in (".js", ".html", ".json"):
                # Saltar archivos extremadamente grandes (> 2MB) como librerías minificadas no relevantes
                if f.stat().st_size > 2 * 1024 * 1024:
                    continue

                res["archivos_analizados"] += 1
                try:
                    content = f.read_text(encoding="utf-8", errors="ignore")
                    for pattern, desc, sev in MALICIOUS_PATTERNS:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            res["hallazgos"].append({
                                "archivo": f.name,
                                "ruta_relativa": str(f.relative_to(ext_dir)),
                                "severidad": sev,
                                "patron": pattern,
                                "descripcion": desc,
                                "coincidencias": len(matches)
                            })
                except Exception:
                    pass
    except Exception as e:
        log(f"[ExtensionScanner] Error en rglob de {ext_dir}: {e}")

    return res


def scan_all_browser_extensions() -> dict[str, Any]:
    """Escanea todas las extensiones instaladas en los perfiles de navegador soportados."""
    profiles = discover()
    extensions_scanned = 0
    alerts: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []

    for p in profiles:
        p_path = p.path
        ext_base = p_path / "Extensions"
        if ext_base.exists() and ext_base.is_dir():
            try:
                for ext_dir in ext_base.iterdir():
                    if ext_dir.is_dir():
                        # Si tiene subcarpetas de versión (formato Chrome estándar)
                        sub_versions = [s for s in ext_dir.iterdir() if s.is_dir()]
                        targets = sub_versions if sub_versions else [ext_dir]
                        for t in targets:
                            extensions_scanned += 1
                            ext_info = scan_extension_directory(t)
                            ext_info["navegador"] = p.name
                            ext_info["perfil"] = p.profile_name
                            results.append(ext_info)
                            if ext_info["hallazgos"]:
                                alerts.append(ext_info)
            except Exception as e:
                log(f"[ExtensionScanner] Error listando extensiones en {ext_base}: {e}")

    return {
        "total_extensiones_analizadas": extensions_scanned,
        "total_alertas": len(alerts),
        "alertas": alerts,
        "extensiones": results,
        "recomendacion": "Si detectas extensiones con webhooks de Discord, bots de Telegram o APIs de depuración, desinstálalas y revoca sesiones inmediatamente." if alerts else None
    }
