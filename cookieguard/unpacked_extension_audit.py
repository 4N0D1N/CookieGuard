"""Módulo de auditoría de extensiones no empaquetadas (Unpacked) y Modo Desarrollador.

Detecta extensiones instaladas desde carpetas locales fuera de las tiendas oficiales
(Chrome Web Store / Edge Add-ons), banderas de lanzamiento sospechosas como
--load-extension, y el estado del Modo Desarrollador en perfiles Chromium (MITRE ATT&CK T1176 / T1562.001).

Zero dependencias externas. 100% biblioteca estándar de Python.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .browsers import Profile, discover
from .common import IS_LINUX, IS_WIN, log
from .process_hunter import _list_processes_quick

# Permisos críticos que en una extensión desempaquetada representan máximo riesgo
HIGH_RISK_PERMISSIONS = {
    "<all_urls>",
    "*://*/*",
    "http://*/*",
    "https://*/*",
    "cookies",
    "webRequest",
    "webRequestBlocking",
    "declarativeNetRequest",
    "debugger",
    "nativeMessaging",
    "management",
    "proxy",
}

# Rutas típicamente usadas por malware o actores maliciosos para soltar extensiones
SUSPICIOUS_PATH_PATTERNS = [
    re.compile(r"[/\\]temp[/\\]", re.IGNORECASE),
    re.compile(r"[/\\]tmp[/\\]", re.IGNORECASE),
    re.compile(r"[/\\]appdata[/\\]local[/\\]temp[/\\]", re.IGNORECASE),
    re.compile(r"[/\\]downloads[/\\]", re.IGNORECASE),
    re.compile(r"[/\\]descargas[/\\]", re.IGNORECASE),
    re.compile(r"[/\\]desktop[/\\]", re.IGNORECASE),
    re.compile(r"[/\\]escritorio[/\\]", re.IGNORECASE),
]


def audit_profile_unpacked_extensions(profile_path: Path) -> List[Dict[str, Any]]:
    """Audita Preferences y Secure Preferences de un perfil Chromium en busca de extensiones desempaquetadas."""
    findings: List[Dict[str, Any]] = []
    p_path = Path(profile_path)
    if not p_path.is_dir():
        return findings

    # Revisar Preferences y Secure Preferences
    pref_files = [p_path / "Preferences", p_path / "Secure Preferences"]

    for pf in pref_files:
        if not pf.is_file():
            continue
        try:
            with open(pf, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except Exception as e:
            log(f"No se pudo parsear {pf.name} en {p_path}: {e}")
            continue

        ext_data = data.get("extensions", {})
        if not isinstance(ext_data, dict):
            continue

        # 1. Comprobar si developer_mode está activado
        dev_mode = (
            ext_data.get("ui", {}).get("developer_mode", False)
            if isinstance(ext_data.get("ui"), dict)
            else ext_data.get("developer_mode", False)
        )
        if dev_mode is True:
            findings.append({
                "tipo": "developer_mode_activo",
                "perfil": str(p_path),
                "fichero": pf.name,
                "nivel": "Medio",
                "mitre": "T1562.001",
                "descripcion": "El Modo Desarrollador está activado en las preferencias del navegador.",
                "detalle": "Permite la carga de extensiones locales no verificadas sin advertencias del navegador.",
                "remediacion": "Desactiva el Modo Desarrollador en chrome://extensions si no desarrollas software."
            })

        # 2. Comprobar settings de extensiones
        settings = ext_data.get("settings", {})
        if not isinstance(settings, dict):
            continue

        for ext_id, cfg in settings.items():
            if not isinstance(cfg, dict):
                continue

            manifest = cfg.get("manifest", {})
            location = cfg.get("location", 0)  # 4 = UNPACKED_LOCATION en Chromium
            path_str = cfg.get("path", "")
            install_type = cfg.get("install_type", "")

            is_unpacked = (
                location == 4
                or install_type in ("development", "unpacked", "sideload")
                or (bool(path_str) and not str(path_str).startswith(str(p_path / "Extensions")))
            )

            if is_unpacked and path_str:
                ext_name = manifest.get("name", ext_id) if isinstance(manifest, dict) else ext_id
                perms = set()
                if isinstance(manifest, dict):
                    raw_perms = manifest.get("permissions", [])
                    if isinstance(raw_perms, list):
                        perms = set(raw_perms)

                risky = perms.intersection(HIGH_RISK_PERMISSIONS)
                is_suspicious_dir = any(pat.search(path_str) for pat in SUSPICIOUS_PATH_PATTERNS)

                # Nivel de riesgo
                if risky or is_suspicious_dir:
                    nivel = "Crítica" if ("<all_urls>" in risky or "cookies" in risky or "debugger" in risky) else "Alta"
                else:
                    nivel = "Medio"

                findings.append({
                    "tipo": "extension_desempaquetada",
                    "id": ext_id,
                    "nombre": ext_name,
                    "perfil": str(p_path),
                    "fichero": pf.name,
                    "ruta": path_str,
                    "location": location,
                    "install_type": install_type,
                    "permisos": list(perms),
                    "permisos_criticos": list(risky),
                    "ubicacion_sospechosa": is_suspicious_dir,
                    "nivel": nivel,
                    "mitre": "T1176",
                    "descripcion": f"Extensión desempaquetada cargada localmente: '{ext_name}' ({ext_id}).",
                    "detalle": f"Ruta: {path_str}. Permisos sensibles: {', '.join(risky) if risky else 'Ninguno detectado'}.",
                    "remediacion": "Elimina esta extensión desde la página de extensiones o elimina la carpeta origen."
                })

    return findings


def audit_running_browser_flags(processes: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Busca banderas de ejecución sospechosas en procesos de navegadores activos."""
    findings: List[Dict[str, Any]] = []

    if processes is None:
        procs = _list_processes_quick()
    else:
        procs = processes

    browser_binaries = {
        "chrome", "chrome.exe", "msedge", "msedge.exe", "brave", "brave.exe",
        "vivaldi", "vivaldi.exe", "chromium", "chromium-browser", "opera", "opera.exe"
    }

    suspicious_flags = [
        ("--load-extension", "Carga forzada de extensión local sin empaquetar", "Crítica", "T1176"),
        ("--disable-web-security", "Desactivación de política del mismo origen (SOP)", "Crítica", "T1562.001"),
        ("--remote-debugging-port", "Apertura de puerto de depuración CDP (robo de sesión vía DevTools)", "Crítica", "T1059.007"),
        ("--allow-running-insecure-content", "Permite contenido HTTP mixto inseguro", "Alta", "T1562.001"),
    ]

    for p in procs:
        p_name = p.get("name", "").lower()
        if p_name not in browser_binaries:
            continue

        cmdline = p.get("cmd", "") or p.get("cmdline", "")
        pid = p.get("pid", 0)

        for flag, desc, nivel, mitre in suspicious_flags:
            if flag in cmdline:
                findings.append({
                    "tipo": "flag_navegador_sospechosa",
                    "proceso": p_name,
                    "pid": pid,
                    "flag": flag,
                    "nivel": nivel,
                    "mitre": mitre,
                    "descripcion": f"Proceso {p_name} (PID {pid}) ejecutado con '{flag}'.",
                    "detalle": desc,
                    "cmdline": cmdline[:300] if len(cmdline) > 300 else cmdline,
                    "remediacion": f"Detén el proceso inmediatamente (PID {pid}) y revisa cómo fue lanzado."
                })

    return findings


def audit_all_unpacked_extensions(
    profiles: Optional[List[Profile]] = None,
    processes: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """Audita todos los perfiles de navegadores y procesos en busca de extensiones locales y flags maliciosas."""
    if profiles is None:
        profiles = discover()

    profile_findings: List[Dict[str, Any]] = []
    seen_profiles = set()

    for prof in profiles:
        if prof.family != "chromium":
            continue
        p_str = str(prof.path).lower()
        if p_str in seen_profiles:
            continue
        seen_profiles.add(p_str)
        profile_findings.extend(audit_profile_unpacked_extensions(prof.path))

    proc_findings = audit_running_browser_flags(processes)
    all_findings = profile_findings + proc_findings

    criticidad = "Limpio"
    if any(f.get("nivel") == "Crítica" for f in all_findings):
        criticidad = "Crítica"
    elif any(f.get("nivel") == "Alta" for f in all_findings):
        criticidad = "Alta"
    elif any(f.get("nivel") == "Medio" for f in all_findings):
        criticidad = "Medio"

    return {
        "total_hallazgos": len(all_findings),
        "criticidad": criticidad,
        "extensiones_desempaquetadas": [f for f in profile_findings if f.get("tipo") == "extension_desempaquetada"],
        "developer_mode": [f for f in profile_findings if f.get("tipo") == "developer_mode_activo"],
        "flags_procesos": proc_findings,
        "todos_los_hallazgos": all_findings,
    }
