"""Auditor detallado de extensiones de navegador y permisos abusivos.

Detecta extensiones maliciosas, cargadas lateralmente (sideloaded) o con permisos excesivos
capaces de interceptar o exfiltrar cookies de sesion y peticiones web (MITRE T1176).

Zero dependencias externas. Solo libreria estandar de Python.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .browsers import Profile, discover
from .common import log

PERMISOS_CRITICOS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}
APIS_SENSIBLES = {"cookies", "webRequest", "webRequestBlocking", "declarativeNetRequest", "debugger", "nativeMessaging", "management"}
OFFICIAL_UPDATE_URLS = {
    "https://clients2.google.com/service/update2/crx",
    "https://edge.microsoft.com/extensionwebstorebase/v1/crx"
}


def audit_browser_extensions(profiles: list[Profile] | None = None) -> list[dict[str, Any]]:
    """Escanea y audita todas las extensiones instaladas en los perfiles de los navegadores."""
    if profiles is None:
        profiles = discover()

    resultados: list[dict[str, Any]] = []

    for prof in profiles:
            p_dir = prof.path
            ext_dir = p_dir / "Extensions"
            if not ext_dir.exists() or not ext_dir.is_dir():
                continue

            try:
                for ext_id_path in ext_dir.iterdir():
                    if not ext_id_path.is_dir() or ext_id_path.name.startswith("."):
                        continue
                    ext_id = ext_id_path.name

                    # Las extensiones se organizan por carpetas de version
                    for ver_path in ext_id_path.iterdir():
                        if not ver_path.is_dir():
                            continue
                        manifest_file = ver_path / "manifest.json"
                        if not manifest_file.exists():
                            continue

                        try:
                            manifest = json.loads(manifest_file.read_text(encoding="utf-8-sig", errors="ignore"))
                        except Exception:
                            continue

                        nombre = manifest.get("name", ext_id)
                        # Resolver cadenas localizadas __MSG_...__
                        if isinstance(nombre, str) and nombre.startswith("__MSG_"):
                            nombre = ext_id

                        version = manifest.get("version", "desconocida")
                        perms = set(manifest.get("permissions", []))
                        optional_perms = set(manifest.get("optional_permissions", []))
                        host_perms = set(manifest.get("host_permissions", []))
                        all_perms = perms | optional_perms | host_perms

                        update_url = manifest.get("update_url", "")
                        es_oficial = any(u in update_url for u in OFFICIAL_UPDATE_URLS)
                        es_sideloaded = not update_url

                        # Evaluacion de riesgo
                        tiene_all_urls = bool(all_perms & PERMISOS_CRITICOS)
                        tiene_cookies = "cookies" in all_perms
                        tiene_webrequest = bool(all_perms & {"webRequest", "webRequestBlocking"})
                        tiene_debugger = "debugger" in all_perms

                        puntos_riesgo = 0
                        motivos: list[str] = []

                        if tiene_all_urls:
                            puntos_riesgo += 4
                            motivos.append("Acceso indiscriminado a todas las paginas web (<all_urls>)")
                        if tiene_cookies:
                            puntos_riesgo += 4
                            motivos.append("Permiso para leer y modificar cookies de sesion ('cookies')")
                        if tiene_webrequest:
                            puntos_riesgo += 3
                            motivos.append("Capacidad de interceptar o bloquear peticiones web ('webRequest')")
                        if tiene_debugger:
                            puntos_riesgo += 5
                            motivos.append("Permiso de depuracion de bajo nivel ('debugger')")
                        if es_sideloaded:
                            puntos_riesgo += 3
                            motivos.append("Cargada localmente o sin origen en Web Store oficial")

                        if puntos_riesgo >= 8:
                            severidad = "CRITICA"
                        elif puntos_riesgo >= 5:
                            severidad = "ALTA"
                        elif puntos_riesgo >= 2:
                            severidad = "MEDIA"
                        else:
                            severidad = "BAJA"

                        resultados.append({
                            "browser": b.name,
                            "profile": prof.name,
                            "extension_id": ext_id,
                            "nombre": nombre,
                            "version": version,
                            "ruta": str(ver_path),
                            "es_oficial": es_oficial,
                            "es_sideloaded": es_sideloaded,
                            "permisos": sorted(list(all_perms)),
                            "puntos_riesgo": puntos_riesgo,
                            "severidad": severidad,
                            "motivos": motivos
                        })
            except Exception as e:
                log(f"Error escaneando extensiones en {prof.name}: {e}")

    return sorted(resultados, key=lambda x: x["puntos_riesgo"], reverse=True)
