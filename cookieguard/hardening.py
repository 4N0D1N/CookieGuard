"""Módulo de auditoría y endurecimiento de configuración y preferencias del navegador.

Audita ficheros Preferences y Secure Preferences para detectar configuraciones inseguras,
extensiones en modo desarrollador, o desactivación de defensas contra malware.
"""
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Any
from .browsers import Profile
from .common import log


def audit_profile_preferences(profile: Profile) -> dict[str, Any]:
    """Audita la configuración del perfil y devuelve hallazgos de seguridad."""
    pref_file = profile.path / "Preferences"
    if not pref_file.is_file():
        return {
            "perfil": profile.profile,
            "navegador": profile.browser,
            "estado": "sin_datos",
            "puntuacion": 100,
            "hallazgos": [],
            "recomendaciones": [],
        }

    try:
        data = json.loads(pref_file.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        return {
            "perfil": profile.profile,
            "navegador": profile.browser,
            "estado": "error",
            "puntuacion": 50,
            "hallazgos": [f"No se pudo parsear Preferences: {e}"],
            "recomendaciones": [],
        }

    hallazgos = []
    recomendaciones = []
    puntuacion = 100

    # 1. Modo desarrollador de extensiones (facilita carga de extensiones maliciosas)
    ext_settings = data.get("extensions", {})
    ui_settings = ext_settings.get("ui", {})
    if ui_settings.get("developer_mode", False):
        hallazgos.append("Modo desarrollador de extensiones ACTIVADO (permite cargar extensiones no firmadas desde disco)")
        recomendaciones.append("Desactiva el Modo Desarrollador en chrome://extensions si no desarrollas extensiones")
        puntuacion -= 20

    # 2. SafeBrowsing
    safebrowsing = data.get("safebrowsing", {})
    if safebrowsing.get("enabled") is False:
        hallazgos.append("Google SafeBrowsing DESACTIVADO (protección contra phishing y descargas maliciosas apagada)")
        recomendaciones.append("Reactiva la navegación segura en la configuración de privacidad del navegador")
        puntuacion -= 30

    # 3. Cookies de terceros y retención
    content_settings = data.get("profile", {}).get("default_content_setting_values", {})
    # block third-party cookies is typically represented or configured
    block_3rd = data.get("profile", {}).get("block_third_party_cookies", False)
    if not block_3rd and content_settings.get("cookies") == 1:
        # Default allow all cookies
        recomendaciones.append("Considera bloquear cookies de terceros o configurar borrado de cookies al cerrar el navegador")

    # 4. Comprobar extensiones instaladas sin tienda oficial (sideloaded)
    ext_installed = ext_settings.get("settings", {})
    unpacked_extensions = []
    for ext_id, ext_data in ext_installed.items():
        if not isinstance(ext_data, dict):
            continue
        location = ext_data.get("location")
        # location 4 = LOAD (unpacked from local disk)
        if location == 4:
            manifest = ext_data.get("manifest", {})
            name = manifest.get("name") or ext_id
            unpacked_extensions.append(f"{name} ({ext_id[:8]}...) cargada desde {ext_data.get('path', 'disco')}")

    if unpacked_extensions:
        hallazgos.append(f"Se detectaron {len(unpacked_extensions)} extension(es) desempaquetadas locales: " + ", ".join(unpacked_extensions[:3]))
        recomendaciones.append("Revisa las extensiones locales en disco; los stealers suelen inyectar extensiones modificadas")
        puntuacion -= 25

    puntuacion = max(0, min(100, puntuacion))

    return {
        "perfil": profile.profile,
        "navegador": profile.browser,
        "ruta": str(profile.path),
        "estado": "alerta" if hallazgos else "ok",
        "puntuacion": puntuacion,
        "hallazgos": hallazgos,
        "recomendaciones": recomendaciones,
    }


def audit_all_profiles(profiles: list[Profile]) -> dict[str, Any]:
    """Audita todos los perfiles de navegador detectados."""
    resultados = []
    total_hallazgos = 0
    puntuacion_media = 100

    for p in profiles:
        r = audit_profile_preferences(p)
        resultados.append(r)
        total_hallazgos += len(r.get("hallazgos", []))

    if resultados:
        puntuacion_media = round(sum(r["puntuacion"] for r in resultados) / len(resultados))

    return {
        "puntuacion_media": puntuacion_media,
        "total_hallazgos": total_hallazgos,
        "perfiles": resultados,
    }


def backup_preferences(profile: Profile) -> Path | None:
    """Crea una copia de seguridad timestamped de Preferences antes de cualquier ajuste."""
    pref = profile.path / "Preferences"
    if not pref.is_file():
        return None
    bdir = profile.path / "cookieguard_backups"
    bdir.mkdir(parents=True, exist_ok=True)
    dst = bdir / f"Preferences_backup_{int(time.time())}.json"
    try:
        shutil.copy2(pref, dst)
        return dst
    except Exception as e:
        log(f"Error creando backup de Preferences: {e}")
        return None
