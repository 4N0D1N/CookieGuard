"""Módulo de auditoría de sincronización de perfiles y cuentas conectadas.

Audita si los perfiles de navegador (Chrome, Edge, Brave, Firefox) tienen sincronización
activa hacia cuentas externas (Google Sync, Microsoft Sync, Firefox Sync).
Detecta si un atacante ha vinculado una cuenta ajena para recibir pasivamente
cookies, contraseñas e historial replicados en la nube (Browser Account Hijacking).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .browsers import Profile, discover
from .common import log


def mask_email(email: str) -> str:
    """Enmascara una dirección de correo para preservar la privacidad en informes."""
    if not email or "@" not in email:
        return email
    user, domain = email.split("@", 1)
    if len(user) <= 2:
        masked_user = user[0] + "*"
    else:
        masked_user = user[0] + "*" * (len(user) - 2) + user[-1]
    return f"{masked_user}@{domain}"


def audit_chromium_sync(profile: Profile, anonymize: bool = True) -> dict[str, Any]:
    """Audita la sincronización y cuentas conectadas en un perfil Chromium."""
    pref_file = profile.path / "Preferences"
    res: dict[str, Any] = {
        "perfil": profile.profile,
        "navegador": profile.browser,
        "familia": "chromium",
        "ruta": str(profile.path),
        "sync_activo": False,
        "cuentas": [],
        "servicios_sincronizados": [],
        "hallazgos": [],
        "estado": "sin_datos"
    }

    if not pref_file.is_file():
        return res

    try:
        data = json.loads(pref_file.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        res["estado"] = "error"
        res["hallazgos"].append(f"Error leyendo Preferences: {e}")
        return res

    res["estado"] = "ok"

    # 1. Cuentas vinculadas en account_info
    account_info = data.get("account_info", [])
    cuentas = []
    if isinstance(account_info, list):
        for acc in account_info:
            if not isinstance(acc, dict):
                continue
            raw_email = acc.get("email", "")
            hosted_domain = acc.get("hosted_domain", "")
            cuentas.append({
                "email": mask_email(raw_email) if anonymize else raw_email,
                "dominio": hosted_domain or (raw_email.split("@")[1] if "@" in raw_email else ""),
                "gaia_id": acc.get("gaia_id", "")[:6] + "..." if acc.get("gaia_id") else "",
            })

    # Edge account info
    ms_account = data.get("ms_edge_account_info", {})
    if ms_account and isinstance(ms_account, dict):
        raw_email = ms_account.get("email", "")
        if raw_email:
            cuentas.append({
                "email": mask_email(raw_email) if anonymize else raw_email,
                "dominio": raw_email.split("@")[1] if "@" in raw_email else "",
                "tipo": "Microsoft Edge Account"
            })

    res["cuentas"] = cuentas

    # 2. Configuración de Sync
    sync_data = data.get("sync", {})
    has_setup = sync_data.get("has_setup_completed", False)
    sync_requested = sync_data.get("requested", False)
    res["sync_activo"] = bool(has_setup or sync_requested or len(cuentas) > 0)

    # Tipos de datos sincronizados
    servicios = []
    if sync_data.get("sync_everything", False):
        servicios.append("Todo (Contraseñas, Cookies, Historial, Extensiones, Marcadores)")
    else:
        for k, v in sync_data.items():
            if k.startswith("sync_") and v is True:
                servicios.append(k.replace("sync_", ""))
    res["servicios_sincronizados"] = servicios

    # 3. Comprobación de anomalías y riesgos
    if res["sync_activo"] and not cuentas:
        res["hallazgos"].append("La sincronización de perfil figura activa pero no se encontró cuenta identificable registrada.")

    if len(cuentas) > 1:
        res["hallazgos"].append(f"Múltiples cuentas ({len(cuentas)}) asociadas en el mismo perfil de navegador.")

    if sync_data.get("sync_everything", False) and len(cuentas) > 0:
        res["hallazgos"].append("Sincronización total ('sync_everything') activada: credenciales y sesiones se replican a la nube.")

    return res


def audit_firefox_sync(profile: Profile, anonymize: bool = True) -> dict[str, Any]:
    """Audita la sincronización y cuentas en un perfil de Firefox (Firefox Sync)."""
    res: dict[str, Any] = {
        "perfil": profile.profile,
        "navegador": profile.browser,
        "familia": "firefox",
        "ruta": str(profile.path),
        "sync_activo": False,
        "cuentas": [],
        "servicios_sincronizados": [],
        "hallazgos": [],
        "estado": "sin_datos"
    }

    # 1. Comprobar signedInUser.json (contiene la cuenta activa de Firefox Sync)
    signed_in_file = profile.path / "signedInUser.json"
    if signed_in_file.is_file():
        try:
            data = json.loads(signed_in_file.read_text(encoding="utf-8", errors="replace"))
            raw_email = data.get("email", "")
            verified = data.get("verified", False)
            if raw_email:
                res["sync_activo"] = True
                res["cuentas"].append({
                    "email": mask_email(raw_email) if anonymize else raw_email,
                    "dominio": raw_email.split("@")[1] if "@" in raw_email else "",
                    "verificado": verified
                })
        except Exception as e:
            res["hallazgos"].append(f"Error analizando signedInUser.json: {e}")

    # 2. Comprobar prefs.js buscando servicios de sync
    prefs_file = profile.path / "prefs.js"
    if prefs_file.is_file():
        try:
            content = prefs_file.read_text(encoding="utf-8", errors="replace")
            if "services.sync.username" in content:
                res["sync_activo"] = True
                m = re.search(r'user_pref\("services\.sync\.username",\s*"([^"]+)"\)', content)
                if m:
                    u = m.group(1)
                    if not any(c.get("email") == u or mask_email(u) in c.get("email", "") for c in res["cuentas"]):
                        res["cuentas"].append({
                            "email": mask_email(u) if anonymize else u,
                            "tipo": "Firefox Sync Prefs"
                        })
        except Exception:
            pass

    if res["sync_activo"]:
        res["estado"] = "ok"
        res["hallazgos"].append("Firefox Sync está configurado en este perfil; verifica que la cuenta pertenezca al usuario.")
    else:
        res["estado"] = "sin_sync"

    return res


def audit_profile_sync(profile: Profile, anonymize: bool = True) -> dict[str, Any]:
    """Audita la sincronización del perfil según su familia."""
    if profile.family == "chromium":
        return audit_chromium_sync(profile, anonymize=anonymize)
    return audit_firefox_sync(profile, anonymize=anonymize)


def audit_all_profiles_sync(profiles: list[Profile] | None = None, anonymize: bool = True) -> dict[str, Any]:
    """Audita las cuentas y sincronización en todos los perfiles disponibles."""
    profs = profiles if profiles is not None else discover()
    resultados: list[dict[str, Any]] = []
    con_sync = 0
    total_cuentas = 0
    alertas = 0

    for p in profs:
        r = audit_profile_sync(p, anonymize=anonymize)
        resultados.append(r)
        if r.get("sync_activo"):
            con_sync += 1
        total_cuentas += len(r.get("cuentas", []))
        if r.get("hallazgos"):
            alertas += len(r["hallazgos"])

    return {
        "total_perfiles": len(resultados),
        "perfiles_con_sync": con_sync,
        "total_cuentas_detectadas": total_cuentas,
        "total_alertas": alertas,
        "perfiles": resultados
    }
