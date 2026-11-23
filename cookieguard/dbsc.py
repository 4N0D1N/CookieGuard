"""DBSC (Device Bound Session Credentials) compatibility and protection checker.

DBSC (IETF Draft / Chromium WICG) binds session cookies to hardware TPM/keys,
preventing stolen cookies from being replayed on an attacker's machine.
"""
from __future__ import annotations

import re
from typing import Any
from .browsers import Profile


# Known high-value services supporting or deploying DBSC (Google, Microsoft, Okta, Cloudflare)
DBSC_AWARE_DOMAINS = {
    "accounts.google.com": {"servicio": "Google Accounts", "estado": "Desplegado", "soporte": "TPM / Secure Enclave"},
    "google.com": {"servicio": "Google Workspace / Services", "estado": "Desplegado", "soporte": "TPM / Secure Enclave"},
    "login.microsoftonline.com": {"servicio": "Microsoft Entra ID (Azure AD)", "estado": "En despliegue", "soporte": "Windows Hello / TPM"},
    "login.live.com": {"servicio": "Microsoft Account (Outlook/Live)", "estado": "En despliegue", "soporte": "Windows Hello / TPM"},
    "okta.com": {"servicio": "Okta Identity Cloud", "estado": "Early Access / Pilot", "soporte": "DBSC Hardware Token"},
    "github.com": {"servicio": "GitHub", "estado": "Planificado", "soporte": "WebAuthn / DBSC Draft"},
}


def evaluate_dbsc_readiness(profiles: list[Profile], sessions: list[dict]) -> dict[str, Any]:
    """Evalua si los navegadores instalados y las sesiones activas son compatibles con DBSC."""
    compatible_browsers = []
    incompatible_browsers = []

    for p in profiles:
        # Chromium 127+ includes native DBSC flags
        ver = getattr(p, "version", None) or ""
        if not ver and p.family == "chromium":
            lv = p.root / "Last Version"
            if lv.is_file():
                try:
                    ver = lv.read_text(encoding="utf-8", errors="ignore").strip()
                except Exception:
                    pass
        major = 0
        m = re.match(r"^(\d+)", ver)
        if m:
            major = int(m.group(1))

        info = {
            "navegador": p.browser,
            "familia": p.family,
            "perfil": p.profile,
            "version": ver or "desconocida",
            "soporta_dbsc": False,
            "motivo": "",
        }

        if p.family == "chromium":
            if major >= 127:
                info["soporta_dbsc"] = True
                info["motivo"] = f"Chromium v{major} soporta DBSC de forma nativa con TPM"
                compatible_browsers.append(info)
            elif major > 0:
                info["motivo"] = f"Chromium v{major} es anterior a la v127 (requiere actualizar)"
                incompatible_browsers.append(info)
            else:
                info["motivo"] = "Version no detectable; se asume compatible si esta actualizado"
                compatible_browsers.append(info)
        elif p.family == "firefox":
            info["motivo"] = "Firefox tiene DBSC en fase de discusion IETF; no desplegado de forma nativa"
            incompatible_browsers.append(info)
        else:
            info["motivo"] = "Navegador sin soporte confirmado para DBSC"
            incompatible_browsers.append(info)

    # Cross-reference user sessions with DBSC-aware domains
    sesiones_protegibles = []
    seen_domains = set()

    for s in sessions:
        domain = (s.get("dominio") or "").lstrip(".").lower()
        if domain in seen_domains:
            continue
        for dbsc_domain, meta in DBSC_AWARE_DOMAINS.items():
            if domain == dbsc_domain or domain.endswith("." + dbsc_domain):
                seen_domains.add(domain)
                sesiones_protegibles.append({
                    "dominio": domain,
                    "servicio": meta["servicio"],
                    "estado_dbsc": meta["estado"],
                    "soporte_hardware": meta["soporte"],
                    "criticidad": s.get("criticidad", "alta"),
                })
                break

    recomendaciones = []
    if incompatible_browsers:
        recomendaciones.append("Actualiza tus navegadores Chromium (Chrome, Edge, Brave) a la version 127 o superior para habilitar proteccion por TPM.")
    if sesiones_protegibles:
        recomendaciones.append(f"Tienes {len(sesiones_protegibles)} servicio(s) critico(s) (ej: Google, Microsoft) con soporte DBSC: si vinculas tus sesiones a hardware TPM, las cookies robadas no funcionaran fuera de este equipo.")
    else:
        recomendaciones.append("Habilita la autenticacion multifactor (FIDO2/WebAuthn) en tus servicios para mitigar el impacto si una sesion es robada.")

    return {
        "compatible": len(compatible_browsers) > 0,
        "navegadores_compatibles": compatible_browsers,
        "navegadores_incompatibles": incompatible_browsers,
        "sesiones_protegibles": sesiones_protegibles,
        "total_sesiones_protegibles": len(sesiones_protegibles),
        "recomendaciones": recomendaciones,
    }
