"""Módulo de invalidación y revocación rápida de sesiones (1-Click Invalidator).

Genera scripts ejecutables por lotes (Windows CMD y Linux Bash) y enlaces directos
para que la víctima o el analista abran simultáneamente los paneles de seguridad
y cierren todas las sesiones activas en los principales proveedores de identidad.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .common import IS_WIN, data_dir, log


REVOCATION_URLS = {
    "google": "https://myaccount.google.com/device-activity",
    "microsoft": "https://account.microsoft.com/devices",
    "github": "https://github.com/settings/sessions",
    "discord": "https://discord.com/channels/@me",
    "amazon": "https://www.amazon.es/gp/css/yourstores/manage",
    "aws": "https://us-east-1.console.aws.amazon.com/iam/home#/security_credentials",
    "twitter": "https://twitter.com/settings/sessions",
    "x": "https://twitter.com/settings/sessions",
    "linkedin": "https://www.linkedin.com/psettings/sessions",
    "telegram": "https://web.telegram.org/a/#?settings=devices",
    "apple": "https://appleid.apple.com/account/manage",
    "meta": "https://accountscenter.facebook.com/password_and_security",
    "facebook": "https://accountscenter.facebook.com/password_and_security",
    "instagram": "https://accountscenter.instagram.com/password_and_security",
    "binance": "https://www.binance.com/es/my/security/device-management",
    "coinbase": "https://www.coinbase.com/settings/activity"
}


def get_revocation_targets(grupos: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Identifica las URLs directas de revocación para los servicios detectados."""
    targets = []
    seen = set()

    for g in grupos:
        nombre = (g.get("nombre") or "").lower()
        dom = (g.get("dominio") or "").lower()

        url = g.get("url_revocacion")
        if not url or "google.com/search" in url:
            for k, u in REVOCATION_URLS.items():
                if k in nombre or k in dom:
                    url = u
                    break

        if not url:
            url = f"https://www.google.com/search?q=cerrar+todas+las+sesiones+{g.get('nombre', dom)}"

        key = (g.get("nombre", dom), url)
        if key not in seen:
            seen.add(key)
            targets.append({
                "servicio": g.get("nombre", dom),
                "criticidad": g.get("criticidad", "Media"),
                "dominio": dom,
                "url": url
            })

    return targets


def generate_batch_revocation_script(grupos: list[dict[str, Any]], output_dir: Path | None = None) -> str:
    """Genera un script por lotes que abre las páginas de revocación de sesiones en el navegador."""
    targets = get_revocation_targets(grupos)
    if output_dir is None:
        target_dir = data_dir() / "informes"
    else:
        target_dir = Path(output_dir)

    target_dir.mkdir(parents=True, exist_ok=True)

    if IS_WIN:
        script_file = target_dir / "Revocar_Todas_Las_Sesiones.cmd"
        lines = [
            "@echo off",
            "chcp 65001 >nul",
            "title CookieGuard - Revocación Rápida de Sesiones",
            "echo =================================================================",
            "echo  🚨 COOKIEGUARD - APERTURA DE PANELES DE SEGURIDAD PARA REVOCACIÓN",
            "echo =================================================================",
            "echo.",
            "echo Abriendo las páginas de gestión de sesiones en tu navegador predeterminado...",
            "echo En cada página, pulsa en 'Cerrar todas las demás sesiones' y cambia la contraseña.",
            "pause",
            ""
        ]
        for t in targets:
            lines.append(f':: Servicio: {t.get("servicio", "")} ({t.get("criticidad", "")})')
            lines.append(f'start "" "{t["url"]}"')
        lines.extend([
            "",
            "echo.",
            "echo [OK] Se han lanzado las páginas de seguridad.",
            "pause"
        ])
    else:
        script_file = target_dir / "revocar_todas_las_sesiones.sh"
        lines = [
            "#!/bin/bash",
            "echo '================================================================='",
            "echo ' 🚨 COOKIEGUARD - APERTURA DE PANELES DE SEGURIDAD PARA REVOCACIÓN'",
            "echo '================================================================='",
            "echo 'Abriendo las páginas de gestión de sesiones en tu navegador predeterminado...'",
            ""
        ]
        for t in targets:
            lines.append(f'# Servicio: {t.get("servicio", "")} ({t.get("criticidad", "")})')
            lines.append(f'xdg-open "{t["url"]}" 2>/dev/null || open "{t["url"]}" 2>/dev/null &')
        lines.extend([
            "",
            "echo '[OK] Páginas de seguridad abiertas en pestañas de tu navegador.'"
        ])

    script_file.write_text("\n".join(lines), encoding="utf-8")
    if not IS_WIN:
        try:
            os.chmod(script_file, 0o755)
        except Exception:
            pass

    log(f"[Invalidator] Script de revocación por lotes generado en: {script_file}")
    return str(script_file)
