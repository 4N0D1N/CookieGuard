"""Notificaciones remotas por webhook (ntfy.sh, Discord, Telegram o webhook generico).

Garantias estrictas de seguridad y privacidad:
1. CERO dependencias de red en Python: utiliza curl en Linux o Invoke-RestMethod en Windows.
2. NUNCA envia valores, nombres de cookies ni contenido confidencial.
3. Solo transmite metadatos de alerta: nivel de semaforo, equipo afectado, indicadores que saltaron y hora.
"""
from __future__ import annotations

import json
import platform
import shutil
from datetime import datetime

from .common import IS_WIN, load_config, log, ps, run


def send_alert(alert_data: dict, webhook_url: str | None = None) -> tuple[bool, str]:
    """Envia una alerta de seguridad al webhook configurado."""
    cfg = load_config()
    url = webhook_url or cfg.get("webhook_url", "")
    if not url:
        return False, "No hay webhook configurado."

    host = platform.node() or "equipo-local"
    nivel = alert_data.get("nivel", "CRITICO").upper()
    indicadores = alert_data.get("indicadores", [])
    resumen = alert_data.get("resumen", "Acceso sospechoso no autorizado a bases de cookies")
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Identificar formato segun la URL
    es_ntfy = "ntfy.sh" in url
    es_discord = "discord.com" in url or "discordapp.com" in url

    if es_ntfy:
        title = f"🚨 CookieGuard [{nivel}]: {host}"
        body_text = f"{resumen}\nIndicadores: {', '.join(indicadores) if indicadores else 'Deteccion directa'}\nHora: {fecha}"
        if IS_WIN:
            script = (
                f"$headers = @{{ 'Title' = '{title}'; 'Priority' = 'urgent'; 'Tags' = 'warning,rotating_light' }}; "
                f"Invoke-RestMethod -Uri '{url}' -Method Post -Body '{body_text}' -Headers $headers -TimeoutSec 10"
            )
            code, out, err = ps(script, timeout=12)
        else:
            if not shutil.which("curl"):
                return False, "curl no encontrado en el sistema."
            cmd = [
                "curl", "-s", "-m", "10", "-X", "POST",
                "-H", f"Title: {title}",
                "-H", "Priority: urgent",
                "-H", "Tags: warning,rotating_light",
                "-d", body_text,
                url
            ]
            code, out, err = run(cmd, timeout=12)

    elif es_discord:
        payload = {
            "username": "CookieGuard Alertas",
            "content": f"🚨 **ALERTA DE SEGURIDAD EN {host.upper()}**",
            "embeds": [{
                "title": f"Semáforo: {nivel}",
                "description": resumen,
                "color": 15158332 if nivel == "ROJO" else 15105570,
                "fields": [
                    {"name": "Equipo", "value": host, "inline": True},
                    {"name": "Hora", "value": fecha, "inline": True},
                    {"name": "Indicadores", "value": "\n".join(f"• {i}" for i in indicadores[:5]) or "Alerta directa"}
                ],
                "footer": {"text": "CookieGuard Local Defense"}
            }]
        }
        json_str = json.dumps(payload)
        if IS_WIN:
            # Escapar comillas para PowerShell
            escaped = json_str.replace("'", "''")
            script = f"Invoke-RestMethod -Uri '{url}' -Method Post -ContentType 'application/json' -Body '{escaped}' -TimeoutSec 10"
            code, out, err = ps(script, timeout=12)
        else:
            if not shutil.which("curl"):
                return False, "curl no encontrado en el sistema."
            cmd = ["curl", "-s", "-m", "10", "-X", "POST", "-H", "Content-Type: application/json", "-d", json_str, url]
            code, out, err = run(cmd, timeout=12)

    else:
        # Webhook generico JSON
        payload = {
            "source": "CookieGuard",
            "host": host,
            "severity": nivel,
            "summary": resumen,
            "indicators": indicadores,
            "timestamp": fecha
        }
        json_str = json.dumps(payload)
        if IS_WIN:
            escaped = json_str.replace("'", "''")
            script = f"Invoke-RestMethod -Uri '{url}' -Method Post -ContentType 'application/json' -Body '{escaped}' -TimeoutSec 10"
            code, out, err = ps(script, timeout=12)
        else:
            if not shutil.which("curl"):
                return False, "curl no encontrado en el sistema."
            cmd = ["curl", "-s", "-m", "10", "-X", "POST", "-H", "Content-Type: application/json", "-d", json_str, url]
            code, out, err = run(cmd, timeout=12)

    exito = (code == 0)
    msg = "Alerta enviada correctamente." if exito else f"Error al enviar alerta ({err.strip() or out.strip()})"
    log(f"WEBHOOK DISPATCH: {url} -> exito={exito}")
    return exito, msg


def test_webhook(url: str) -> tuple[bool, str]:
    """Envia un mensaje de prueba al webhook."""
    test_data = {
        "nivel": "TEST",
        "resumen": "Mensaje de prueba de CookieGuard. La integracion funciona correctamente.",
        "indicadores": ["Prueba_Manual"]
    }
    return send_alert(test_data, webhook_url=url)
