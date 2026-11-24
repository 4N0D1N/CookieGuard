"""
Módulo de Asistente de Rescate Rápido / Zero-Trust Recovery Wizard para CookieGuard v2.4.0.
Guía paso a paso ante incidentes de robo o sospecha de exfiltración de cookies y credenciales.
100% offline, sin dependencias externas, compatible con Windows y Linux.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from cookieguard.common import VERSION


# Matriz de prioridades tácticas de rotación de credenciales
ROTATION_PRIORITIES = [
    {
        "fase": 1,
        "categoria": "Identidad Raíz y Correo Electrónico",
        "criticidad": "CRÍTICA INMEDIATA (0 - 5 min)",
        "motivo": "Si el atacante entra a tu correo o cuenta Google/Microsoft/Apple, puede restablecer cualquier otra contraseña.",
        "servicios": ["Google (Gmail)", "Microsoft 365 / Outlook", "Apple ID", "ProtonMail"],
        "acciones": [
            "Cerrar todas las sesiones activas en otros dispositivos.",
            "Cambiar la contraseña principal.",
            "Verificar métodos 2FA (eliminar claves de seguridad o números de teléfono no reconocidos)."
        ]
    },
    {
        "fase": 2,
        "categoria": "Gestores de Contraseñas en la Nube",
        "criticidad": "CRÍTICA INMEDIATA (5 - 10 min)",
        "motivo": "Contiene el baúl de todas tus demás claves y tarjetas.",
        "servicios": ["Bitwarden", "1Password", "Dashlane", "NordPass", "Keeper"],
        "acciones": [
            "Desconectar todas las sesiones/dispositivos en la consola web.",
            "Cambiar Master Password.",
            "Rotar claves de emergencia y desautorizar extensiones de navegador vinculadas."
        ]
    },
    {
        "fase": 3,
        "categoria": "Desarrollo, Nube e Infraestructura",
        "criticidad": "ALTA (10 - 20 min)",
        "motivo": "Tokens de acceso directo a repositorios, servidores y datos confidenciales.",
        "servicios": ["GitHub", "GitLab", "AWS Console", "Google Cloud", "DigitalOcean", "Cloudflare"],
        "acciones": [
            "Revocar Personal Access Tokens (PAT) y claves SSH.",
            "Revocar autorizaciones OAuth a aplicaciones de terceros.",
            "Cerrar sesiones web activas y rotar claves."
        ]
    },
    {
        "fase": 4,
        "categoria": "Finanzas, Cripto y Pasarelas de Pago",
        "criticidad": "ALTA (20 - 30 min)",
        "motivo": "Pérdida financiera directa e irreversible si se exfiltran cookies con sesión bancaria abierta.",
        "servicios": ["Banca Online", "PayPal", "Binance", "Coinbase", "Kraken", "Stripe"],
        "acciones": [
            "Comprobar movimientos recientes y transferencias pendientes.",
            "Cerrar sesiones remotas y desvincular APIs de trading o retiros automáticos.",
            "Activar bloqueo temporal de retiros si el exchange lo permite."
        ]
    },
    {
        "fase": 5,
        "categoria": "Redes Sociales, Ocio y Colaboración",
        "criticidad": "MEDIA (30 - 60 min)",
        "motivo": "Suplantación de identidad, chantaje o propagación del malware a tus contactos.",
        "servicios": ["Discord", "Telegram Web", "Slack", "Twitter / X", "LinkedIn", "Steam"],
        "acciones": [
            "Invalidar sesiones activas en Ajustes > Dispositivos.",
            "Revisar webhooks y bots autorizados en Discord/Slack.",
            "Cambiar contraseña y regenerar códigos de respaldo."
        ]
    }
]


def terminate_running_browsers(dry_run: bool = False) -> list[dict[str, Any]]:
    """
    Localiza y detiene procesos de navegadores abiertos para impedir que
    sigan escribiendo cookies o que un stealer continúe volcando memoria viva.
    """
    targets = ["chrome", "msedge", "firefox", "brave", "opera", "chromium", "vivaldi"]
    terminated = []

    if sys.platform == "win32":
        for target in targets:
            proc_name = f"{target}.exe"
            if dry_run:
                terminated.append({"browser": target, "status": "simulado", "pid": "dry-run"})
                continue
            try:
                res = subprocess.run(
                    ["taskkill", "/F", "/IM", proc_name],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if res.returncode == 0:
                    terminated.append({"browser": target, "status": "cerrado", "output": res.stdout.strip()})
            except Exception as e:
                terminated.append({"browser": target, "status": "error", "error": str(e)})
    else:
        # Linux
        for target in targets:
            if dry_run:
                terminated.append({"browser": target, "status": "simulado", "pid": "dry-run"})
                continue
            try:
                res = subprocess.run(
                    ["pkill", "-f", target],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if res.returncode == 0:
                    terminated.append({"browser": target, "status": "cerrado"})
            except Exception as e:
                terminated.append({"browser": target, "status": "error", "error": str(e)})

    return terminated


def run_rescue_plan(
    auto: bool = True,
    killswitch: bool = False,
    kill_browsers: bool = True,
    output_dir: Path | None = None
) -> dict[str, Any]:
    """
    Ejecuta el protocolo de rescate cero-confianza.
    Devuelve un diccionario estructurado con los resultados forenses y las acciones requeridas.
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    out_dir = output_dir or Path(os.getcwd())

    report: dict[str, Any] = {
        "timestamp": timestamp,
        "cookieguard_version": VERSION,
        "fase_actual": "Completada",
        "contencion": {
            "killswitch_solicitado": killswitch,
            "estado_killswitch": "omitido" if not killswitch else "ejecutado",
            "navegadores_detenidos": []
        },
        "rotacion_prioritaria": ROTATION_PRIORITIES,
        "recomendaciones_inmediatas": [
            "NO utilices este equipo infectado para cambiar las contraseñas críticas.",
            "Usa un teléfono móvil con datos móviles o un segundo ordenador seguro.",
            "Invalida primero tu cuenta de correo electrónico principal para cortar restablecimientos.",
            "Revisa los métodos de autenticación en dos pasos (2FA) configurados."
        ]
    }

    if kill_browsers:
        report["contencion"]["navegadores_detenidos"] = terminate_running_browsers(dry_run=auto and not kill_browsers)

    # Generar informe JSON de rescate
    json_path = out_dir / "cookieguard_rescue_report.json"
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        report["archivo_reporte_json"] = str(json_path)
    except Exception as e:
        report["error_guardado_json"] = str(e)

    # Generar informe HTML de rescate
    html_path = out_dir / "cookieguard_rescue_report.html"
    try:
        html_content = generate_rescue_html(report)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        report["archivo_reporte_html"] = str(html_path)
    except Exception as e:
        report["error_guardado_html"] = str(e)

    return report


def generate_rescue_html(report: dict[str, Any]) -> str:
    """Genera un informe visual offline y responsive para triage de rescate."""
    fases_html = ""
    for f in report.get("rotacion_prioritaria", []):
        acciones = "".join(f"<li>{a}</li>" for a in f["acciones"])
        servicios = ", ".join(f["servicios"])
        fases_html += f"""
        <div class="fase-card">
            <div class="fase-header">
                <span class="fase-badge">Fase {f['fase']}</span>
                <h3>{f['categoria']}</h3>
                <span class="criticidad">{f['criticidad']}</span>
            </div>
            <p class="motivo"><strong>¿Por qué?:</strong> {f['motivo']}</p>
            <p class="servicios"><strong>Servicios clave:</strong> {servicios}</p>
            <ul class="acciones">
                {acciones}
            </ul>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>CookieGuard - Protocolo de Rescate Cero-Confianza</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 24px; line-height: 1.6; }}
.container {{ max-width: 900px; margin: 0 auto; }}
.hero {{ background: linear-gradient(135deg, #ef4444 0%, #991b1b 100%); padding: 24px; border-radius: 12px; margin-bottom: 24px; box-shadow: 0 10px 25px rgba(239, 68, 68, 0.3); }}
.hero h1 {{ margin: 0 0 8px 0; font-size: 24px; }}
.hero p {{ margin: 0; font-size: 14px; opacity: 0.95; }}
.alert-box {{ background: #1e293b; border-left: 4px solid #f59e0b; padding: 16px; border-radius: 6px; margin-bottom: 24px; font-size: 14px; }}
.fase-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 18px; margin-bottom: 16px; }}
.fase-header {{ display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; margin-bottom: 8px; }}
.fase-badge {{ background: #3b82f6; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
.criticidad {{ color: #ef4444; font-weight: bold; font-size: 12px; }}
.motivo {{ font-size: 13px; color: #cbd5e1; margin: 6px 0; }}
.servicios {{ font-size: 13px; color: #94a3b8; margin-bottom: 8px; }}
.acciones {{ margin: 0; padding-left: 20px; font-size: 13px; color: #e2e8f0; }}
.acciones li {{ margin-bottom: 4px; }}
footer {{ text-align: center; font-size: 12px; color: #64748b; margin-top: 32px; }}
</style>
</head>
<body>
<div class="container">
    <div class="hero">
        <h1>🚨 Protocolo de Rescate y Rotación de Credenciales</h1>
        <p>Generado por CookieGuard v{report.get('cookieguard_version', '2.4.0')} el {report.get('timestamp')}.</p>
    </div>

    <div class="alert-box">
        ⚠️ <strong>REGLA DE ORO DE SEGURIDAD:</strong> Si sospechas que este equipo tiene un infostealer activo,
        <strong>NO cambies las contraseñas desde este ordenador</strong>. Usa tu teléfono móvil o un dispositivo limpio
        para evitar que el malware capture de nuevo las credenciales recién renovadas.
    </div>

    <h2>Orden Táctico de Revocación y Rotación</h2>
    {fases_html}

    <footer>CookieGuard v{report.get('cookieguard_version', '2.4.0')} • 100% Offline y Privado</footer>
</div>
</body>
</html>
"""
