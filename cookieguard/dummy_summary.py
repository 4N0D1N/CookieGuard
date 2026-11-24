# -*- coding: utf-8 -*-
"""
CookieGuard - Resumen Ejecutivo 'Modo Dummy' (Semáforo de Seguridad).
Genera un diagnóstico ultra-simplificado en tres colores y tres acciones urgentes
sin tecnicismos para cualquier persona.
"""

from __future__ import annotations
import os
import sys
from typing import Dict, Any, List, Optional
from datetime import datetime

from .common import VERSION

def compute_traffic_light(
    has_critical_detections: bool = False,
    active_critical_sessions: int = 0,
    has_persistence_alerts: bool = False,
    has_hosts_hijack: bool = False,
    has_unverified_extensions: bool = False,
    canary_triggered: bool = False,
) -> Dict[str, Any]:
    """Calcula el estado del semáforo y las 3 acciones inmediatas."""
    # ROJO: Evidencias de robo activo o persistencia maliciosa
    if has_critical_detections or has_persistence_alerts or has_hosts_hijack or canary_triggered:
        color = "ROJO"
        color_hex = "#dc2626"
        titulo = "PELIGRO: Posible compromiso de cuentas o malware detectado"
        explicacion = (
            "Se han detectado indicios sospechosos en tu equipo (procesos desconocidos accediendo "
            "a tus sesiones, persistencia oculta o manipulaciones del sistema). Tus cuentas pueden "
            "estar en riesgo inminente."
        )
        acciones = [
            {
                "paso": 1,
                "urgencia": "Inmediato (0-2 min)",
                "accion": "Desconecta la red o cierra los navegadores",
                "detalle": "Si crees que hay un robo en curso, desconecta el WiFi o cable de red para frenar cualquier exfiltración de datos."
            },
            {
                "paso": 2,
                "urgencia": "Urgente (2-5 min)",
                "accion": "Cierra sesiones remotas y cambia contraseñas desde otro dispositivo seguro",
                "detalle": "Prioriza tus correos principales (Google, Microsoft), redes sociales y banca. Usa la opción 'Cerrar todas las demás sesiones'."
            },
            {
                "paso": 3,
                "urgencia": "Post-incidente (5-15 min)",
                "accion": "Pasa un antivirus completo y activa verificación en dos pasos (2FA)",
                "detalle": "No vuelvas a iniciar sesión en este equipo hasta haber verificado que no quedan programas maliciosos activos."
            }
        ]
    # AMARILLO: Riesgo moderado / Buenas prácticas preventivas
    elif active_critical_sessions > 0 or has_unverified_extensions:
        color = "AMARILLO"
        color_hex = "#d97706"
        titulo = "ATENCIÓN: Tienes sesiones importantes abiertas sin rotar"
        explicacion = (
            f"Tienes {active_critical_sessions} sesión(es) activa(s) en servicios sensibles. "
            "Aunque no hay robo detectado ahora mismo, tus cookies de sesión pueden vivir semanas. "
            "Si alguna vez descargaste un archivo sospechoso, conviene revisar."
        )
        acciones = [
            {
                "paso": 1,
                "urgencia": "Recomendado hoy",
                "accion": "Revisa los servicios críticos listados y rota contraseñas antiguas",
                "detalle": "Accede a tus cuentas y comprueba si hay dispositivos o ubicaciones desconocidas en tu historial de actividad."
            },
            {
                "paso": 2,
                "urgencia": "Recomendado hoy",
                "accion": "Activa 2FA (doble factor) en tus correos y redes",
                "detalle": "Usa aplicaciones como Google Authenticator o llaves físicas FIDO2 para que una cookie robada no baste para acceder."
            },
            {
                "paso": 3,
                "urgencia": "Prevención",
                "accion": "Limpia extensiones del navegador y descargas no utilizadas",
                "detalle": "Desinstala cualquier extensión que no uses a diario o que no venga de desarrolladores oficiales verificados."
            }
        ]
    # VERDE: Sistema despejado
    else:
        color = "VERDE"
        color_hex = "#16a34a"
        titulo = "TRANQUILIDAD: No se detectan anomalías ni accesos no autorizados"
        explicacion = (
            "Tus navegadores no presentan indicios de robo de sesiones, las firmas son válidas "
            "y no se han encontrado procesos sospechosos intentando leer tus bases de cookies."
        )
        acciones = [
            {
                "paso": 1,
                "urgencia": "Mantenimiento",
                "accion": "Mantén tus navegadores y sistema operativo siempre actualizados",
                "detalle": "Las últimas versiones de Chrome, Edge y Firefox incorporan mejores cifrados (como App-Bound Encryption)."
            },
            {
                "paso": 2,
                "urgencia": "Prevención",
                "accion": "No ejecutes archivos .exe, .bat o .scr provenientes de descargas no verificadas",
                "detalle": "La mayoría de ladrones de cookies (infostealers) entran disfrazados de trucos de juegos, cracks o software pirateado."
            },
            {
                "paso": 3,
                "urgencia": "Hábito seguro",
                "accion": "Cierra sesión al terminar de usar ordenadores compartidos o redes públicas",
                "detalle": "Usa navegación privada cuando no quieras dejar rastros de sesión persistentes."
            }
        ]

    return {
        "color": color,
        "color_hex": color_hex,
        "titulo": titulo,
        "explicacion": explicacion,
        "acciones": acciones,
        "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "version": VERSION
    }


def format_dummy_summary_cli(summary: Dict[str, Any]) -> str:
    """Devuelve un formato visual limpio para consola."""
    color = summary["color"]
    emoji = "🟢" if color == "VERDE" else ("🟡" if color == "AMARILLO" else "🔴")
    linea = "=" * 65

    res = [
        linea,
        f" {emoji} COOKIEGUARD - RESUMEN DE SEGURIDAD (MODO DUMMY) v{summary['version']}",
        linea,
        f" ESTADO GLOBAL: {summary['color']} - {summary['titulo']}",
        linea,
        f"\n¿QUÉ SIGNIFICA ESTO?",
        f"{summary['explicacion']}\n",
        linea,
        " 3 PASOS PRIORITARIOS PARA LOS PRÓXIMOS MINUTOS:",
        linea
    ]

    for acc in summary["acciones"]:
        res.append(f"\n [{acc['paso']}] {acc['accion'].upper()}")
        res.append(f"     Plazo:   {acc['urgencia']}")
        res.append(f"     Detalle: {acc['detalle']}")

    res.append("\n" + linea)
    res.append(" Generado localmente y 100% offline. Ningún dato sensible ha salido de tu PC.")
    res.append(linea)
    return "\n".join(res)


def generate_dummy_summary_html(summary: Dict[str, Any], output_path: Optional[str] = None) -> str:
    """Genera un archivo HTML estético y responsive para abrir en cualquier navegador."""
    color = summary["color"]
    badge_bg = summary["color_hex"]
    emoji = "🟢" if color == "VERDE" else ("🟡" if color == "AMARILLO" else "🔴")

    pasos_html = ""
    for acc in summary["acciones"]:
        pasos_html += f"""
        <div class="step-card">
            <div class="step-num">{acc['paso']}</div>
            <div class="step-content">
                <span class="step-badge">{acc['urgencia']}</span>
                <h3>{acc['accion']}</h3>
                <p>{acc['detalle']}</p>
            </div>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CookieGuard - Resumen Semáforo</title>
    <style>
        :root {{
            --bg: #0f172a;
            --card-bg: #1e293b;
            --text: #f8fafc;
            --muted: #94a3b8;
            --border: #334155;
            --status: {badge_bg};
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem 1rem;
        }}
        .container {{
            max-width: 750px;
            margin: 0 auto;
        }}
        .header {{
            text-align: center;
            margin-bottom: 2rem;
        }}
        .header h1 {{
            font-size: 1.8rem;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        }}
        .header p {{
            color: var(--muted);
            font-size: 0.95rem;
        }}
        .traffic-banner {{
            background: var(--card-bg);
            border-left: 8px solid var(--status);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
        }}
        .traffic-pill {{
            display: inline-block;
            background: var(--status);
            color: white;
            font-weight: bold;
            padding: 0.35rem 0.85rem;
            border-radius: 9999px;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.75rem;
        }}
        .traffic-banner h2 {{
            font-size: 1.4rem;
            margin-bottom: 0.5rem;
        }}
        .traffic-banner p {{
            color: #cbd5e1;
            font-size: 1.05rem;
        }}
        .actions-section h2 {{
            font-size: 1.3rem;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        .step-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1.25rem;
            margin-bottom: 1rem;
            display: flex;
            gap: 1.25rem;
            align-items: flex-start;
        }}
        .step-num {{
            background: #334155;
            color: #38bdf8;
            font-size: 1.2rem;
            font-weight: 700;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
        }}
        .step-content {{
            flex: 1;
        }}
        .step-badge {{
            display: inline-block;
            background: rgba(56, 189, 248, 0.15);
            color: #38bdf8;
            font-size: 0.75rem;
            font-weight: 600;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            margin-bottom: 0.4rem;
        }}
        .step-content h3 {{
            font-size: 1.1rem;
            margin-bottom: 0.35rem;
            color: #f1f5f9;
        }}
        .step-content p {{
            color: var(--muted);
            font-size: 0.95rem;
        }}
        .footer {{
            text-align: center;
            margin-top: 2.5rem;
            color: var(--muted);
            font-size: 0.85rem;
            border-top: 1px solid var(--border);
            padding-top: 1.5rem;
        }}
        .footer a {{
            color: #38bdf8;
            text-decoration: none;
        }}
        .footer a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ CookieGuard <span>Semáforo para Dummies</span></h1>
            <p>Diagnóstico de seguridad simplificado &bull; Generado el {summary['fecha']}</p>
        </div>

        <div class="traffic-banner">
            <span class="traffic-pill">{emoji} ESTADO: {summary['color']}</span>
            <h2>{summary['titulo']}</h2>
            <p>{summary['explicacion']}</p>
        </div>

        <div class="actions-section">
            <h2>⚡ Tus 3 pasos prioritarios:</h2>
            {pasos_html}
        </div>

        <div class="footer">
            <p>CookieGuard v{summary['version']} &bull; Análisis 100% offline y confidencial.</p>
            <p style="margin-top: 0.5rem;">¿Quieres revocar sesiones de cuentas específicas? Abre el <strong>Playbook de Revocación</strong>.</p>
        </div>
    </div>
</body>
</html>
"""
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
    return html
