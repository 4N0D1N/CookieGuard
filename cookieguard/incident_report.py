"""Módulo de generación de Dossier Forense y Reporte de Incidente con mapeo MITRE ATT&CK.

Genera informes ejecutivos y técnicos para equipos de seguridad (SOC, CISO, aseguradoras)
en formatos HTML imprimible (Print-to-PDF con estilos CSS @media print) y Markdown.
"""
from __future__ import annotations

import html
import json
import os
import platform
from datetime import datetime
from pathlib import Path
from typing import Any

from .common import data_dir, log


MITRE_MAPPING = {
    "T1539": {
        "nombre": "Steal Web Session Cookie",
        "tactica": "Credential Access",
        "indicadores": ["I01_acceso_ficheros", "I02_flags_navegador", "I12_anomalias_cookies", "I13_canary_cookie"],
        "descripcion": "Adversarios extraen cookies de sesión web para sortear autenticación multifactor (MFA)."
    },
    "T1555.003": {
        "nombre": "Credentials from Web Browsers",
        "tactica": "Credential Access",
        "indicadores": ["I01_acceso_ficheros", "I04_abe_elevation", "I06_copias_bd", "I14_dpapi_masterkey"],
        "descripcion": "Lectura y descifrado de bases de datos de credenciales, Local State y claves DPAPI."
    },
    "T1005": {
        "nombre": "Data from Local System",
        "tactica": "Collection",
        "indicadores": ["I06_copias_bd", "I17_sesiones_escritorio", "I18_perfil_trampa"],
        "descripcion": "Recolección de datos locales, perfiles señuelo o billeteras y sesiones de escritorio."
    },
    "T1071": {
        "nombre": "Application Layer Protocol",
        "tactica": "Command and Control / Exfiltration",
        "indicadores": ["I07_red_exfil", "I16_ioc_malicioso"],
        "descripcion": "Canales de exfiltración hacia Telegram, Discord C2 o servidores de infostealers."
    },
    "T1055": {
        "nombre": "Process Injection / Memory Hooking",
        "tactica": "Defense Evasion / Privilege Escalation",
        "indicadores": ["I03_memoria_navegador", "I19_inyeccion_memoria"],
        "descripcion": "Inyección de DLLs o lectura de memoria en procesos legítimos de navegadores."
    },
    "T1059": {
        "nombre": "Command and Scripting Interpreter",
        "tactica": "Execution",
        "indicadores": ["I15_procesos_infostealer"],
        "descripcion": "Ejecución de procesos y scripts de troyanos infostealer en memoria."
    },
    "T1562.001": {
        "nombre": "Impair Defenses: Disable or Modify Tools",
        "tactica": "Defense Evasion",
        "indicadores": ["I08_defender"],
        "descripcion": "Desactivación de Microsoft Defender, exclusiones fraudulentas o evasión de EDR."
    }
}


def generate_incident_dossier(res: dict[str, Any], output_path: str | Path | None = None, formato: str = "html") -> str:
    """Genera el Dossier de Incidente forense con mapeo MITRE ATT&CK en HTML o Markdown."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if output_path is None:
        target_dir = data_dir() / "informes"
        target_dir.mkdir(parents=True, exist_ok=True)
        ext = "html" if formato.lower() == "html" else "md"
        dest = target_dir / f"Dossier_Incidente_{timestamp}.{ext}"
    else:
        dest = Path(output_path)

    dest.parent.mkdir(parents=True, exist_ok=True)

    if formato.lower() == "html":
        content = _render_html_dossier(res, timestamp)
    else:
        content = _render_markdown_dossier(res, timestamp)

    dest.write_text(content, encoding="utf-8")
    log(f"[Dossier] Informe de incidente generado en {dest}")
    return str(dest)


def _render_html_dossier(res: dict[str, Any], timestamp: str) -> str:
    veredicto = res.get("veredicto", {})
    color = veredicto.get("color", "verde")
    puntos = veredicto.get("puntos", 0)
    nivel = veredicto.get("nombre", "Normal").upper()
    indicadores = res.get("indicadores", [])
    alertas = [i for i in indicadores if i.get("estado") == "alerta"]
    grupos = res.get("grupos", [])
    hostname = platform.node()

    # Mapeo MITRE de alertas detectadas
    mitre_detectado = []
    ids_alerta = {i.get("id") for i in alertas}
    for tid, info in MITRE_MAPPING.items():
        coincidencias = [i for i in info["indicadores"] if i in ids_alerta]
        if coincidencias:
            mitre_detectado.append((tid, info, coincidencias))

    html_code = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>CookieGuard - Dossier Forense de Incidente ({timestamp})</title>
<style>
  :root {{
    --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9;
    --text-bright: #f0f6fc; --red: #f85149; --yellow: #d29922; --green: #3fb950;
    --blue: #58a6ff;
  }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    background: var(--bg); color: var(--text); margin: 0; padding: 24px; line-height: 1.5;
  }}
  .container {{ max-width: 960px; margin: 0 auto; }}
  .header {{
    border-bottom: 2px solid var(--border); padding-bottom: 16px; margin-bottom: 24px;
    display: flex; justify-content: space-between; align-items: flex-start;
  }}
  .badge {{
    padding: 6px 12px; border-radius: 6px; font-weight: bold; font-size: 14px; text-transform: uppercase;
  }}
  .badge-rojo {{ background: rgba(248,81,73,0.2); color: var(--red); border: 1px solid var(--red); }}
  .badge-amarillo {{ background: rgba(210,153,34,0.2); color: var(--yellow); border: 1px solid var(--yellow); }}
  .badge-verde {{ background: rgba(63,185,80,0.2); color: var(--green); border: 1px solid var(--green); }}
  .card {{
    background: var(--card); border: 1px solid var(--border); border-radius: 8px;
    padding: 20px; margin-bottom: 20px;
  }}
  h1, h2, h3 {{ color: var(--text-bright); margin-top: 0; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 14px; }}
  th, td {{ border: 1px solid var(--border); padding: 8px 12px; text-align: left; }}
  th {{ background: #21262d; color: var(--text-bright); }}
  .print-btn {{
    background: var(--blue); color: #fff; border: none; padding: 10px 18px; border-radius: 6px;
    cursor: pointer; font-weight: 600; margin-bottom: 20px;
  }}
  @media print {{
    body {{ background: #fff !important; color: #111 !important; padding: 0 !important; }}
    .card {{ border: 1px solid #ccc !important; background: #fff !important; color: #111 !important; page-break-inside: avoid; }}
    th {{ background: #f0f0f0 !important; color: #000 !important; }}
    th, td {{ border: 1px solid #ccc !important; }}
    h1, h2, h3 {{ color: #000 !important; }}
    .print-btn {{ display: none !important; }}
  }}
</style>
</head>
<body>
<div class="container">
  <button class="print-btn" onclick="window.print()">🖨️ Imprimir / Guardar en PDF</button>

  <div class="header">
    <div>
      <h1>🛡️ COOKIEGUARD - DOSSIER FORENSE DE INCIDENTE</h1>
      <p style="margin: 4px 0;">Referencia: <strong>CG-IR-{timestamp}</strong> | Host: <strong>{html.escape(hostname)}</strong></p>
      <p style="margin: 0; font-size: 13px; color: #8b949e;">Clasificación: CONFIDENCIAL / USO INTERNO DE SEGURIDAD</p>
    </div>
    <div>
      <span class="badge badge-{color}">{nivel} ({puntos} PUNTOS)</span>
    </div>
  </div>

  <div class="card">
    <h2>1. Resumen Ejecutivo</h2>
    <p>{html.escape(veredicto.get("mensaje", "Análisis de integridad de cookies completado."))}</p>
    <p>Se auditaron <strong>{len(indicadores)}</strong> grupos de indicadores de compromiso. Se detectaron <strong>{len(alertas)}</strong> alertas activas y <strong>{len(grupos)}</strong> servicios web con sesiones persistentes.</p>
  </div>

  <div class="card">
    <h2>2. Alineación con la Matriz MITRE ATT&CK</h2>
    <table>
      <thead>
        <tr><th>Técnica ID</th><th>Nombre de la Técnica</th><th>Táctica</th><th>Indicadores Activados</th></tr>
      </thead>
      <tbody>"""

    if mitre_detectado:
        for tid, info, matches in mitre_detectado:
            html_code += f"""
        <tr>
          <td><strong>{tid}</strong></td>
          <td>{html.escape(info['nombre'])}</td>
          <td>{html.escape(info['tactica'])}</td>
          <td>{', '.join(matches)}</td>
        </tr>"""
    else:
        html_code += """
        <tr><td colspan="4" style="text-align: center; color: var(--green);">[OK] Ninguna técnica de la matriz MITRE ATT&CK activada en este análisis.</td></tr>"""

    html_code += """
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>3. Detalle Forense de Indicadores Comprometidos</h2>
    <table>
      <thead>
        <tr><th>ID</th><th>Indicador</th><th>Puntos</th><th>Hallazgos y Evidencias</th></tr>
      </thead>
      <tbody>"""

    for ind in indicadores:
        st_color = "var(--red)" if ind.get("estado") == "alerta" else ("var(--green)" if ind.get("estado") == "ok" else "var(--yellow)")
        h_list = ind.get("hallazgos", [])
        h_str = "<br>".join(html.escape(str(h)) for h in h_list[:8]) if h_list else html.escape(ind.get("resumen", "-"))
        html_code += f"""
        <tr>
          <td><strong>{ind.get('id')}</strong></td>
          <td>{html.escape(ind.get('nombre', ''))}</td>
          <td style="color: {st_color}; font-weight: bold;">{ind.get('puntos', 0)}</td>
          <td>{h_str}</td>
        </tr>"""

    html_code += """
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>4. Cuentas y Sesiones Afectadas</h2>
    <table>
      <thead>
        <tr><th>Criticidad</th><th>Servicio</th><th>Dominio</th><th>Cookies</th><th>Revocación Rápida</th></tr>
      </thead>
      <tbody>"""

    if grupos:
        for g in grupos:
            html_code += f"""
        <tr>
          <td><strong>{g.get('criticidad', 'Media')}</strong></td>
          <td>{html.escape(g.get('nombre', 'Servicio'))}</td>
          <td>{html.escape(g.get('dominio', ''))}</td>
          <td>{g.get('total_cookies', 0)}</td>
          <td><a href="{html.escape(g.get('url_revocacion', '#'))}" target="_blank" style="color: var(--blue);">Cerrar Sesión</a></td>
        </tr>"""
    else:
        html_code += """
        <tr><td colspan="5" style="text-align: center;">No se encontraron sesiones persistentes.</td></tr>"""

    html_code += """
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>5. Plan de Acción Inmediato (Checklist IR)</h2>
    <ol>
      <li><strong>Aislamiento de Red:</strong> Desconectar el equipo analizado para detener posibles comunicaciones C2.</li>
      <li><strong>Rotación de Claves Fuera de Banda:</strong> Cambiar credenciales desde un móvil o equipo limpio.</li>
      <li><strong>Revocación Forzada:</strong> Hacer clic en 'Cerrar todas las demás sesiones' en Google, Microsoft, GitHub y banca.</li>
      <li><strong>Análisis de Persistencia:</strong> Revisar tareas programadas y entradas Run identificadas en el snapshot forense.</li>
      <li><strong>Revisión de Reglas de Correo:</strong> Confirmar que no existan reglas fraudulentas de reenvío en las cuentas de correo.</li>
    </ol>
  </div>
</div>
</body>
</html>"""
    return html_code


def _render_markdown_dossier(res: dict[str, Any], timestamp: str) -> str:
    veredicto = res.get("veredicto", {})
    indicadores = res.get("indicadores", [])
    alertas = [i for i in indicadores if i.get("estado") == "alerta"]
    hostname = platform.node()

    lines = [
        f"# CookieGuard - Dossier Forense de Incidente (CG-IR-{timestamp})",
        f"- **Fecha**: {datetime.now().isoformat()}",
        f"- **Equipo**: {hostname} ({platform.system()} {platform.version()})",
        f"- **Veredicto**: {veredicto.get('nombre', 'DESCONOCIDO').upper()} ({veredicto.get('puntos', 0)} puntos)",
        "",
        "## 1. Resumen Ejecutivo",
        veredicto.get("mensaje", ""),
        f"Se identificaron {len(alertas)} alertas sobre {len(indicadores)} indicadores auditados.",
        "",
        "## 2. Alineación MITRE ATT&CK",
        "| Técnica | Nombre | Táctica | Indicadores |",
        "| :--- | :--- | :--- | :--- |"
    ]

    ids_alerta = {i.get("id") for i in alertas}
    for tid, info in MITRE_MAPPING.items():
        matches = [i for i in info["indicadores"] if i in ids_alerta]
        if matches:
            lines.append(f"| {tid} | {info['nombre']} | {info['tactica']} | {', '.join(matches)} |")

    lines.extend([
        "",
        "## 3. Indicadores en Alerta",
    ])
    for a in alertas:
        lines.append(f"### [{a.get('id')}] {a.get('nombre')} ({a.get('puntos')} pts)")
        lines.append(f"- **Resumen**: {a.get('resumen')}")
        for h in a.get("hallazgos", []):
            lines.append(f"  * {h}")
        lines.append("")

    lines.extend([
        "## 4. Medidas de Mitigación Inmediata",
        "1. Desconectar el equipo de la red.",
        "2. Rotar contraseñas críticas desde un dispositivo móvil o equipo limpio.",
        "3. Revocar todas las sesiones activas en los paneles de seguridad de los proveedores.",
        "4. Activar autenticación 2FA basada en aplicación (TOTP / FIDO2).",
        "",
        "---",
        "Generado por CookieGuard Dossier Generator."
    ])
    return "\n".join(lines)
