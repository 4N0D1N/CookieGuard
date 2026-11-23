"""Módulo de triaje y rescate forense USB (Incident Response Kit).

Permite ejecutar CookieGuard desde un soporte extraíble (pendrive USB)
garantizando que toda la información forense, logs e informes queden
confinados en el propio USB sin escribir ni alterar el disco del sistema analizado.
Genera además un checklist de texto plano (URGENTE_ROTAR_CLAVES.txt) para
que la víctima pueda revocar credenciales desde un dispositivo seguro.
"""
from __future__ import annotations

import json
import os
import shutil
import platform
import sys
import webbrowser
from datetime import datetime
from pathlib import Path

from . import engine, process_hunter, reports, forensics, incident_report, invalidation
from .common import IS_WIN, log


def run_triage(salida_dir: str | Path | None = None, open_report: bool = True) -> dict:
    """Ejecuta el protocolo de triaje y rescate USB."""
    hostname = platform.node() or "equipo-analizado"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if salida_dir:
        out_path = Path(salida_dir).resolve()
    else:
        env_home = os.environ.get("COOKIEGUARD_HOME")
        if env_home:
            out_path = Path(env_home).resolve()
        else:
            out_path = Path.cwd() / f"Informes_Rescate_{hostname}_{timestamp}"

    out_path.mkdir(parents=True, exist_ok=True)
    os.environ["COOKIEGUARD_HOME"] = str(out_path)

    log(f"Iniciando triaje forense USB en {out_path}...")

    # 1. Ejecutar análisis de sesiones e indicadores
    res = engine.run_login(open_report=False, notify_user=False)

    # 2. Escaneo especializado de malware en memoria
    ph_res = process_hunter.scan_processes()

    # 3. Guardar informe HTML interactivo en la carpeta de rescate
    informe_origen = res.get("informe")
    html_destino = out_path / "Informe_Rescate.html"
    if informe_origen and Path(informe_origen).exists():
        try:
            shutil.copy2(informe_origen, html_destino)
        except Exception:
            html_destino = Path(informe_origen)
    else:
        html_destino = Path(reports.generate(res, out_path / "informes"))

    # 4. Generar checklist de texto plano URGENTE_ROTAR_CLAVES.txt
    txt_destino = out_path / "URGENTE_ROTAR_CLAVES.txt"
    _generate_urgent_txt(res, ph_res, txt_destino, hostname)

    # 5. Generar exportación técnica JSON para equipos de SOC / forenses
    json_destino = out_path / "metadatos_forenses.json"
    with open(json_destino, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)

    # 6. Captura de evidencias volátiles (Live Forensics Snapshot)
    try:
        snapshot_zip = forensics.capture_volatile_snapshot(reason="triaje_usb", output_dir=out_path)
    except Exception as e:
        log(f"Error generando snapshot volátil: {e}")
        snapshot_zip = ""

    # 7. Dossier de Incidente formal alineado con MITRE ATT&CK
    try:
        dossier_html = incident_report.generate_incident_dossier(res, out_path / "Dossier_Incidente_MITRE.html", formato="html")
        dossier_md = incident_report.generate_incident_dossier(res, out_path / "Dossier_Incidente_MITRE.md", formato="md")
    except Exception as e:
        log(f"Error generando dossier MITRE: {e}")
        dossier_html, dossier_md = "", ""

    # 8. Script por lotes de revocación rápida (1-Click Invalidator)
    try:
        inval_script = invalidation.generate_batch_revocation_script(res.get("grupos", []), out_path)
    except Exception as e:
        log(f"Error generando script de revocación: {e}")
        inval_script = ""

    if open_report and html_destino.exists():
        try:
            webbrowser.open(html_destino.as_uri())
        except Exception as e:
            log(f"No se pudo abrir el navegador: {e}")

    return {
        "salida": str(out_path),
        "html": str(html_destino),
        "txt": str(txt_destino),
        "json": str(json_destino),
        "snapshot_zip": str(snapshot_zip),
        "dossier_html": str(dossier_html),
        "dossier_md": str(dossier_md),
        "script_revocacion": str(inval_script),
        "veredicto": res.get("veredicto", {}),
        "malware_encontrado": not ph_res.get("limpio", True),
        "sospechosos": ph_res.get("sospechosos", [])
    }


def _generate_urgent_txt(res: dict, ph_res: dict, dest: Path, hostname: str) -> None:
    """Genera un archivo de texto claro con pasos inmediatos de mitigación."""
    veredicto = res.get("veredicto", {})
    grupos = res.get("grupos", [])
    stats = res.get("estadisticas", {})

    lines = [
        "=" * 72,
        "🚨 COOKIEGUARD - PROTOCOLO DE RESCATE Y ROTACIÓN DE CREDENCIALES 🚨",
        f"Equipo analizado: {hostname} ({'Windows' if IS_WIN else 'Linux'})",
        f"Fecha y hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Nivel de riesgo detectado: {veredicto.get('nombre', 'DESCONOCIDO').upper()} ({veredicto.get('puntos', 0)} puntos)",
        "=" * 72,
        "",
        "⚠️  INSTRUCCIÓN DE SEGURIDAD CRÍTICA:",
        "Si sospechas que este equipo está infectado con malware o un infostealer:",
        "1. NO cambies las contraseñas ni inicies sesión DESDE ESTE EQUIPO.",
        "2. Hazlo desde tu teléfono móvil (con datos móviles, no la misma Wi-Fi)",
        "   o desde otro ordenador limpio.",
        "3. Desconecta este ordenador de Internet de inmediato (cable y Wi-Fi).",
        "",
        "-" * 72,
        "1. CUENTAS Y SERVICIOS CON SESIONES ACTIVAS (ORDEN DE PRIORIDAD):",
        "-" * 72
    ]

    if not grupos:
        lines.append("  (No se encontraron cookies de sesión activas en los navegadores)")
    else:
        # Ordenar por criticidad
        orden = {"Critica": 1, "Alta": 2, "Media": 3, "Baja": 4}
        grupos_ordenados = sorted(grupos, key=lambda g: orden.get(g.get("criticidad"), 5))
        for g in grupos_ordenados:
            crit = g.get("criticidad", "Media").upper()
            nombre = g.get("nombre", "Servicio")
            dom = g.get("dominio", "")
            cookies = g.get("total_cookies", 0)
            url_revoc = g.get("url_revocacion") or f"https://www.google.com/search?q=cerrar+todas+las+sesiones+{nombre}"
            lines.extend([
                f"  [{crit}] {nombre} ({dom})",
                f"    - Cookies de sesión abiertas: {cookies}",
                f"    - Enlace para cerrar sesiones activas y cambiar contraseña:",
                f"      {url_revoc}",
                ""
            ])

    lines.extend([
        "-" * 72,
        "2. MALWARE Y PROCESOS EN MEMORIA:",
        "-" * 72
    ])

    sospechosos = ph_res.get("sospechosos", [])
    if sospechosos:
        lines.append(f"  🚨 ATENCIÓN: Se han detectado {len(sospechosos)} proceso(s) sospechoso(s) en ejecución:")
        for s in sospechosos:
            lines.extend([
                f"    * Proceso: {s.get('name')} (PID {s.get('pid')})",
                f"      Ruta: {s.get('exe')}",
                f"      Tipo: {s.get('familia')} [{s.get('severidad')}]",
                f"      Motivo: {s.get('motivo')}",
                f"      Comando para detenerlo: {s.get('comando')}",
                ""
            ])
    else:
        lines.append("  [OK] No se detectaron infostealers evidentes corriendo en memoria.")
        lines.append("")

    lines.extend([
        "-" * 72,
        "3. LISTA DE ACCIONES PASO A PASO (CHECKLIST DE RESCATE):",
        "-" * 72,
        "  [ ] Paso 1: Aislar el equipo (desconectar cable de red y desactivar Wi-Fi).",
        "  [ ] Paso 2: Desde el móvil, cambiar contraseñas de correos principales (Google, Microsoft).",
        "  [ ] Paso 3: Forzar 'Cerrar todas las demás sesiones' en cada servicio crítico.",
        "  [ ] Paso 4: Revisar cuentas bancarias, PayPal y exchanges de criptomonedas.",
        "  [ ] Paso 5: Comprobar que no hayan creado reglas de reenvío ocultas en el correo.",
        "  [ ] Paso 6: Activar verificación en dos pasos (2FA) por app autenticadora (no SMS).",
        "  [ ] Paso 7: Analizar el equipo con antivirus antes de volverlo a conectar.",
        "=" * 72,
        "Generado automáticamente por CookieGuard USB Triage Kit.",
        "Más información y código fuente: https://github.com/4N0D1N/CookieGuard"
    ])

    dest.write_text("\n".join(lines), encoding="utf-8")
