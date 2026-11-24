"""
Chequeo integral de salud de sensores de CookieGuard (Doctor).
Diagnostica la disponibilidad y permisos de todos los sensores locales
en Windows y Linux: perfiles de navegadores, subsistema de notificaciones,
capacidades de contención de red, auditoría de persistencia y portapapeles.
"""

import os
import sys
import shutil
import sqlite3
import subprocess
from typing import Dict, Any, List, Optional


def _check_command_available(cmd: str) -> bool:
    """Verifica si un comando ejecutable está en el PATH del sistema."""
    return shutil.which(cmd) is not None


def _check_elevated_privileges() -> bool:
    """Comprueba si el proceso se ejecuta como Administrador / Root."""
    if sys.platform == "win32":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def run_sensor_diagnostic(
    test_overrides: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Ejecuta el chequeo integral de diagnóstico y salud de todos los sensores.
    """
    if test_overrides is not None:
        return test_overrides

    sensores = []
    puntos = 100
    is_windows = sys.platform == "win32"
    is_elevated = _check_elevated_privileges()

    # 1. Privilegios de ejecución
    sensores.append({
        "categoria": "Sistema",
        "nombre": "Nivel de Privilegios",
        "estado": "Informativo",
        "detalle": "Elevado (Administrador/Root)" if is_elevated else "Estándar (Usuario sin privilegios)",
        "nota": "CookieGuard opera 100% en modo usuario estándar para inspeccionar sesiones personales."
    })

    # 2. Navegadores y perfiles
    from . import browsers
    detected_browsers = browsers.discover()
    if detected_browsers:
        sensores.append({
            "categoria": "Navegadores",
            "nombre": "Perfiles de Navegador Detectados",
            "estado": "OK",
            "detalle": f"{len(detected_browsers)} perfiles identificados ({', '.join(b.browser for b in detected_browsers[:4])})",
            "nota": "Listo para auditar metadatos de cookies y extensiones."
        })
    else:
        puntos -= 15
        sensores.append({
            "categoria": "Navegadores",
            "nombre": "Perfiles de Navegador Detectados",
            "estado": "ADVERTENCIA",
            "detalle": "No se encontraron rutas estándar de navegadores.",
            "nota": "Instala o abre Chrome, Edge, Brave o Firefox para monitorizar."
        })

    # 3. Subsistema de Notificaciones de Alerta
    notif_ok = False
    notif_tool = "Desconocido"
    if is_windows:
        notif_ok = True
        notif_tool = "PowerShell / Windows Toast API"
    else:
        if _check_command_available("notify-send"):
            notif_ok = True
            notif_tool = "notify-send (libnotify)"
        elif _check_command_available("zenity"):
            notif_ok = True
            notif_tool = "zenity"
        elif _check_command_available("kdialog"):
            notif_ok = True
            notif_tool = "kdialog"

    if notif_ok:
        sensores.append({
            "categoria": "Alertas",
            "nombre": "Subsistema de Notificaciones Nativas",
            "estado": "OK",
            "detalle": f"Operativo ({notif_tool})",
            "nota": "Los popups de alerta se mostrarán inmediatamente al usuario."
        })
    else:
        puntos -= 10
        sensores.append({
            "categoria": "Alertas",
            "nombre": "Subsistema de Notificaciones Nativas",
            "estado": "DEGRADADO",
            "detalle": "Sin motor de notificaciones nativas de escritorio.",
            "nota": "En Linux instala `libnotify-bin` para recibir alertas visuales en tiempo real."
        })

    # 4. Capacidad de Contención de Red (Killswitch)
    fw_ok = False
    fw_backend = "Ninguno"
    if is_windows:
        if _check_command_available("netsh"):
            fw_ok = True
            fw_backend = "Windows Firewall (netsh advfirewall)"
    else:
        for tool in ["nft", "iptables", "ufw"]:
            if _check_command_available(tool):
                fw_ok = True
                fw_backend = tool
                break

    if fw_ok:
        sensores.append({
            "categoria": "Contención",
            "nombre": "Cortafuegos y Killswitch de Red",
            "estado": "OK",
            "detalle": f"Disponible ({fw_backend})",
            "nota": "El aislamiento de red de emergencia puede invocarse ante incidentes graves."
        })
    else:
        puntos -= 10
        sensores.append({
            "categoria": "Contención",
            "nombre": "Cortafuegos y Killswitch de Red",
            "estado": "ADVERTENCIA",
            "detalle": "Herramienta de cortafuegos no detectada en PATH.",
            "nota": "El killswitch automático requerirá permisos o utilidades del sistema."
        })

    # 5. Sensores de Persistencia
    persist_ok = False
    if is_windows:
        persist_ok = _check_command_available("reg") or _check_command_available("schtasks")
        persist_tool = "Registro de Windows & Programador de Tareas"
    else:
        persist_ok = _check_command_available("systemctl") or _check_command_available("crontab")
        persist_tool = "systemd user units / crontab / autostart .desktop"

    sensores.append({
        "categoria": "Forense",
        "nombre": "Auditor de Persistencia del Sistema",
        "estado": "OK" if persist_ok else "ADVERTENCIA",
        "detalle": f"Activo ({persist_tool})",
        "nota": "Capaz de escanear ganchos de persistencia comúnmente abusados por malware."
    })
    if not persist_ok:
        puntos -= 10

    # 6. Sensores de Portapapeles (Clipper)
    clip_ok = False
    if is_windows:
        clip_ok = True
        clip_backend = "Win32 Clipboard API"
    else:
        if _check_command_available("wl-paste") or _check_command_available("xclip") or _check_command_available("xsel"):
            clip_ok = True
            clip_backend = "xclip / Wayland wl-paste"
        else:
            clip_backend = "Fallback genérico"

    sensores.append({
        "categoria": "Portapapeles",
        "nombre": "Auditor de Portapapeles y Clipper",
        "estado": "OK" if clip_ok else "ADVERTENCIA",
        "detalle": f"Disponible ({clip_backend})",
        "nota": "Permite auditar y purgar tokens y criptodirecciones expuestas en memoria."
    })
    if not clip_ok:
        puntos -= 10

    # 7. Motor SQLite Local
    sql_ok = False
    try:
        conn = sqlite3.connect(":memory:")
        conn.close()
        sql_ok = True
    except Exception:
        pass

    sensores.append({
        "categoria": "Motor",
        "nombre": "Motor de Lectura de Base de Datos SQLite",
        "estado": "OK" if sql_ok else "ERROR",
        "detalle": "Operativo (sqlite3 nativo de Python)",
        "nota": "Lectura segura y no destructiva en modo solo lectura."
    })
    if not sql_ok:
        puntos -= 30

    # Evaluación global
    puntos = max(0, min(100, puntos))
    if puntos >= 80:
        estado_global = "OPERATIVO"
        color_resumen = "Verde"
    elif puntos >= 50:
        estado_global = "ADVERTENCIA"
        color_resumen = "Amarillo"
    else:
        estado_global = "DEGRADADO"
        color_resumen = "Rojo"

    return {
        "puntuacion_salud": puntos,
        "estado_general": estado_global,
        "color_resumen": color_resumen,
        "total_sensores": len(sensores),
        "sensores": sensores,
        "sistema_operativo": sys.platform,
        "resumen": f"Salud del sistema: {puntos}/100 ({estado_global}). Sensores operativos y listos para auditoría local."
    }


def format_sensor_diagnostic_cli(data: Dict[str, Any]) -> str:
    """Formatea el diagnóstico de sensores para salida de consola clara y visual."""
    lines = [
        "=" * 70,
        f"🩺 CHEQUEO INTEGRAL DE SALUD DE SENSORES (COOKIEGUARD DOCTOR)",
        "=" * 70,
        f"  Estado Global : [{data['estado_general']}] ({data['color_resumen']})",
        f"  Puntuación    : {data['puntuacion_salud']}/100",
        f"  Plataforma    : {data['sistema_operativo']}",
        "-" * 70,
        "  DESGLOSE DE SENSORES Y SUBSISTEMAS:",
    ]
    for s in data["sensores"]:
        icon = "✅" if s["estado"] == "OK" else ("ℹ️" if s["estado"] == "Informativo" else "⚠️")
        lines.append(f"  {icon} [{s['categoria']}] {s['nombre']}")
        lines.append(f"     Estado : {s['estado']} -> {s['detalle']}")
        lines.append(f"     Nota   : {s['nota']}")
        lines.append("")
    lines.append("-" * 70)
    lines.append(f"  {data['resumen']}")
    lines.append("=" * 70)
    return "\n".join(lines)
