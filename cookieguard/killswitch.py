"""Killswitch de red de emergencia: aislamiento local para evitar exfiltracion de datos C2.

No importa bibliotecas de red en Python (cumple la garantia de cero dependencias y privacidad).
Utiliza utilidades del sistema operativo (netsh en Windows, iptables/nmcli en Linux).
Permite mantener loopback (127.0.0.1) para que el navegador y el panel de triaje sigan funcionando.
"""
from __future__ import annotations

import json
import os
import shutil
from datetime import datetime
from pathlib import Path

from .common import IS_LINUX, IS_WIN, data_dir, is_admin, log, ps, run

STATE_FILE = "killswitch_state.json"
RULE_NAME_WIN = "CookieGuard_Emergency_Killswitch"


def _state_path() -> Path:
    return data_dir() / STATE_FILE


def status() -> dict:
    """Devuelve el estado actual del killswitch."""
    p = _state_path()
    info = {"activo": False, "metodo": "ninguno", "fecha": None, "detalles": ""}
    if p.exists():
        try:
            saved = json.loads(p.read_text(encoding="utf-8"))
            info.update(saved)
        except Exception:
            pass
    # Verificar activamente en el SO si es posible
    if IS_WIN:
        code, out, _ = run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={RULE_NAME_WIN}"], timeout=5)
        info["regla_so_presente"] = (code == 0 and RULE_NAME_WIN in out)
        if info["regla_so_presente"]:
            info["activo"] = True
    elif IS_LINUX:
        if shutil.which("iptables"):
            code, out, _ = run(["iptables", "-C", "OUTPUT", "-j", "DROP"], timeout=5)
            if code == 0:
                info["activo"] = True
                info["regla_so_presente"] = True
    return info


def enable(dry_run: bool = False) -> tuple[bool, str]:
    """Activa el corte de red saliente de emergencia.
    
    Bloquea conexiones salientes hacia internet para impedir que un infostealer
    envie las cookies o credenciales robadas a su panel C2 o webhook.
    """
    now = datetime.now().isoformat()
    if dry_run:
        return True, "Simulacion: killswitch se activaria cortando conexiones salientes."

    if IS_WIN:
        if not is_admin():
            # Intentar via PowerShell o netsh
            pass
        # Creamos regla que bloquea todo trafico saliente excepto loopback
        # netsh advfirewall firewall add rule name="CookieGuard_Emergency_Killswitch" dir=out action=block
        code, out, err = run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={RULE_NAME_WIN}", "dir=out", "action=block", "enable=yes",
            "description=CookieGuard bloqueo de emergencia de trafico saliente contra exfiltracion"
        ], timeout=10)

        if code != 0:
            # Fallback PowerShell
            ps_cmd = (
                f"New-NetFirewallRule -DisplayName '{RULE_NAME_WIN}' -Direction Outbound "
                "-Action Block -Enabled True -Description 'CookieGuard Emergency Killswitch'"
            )
            code, out, err = ps(ps_cmd, timeout=10)

        exito = (code == 0)
        msg = "Red aislada exitosamente via Firewall de Windows." if exito else f"Error al aplicar regla de firewall ({err.strip() or out.strip()}). Se requieren permisos de Administrador."
    elif IS_LINUX:
        # En Linux escritorio intentamos primero nmcli (NetworkManager) que no siempre requiere root
        exito = False
        msg = ""
        if shutil.which("nmcli"):
            c_nm, out_nm, err_nm = run(["nmcli", "networking", "off"], timeout=5)
            if c_nm == 0:
                exito = True
                msg = "Conectividad de red deshabilitada mediante NetworkManager (nmcli)."

        if not exito and shutil.which("iptables"):
            if not is_admin():
                msg = "Se requieren permisos de root (sudo) para aislar la red con iptables. Ejecuta: sudo iptables -I OUTPUT 1 -j DROP"
            else:
                # Permitir loopback y bloquear el resto de salida
                run(["iptables", "-I", "OUTPUT", "1", "-o", "lo", "-j", "ACCEPT"], timeout=5)
                c_ip, _, err_ip = run(["iptables", "-I", "OUTPUT", "2", "-j", "DROP"], timeout=5)
                if c_ip == 0:
                    exito = True
                    msg = "Reglas iptables aplicadas: salida bloqueada excepto loopback (127.0.0.1)."
                else:
                    msg = f"Error ejecutando iptables: {err_ip}"
        if not exito and not msg:
            msg = "No se encontraron herramientas de red (nmcli / iptables) para corte automatico."
    else:
        exito = False
        msg = "Sistema operativo no soportado para killswitch automatico."

    st = {
        "activo": exito,
        "metodo": "netsh" if IS_WIN else ("nmcli" if "nmcli" in msg else "iptables"),
        "fecha": now,
        "detalles": msg
    }
    try:
        _state_path().write_text(json.dumps(st, indent=2), encoding="utf-8")
    except Exception:
        pass
    log(f"KILLSWITCH ENABLE: exito={exito} - {msg}")
    return exito, msg


def disable(dry_run: bool = False) -> tuple[bool, str]:
    """Restaura la conexion de red y elimina las reglas de emergencia."""
    if dry_run:
        return True, "Simulacion: killswitch se desactivaria restaurando la red."

    exito = True
    mensajes = []

    if IS_WIN:
        code, out, err = run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={RULE_NAME_WIN}"], timeout=10)
        if code == 0:
            mensajes.append("Regla de firewall de Windows eliminada.")
        else:
            # Intentar por PowerShell
            ps_cmd = f"Remove-NetFirewallRule -DisplayName '{RULE_NAME_WIN}' -ErrorAction SilentlyContinue"
            c2, _, _ = ps(ps_cmd, timeout=10)
            if c2 == 0:
                mensajes.append("Regla de firewall retirada via PowerShell.")
            else:
                mensajes.append("Aviso: No se pudo eliminar la regla (o ya no existia).")

    elif IS_LINUX:
        if shutil.which("nmcli"):
            c_nm, _, _ = run(["nmcli", "networking", "on"], timeout=5)
            if c_nm == 0:
                mensajes.append("NetworkManager restablecido (nmcli networking on).")
        if shutil.which("iptables") and is_admin():
            run(["iptables", "-D", "OUTPUT", "-j", "DROP"], timeout=5)
            run(["iptables", "-D", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], timeout=5)
            mensajes.append("Reglas temporales de iptables eliminadas.")

    st = {
        "activo": False,
        "metodo": "ninguno",
        "fecha": datetime.now().isoformat(),
        "detalles": "Red restaurada por el usuario"
    }
    try:
        _state_path().write_text(json.dumps(st, indent=2), encoding="utf-8")
    except Exception:
        pass
    res_msg = " ".join(mensajes) or "Killswitch desactivado. Red restablecida."
    log(f"KILLSWITCH DISABLE: {res_msg}")
    return exito, res_msg
