"""Gestor de servicio en segundo plano y autoarranque para CookieGuard.

Permite configurar el monitor de CookieGuard como servicio persistente:
- Windows: Tarea programada al inicio de sesion (Task Scheduler / schtasks) o clave Run de usuario.
- Linux: Servicio de usuario de systemd (~/.config/systemd/user/cookieguard.service).

Zero dependencias externas. Solo libreria estandar de Python.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from .common import APP_ROOT, IS_LINUX, IS_WIN, log, run


def _get_exec_command() -> str:
    """Calcula el comando de ejecucion exacto segun sea binario congelado o script Python."""
    if getattr(sys, "frozen", False):
        exe_path = sys.executable
        return f'"{exe_path}" watcher'
    return f'"{sys.executable}" -m cookieguard watcher'


def install_service() -> dict[str, Any]:
    """Instala CookieGuard para que arranque automaticamente en segundo plano."""
    cmd = _get_exec_command()

    if IS_WIN:
        # 1. Crear Tarea Programada de Windows (Task Scheduler)
        task_cmd = [
            "schtasks", "/Create",
            "/TN", "CookieGuardWatcher",
            "/TR", cmd,
            "/SC", "ONLOGON",
            "/RL", "LIMITED",
            "/F"
        ]
        rc, out, err = run(task_cmd, timeout=15)
        if rc == 0:
            log("Servicio CookieGuard instalado en el Programador de Tareas de Windows (ONLOGON).")
            return {
                "success": True,
                "plataforma": "Windows",
                "metodo": "Task Scheduler",
                "tarea": "CookieGuardWatcher",
                "comando": cmd,
                "mensaje": "Servicio de vigilancia instalado con exito en el Programador de Tareas."
            }
        else:
            # Fallback a registro HKCU Run
            reg_cmd = [
                "reg", "add",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v", "CookieGuardWatcher",
                "/t", "REG_SZ",
                "/d", cmd,
                "/f"
            ]
            rc2, out2, err2 = run(reg_cmd, timeout=10)
            if rc2 == 0:
                log("Servicio CookieGuard configurado en HKCU Run.")
                return {
                    "success": True,
                    "plataforma": "Windows",
                    "metodo": "HKCU Run Registry",
                    "comando": cmd,
                    "mensaje": "Servicio configurado en el inicio de sesion del usuario (Registro)."
                }
            return {
                "success": False,
                "plataforma": "Windows",
                "error": err or err2,
                "mensaje": "No se pudo registrar la tarea programada ni la clave de inicio."
            }

    elif IS_LINUX:
        systemd_user_dir = Path.home() / ".config" / "systemd" / "user"
        systemd_user_dir.mkdir(parents=True, exist_ok=True)
        service_file = systemd_user_dir / "cookieguard.service"

        # Escribir unidad systemd de usuario
        service_content = f"""[Unit]
Description=CookieGuard - Monitor de Integridad de Sesiones y Cookies
Documentation=https://github.com/4N0D1N/CookieGuard
After=graphical-session.target

[Service]
Type=simple
ExecStart={cmd.replace('"', '')}
Restart=on-failure
RestartSec=10
Environment="PYTHONUNBUFFERED=1"

[Install]
WantedBy=default.target
"""
        try:
            service_file.write_text(service_content, encoding="utf-8")
            run(["systemctl", "--user", "daemon-reload"], timeout=10)
            rc, out, err = run(["systemctl", "--user", "enable", "--now", "cookieguard.service"], timeout=10)
            if rc == 0:
                log("Servicio systemd de usuario cookieguard.service habilitado e iniciado.")
                return {
                    "success": True,
                    "plataforma": "Linux",
                    "metodo": "systemd --user",
                    "archivo": str(service_file),
                    "mensaje": "Servicio systemd de usuario habilitado e iniciado satisfactoriamente."
                }
            return {
                "success": False,
                "plataforma": "Linux",
                "archivo": str(service_file),
                "error": err,
                "mensaje": f"Archivo de unidad creado en {service_file}, pero 'systemctl --user enable' devolvio error."
            }
        except Exception as e:
            return {
                "success": False,
                "plataforma": "Linux",
                "error": str(e),
                "mensaje": f"Error escribiendo el servicio systemd: {e}"
            }

    return {"success": False, "mensaje": "Plataforma no soportada para servicio automatico."}


def uninstall_service() -> dict[str, Any]:
    """Desinstala el servicio y remueve el autoarranque de CookieGuard."""
    if IS_WIN:
        # Eliminar tarea programada
        run(["schtasks", "/Delete", "/TN", "CookieGuardWatcher", "/F"], timeout=10)
        # Eliminar clave Run si existiera
        run(["reg", "delete", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "CookieGuardWatcher", "/f"], timeout=10)
        log("Servicio CookieGuard desinstalado de Windows.")
        return {
            "success": True,
            "plataforma": "Windows",
            "mensaje": "Servicio y autoarranque eliminados correctamente."
        }

    elif IS_LINUX:
        run(["systemctl", "--user", "stop", "cookieguard.service"], timeout=10)
        run(["systemctl", "--user", "disable", "cookieguard.service"], timeout=10)
        service_file = Path.home() / ".config" / "systemd" / "user" / "cookieguard.service"
        if service_file.exists():
            try:
                service_file.unlink()
            except Exception:
                pass
        run(["systemctl", "--user", "daemon-reload"], timeout=10)
        log("Servicio systemd cookieguard.service desinstalado.")
        return {
            "success": True,
            "plataforma": "Linux",
            "mensaje": "Servicio de usuario systemd detenido y eliminado."
        }

    return {"success": False, "mensaje": "Plataforma no soportada."}


def status_service() -> dict[str, Any]:
    """Consulta el estado del servicio en segundo plano."""
    if IS_WIN:
        rc, out, _ = run(["schtasks", "/Query", "/TN", "CookieGuardWatcher"], timeout=10)
        activo = rc == 0
        return {
            "plataforma": "Windows",
            "instalado": activo,
            "detalle": out.strip() if activo else "Tarea no registrada en Programador de Tareas."
        }
    elif IS_LINUX:
        service_file = Path.home() / ".config" / "systemd" / "user" / "cookieguard.service"
        rc, out, _ = run(["systemctl", "--user", "is-active", "cookieguard.service"], timeout=10)
        activo = (rc == 0 and "active" in out.lower())
        return {
            "plataforma": "Linux",
            "instalado": service_file.exists(),
            "activo": activo,
            "estado": out.strip()
        }
    return {"instalado": False, "mensaje": "Plataforma no soportada."}
