# -*- coding: utf-8 -*-
r"""
CookieGuard - Auditoría Heurística de Persistencia y Tareas Programadas.
Inspecciona mecanismos comunes de persistencia utilizados por infostealers (RedLine,
Lumma, Stealc, Vidar) en Windows y Linux:
- Tareas programadas (schtasks / System32\Tasks / cron)
- Claves de ejecución de inicio (Registry Run / ~/.config/autostart)
- Scripts y ejecutables residiendo en directorios temporales (%TEMP%, /tmp, /dev/shm)
"""

from __future__ import annotations
import os
import sys
import re
import csv
import io
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional

# Patrones heurísticos de alta sospecha en comandos de persistencia
SUSPICIOUS_PATTERNS = [
    (r"(?:powershell(?:\.exe)?).*?(?:-enc|-encodedcommand|-w\s+hidden|-windowstyle\s+hidden)", "PowerShell con parámetros ocultos o codificados en Base64"),
    (r"(?:cmd(?:\.exe)?)\s+/c\s+(?:curl|certutil|bitsadmin)", "Descarga o ejecución remota con utilidades nativas (Living Off The Land)"),
    (r"(?:wscript|cscript|mshta)(?:\.exe)?", "Ejecutor de scripts Windows (VBScript/JScript/HTA)"),
    (r"AppData\\Local\\Temp", "Ejecución programada desde directorio temporal de usuario"),
    (r"/tmp/|/dev/shm/", "Ejecución programada desde directorios volátiles en Linux"),
    (r"(?:chrome|edge|firefox|browser)_update\.(?:exe|bat|vbs|ps1|sh)", "Nombre engañoso imitando actualización de navegador fuera de ruta oficial"),
]

def analyze_command_heuristics(cmd: str, location_hint: str = "") -> List[Dict[str, str]]:
    """Evalúa si una línea de comando o comando de persistencia presenta anomalías."""
    alerts = []
    if not cmd:
        return alerts

    cmd_lower = cmd.lower()
    for pattern, desc in SUSPICIOUS_PATTERNS:
        if re.search(pattern, cmd, re.IGNORECASE):
            alerts.append({
                "patron": pattern,
                "descripcion": desc,
                "comando": cmd.strip(),
                "origen": location_hint,
                "severidad": "CRITICAL" if "hidden" in pattern or "Temp" in pattern or "/tmp/" in pattern else "WARNING"
            })
    return alerts


def audit_linux_autostart(base_dir: Optional[str] = None) -> List[Dict[str, Any]]:
    """Audita archivos .desktop en ~/.config/autostart o directorio especificado."""
    findings = []
    autostart_dir = Path(base_dir) if base_dir else Path.home() / ".config" / "autostart"
    if not autostart_dir.is_dir():
        return findings

    try:
        for item in autostart_dir.glob("*.desktop"):
            try:
                content = item.read_text(encoding="utf-8", errors="ignore")
                exec_line = ""
                for line in content.splitlines():
                    if line.startswith("Exec="):
                        exec_line = line[5:].strip()
                        break

                alerts = analyze_command_heuristics(exec_line, location_hint=str(item))
                findings.append({
                    "tipo": "linux_autostart",
                    "archivo": str(item),
                    "nombre": item.name,
                    "comando": exec_line,
                    "sospechoso": len(alerts) > 0,
                    "alertas": alerts
                })
            except Exception as e:
                findings.append({
                    "tipo": "linux_autostart",
                    "archivo": str(item),
                    "error": str(e)
                })
    except Exception:
        pass

    return findings


def audit_linux_cron() -> List[Dict[str, Any]]:
    """Audita cron de usuario de manera segura y pasiva."""
    findings = []
    if sys.platform.startswith("win"):
        return findings

    try:
        proc = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=3)
        if proc.returncode == 0 and proc.stdout:
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    alerts = analyze_command_heuristics(line, location_hint="crontab_user")
                    findings.append({
                        "tipo": "linux_cron",
                        "comando": line,
                        "sospechoso": len(alerts) > 0,
                        "alertas": alerts
                    })
    except Exception:
        pass
    return findings


def audit_windows_startup_folders(base_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Audita accesos directos o scripts en la carpeta Inicio (Startup) de Windows."""
    findings = []
    if base_path:
        startup_dir = Path(base_path)
    else:
        appdata = os.environ.get("APPDATA", "")
        if not appdata:
            return findings
        startup_dir = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"

    if not startup_dir.is_dir():
        return findings

    try:
        for item in startup_dir.iterdir():
            if item.is_file():
                ext = item.suffix.lower()
                is_suspicious_ext = ext in [".bat", ".vbs", ".ps1", ".cmd", ".js", ".hta", ".scr"]
                alerts = []
                if is_suspicious_ext:
                    alerts.append({
                        "patron": ext,
                        "descripcion": f"Script ejecutable no estándar en carpeta de inicio ({ext})",
                        "comando": str(item),
                        "origen": str(startup_dir),
                        "severidad": "CRITICAL"
                    })
                findings.append({
                    "tipo": "windows_startup_file",
                    "archivo": str(item),
                    "nombre": item.name,
                    "sospechoso": len(alerts) > 0,
                    "alertas": alerts
                })
    except Exception:
        pass

    return findings


def audit_windows_schtasks() -> List[Dict[str, Any]]:
    """Audita tareas programadas vía 'schtasks /query /fo csv /v' si está disponible."""
    findings = []
    if not sys.platform.startswith("win"):
        return findings

    try:
        cmd = ["schtasks", "/query", "/fo", "csv", "/v"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, encoding="cp1252", errors="ignore")
        if proc.returncode == 0 and proc.stdout:
            reader = csv.DictReader(io.StringIO(proc.stdout))
            for row in reader:
                task_name = row.get("Nombre de tarea") or row.get("TaskName") or ""
                task_to_run = row.get("Tarea para ejecutar") or row.get("Task To Run") or ""
                if not task_to_run or task_to_run.lower() == "n/a":
                    continue

                alerts = analyze_command_heuristics(task_to_run, location_hint=f"Task: {task_name}")
                if alerts:
                    findings.append({
                        "tipo": "windows_schtask",
                        "tarea": task_name,
                        "comando": task_to_run,
                        "sospechoso": True,
                        "alertas": alerts
                    })
    except Exception:
        pass
    return findings


def run_persistence_audit(
    custom_autostart_dir: Optional[str] = None,
    custom_startup_dir: Optional[str] = None
) -> Dict[str, Any]:
    """Ejecuta una auditoría completa de persistencia para el sistema actual."""
    findings: List[Dict[str, Any]] = []

    # Linux / Unix
    if not sys.platform.startswith("win"):
        findings.extend(audit_linux_autostart(custom_autostart_dir))
        findings.extend(audit_linux_cron())
    # Windows
    else:
        findings.extend(audit_windows_startup_folders(custom_startup_dir))
        findings.extend(audit_windows_schtasks())

    total_audited = len(findings)
    suspicious_items = [f for f in findings if f.get("sospechoso")]

    return {
        "plataforma": sys.platform,
        "total_audited": total_audited,
        "suspicious_count": len(suspicious_items),
        "has_alerts": len(suspicious_items) > 0,
        "suspicious_items": suspicious_items,
        "all_findings": findings
    }
