"""Detector de infostealers y procesos maliciosos en memoria (Process Hunter).

Analiza procesos activos en Windows y Linux buscando:
1. Suplantación de procesos del sistema (Masquerading / MITRE T1036).
2. Procesos no autorizados ejecutándose desde carpetas temporales (%TEMP%, AppData, /tmp, /dev/shm).
3. Líneas de comandos asociadas a downloaders o infostealers conocidos (Lumma, Stealc, RedLine, Vidar).
4. Descriptores abiertos o handles hacia bases de datos de cookies (Linux /proc y Windows).
Zero dependencias externas. Solo libreria estandar de Python.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

from .common import IS_LINUX, IS_WIN, log, ps, run

# Procesos legítimos de Windows que NUNCA deben ejecutarse fuera de System32 / SysWOW64
SYSTEM_BINARIES_WIN = {
    "svchost.exe", "csrss.exe", "lsass.exe", "services.exe", "smss.exe",
    "winlogon.exe", "wininit.exe", "taskhostw.exe", "conhost.exe", "dwm.exe"
}

# Carpetas de alto riesgo donde los infostealers suelen instalarse o correr
HIGH_RISK_DIRS_WIN = [
    r"\appdata\local\temp",
    r"\appdata\roaming\temp",
    r"\users\public",
    r"\programdata\temp"
]

HIGH_RISK_DIRS_LINUX = [
    "/tmp",
    "/dev/shm",
    "/var/tmp"
]

# Patrones típicos de infostealers y downloaders en línea de comandos
SUSPICIOUS_CMD_PATTERNS = [
    (re.compile(r"powershell.*(-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}", re.IGNORECASE),
     "PowerShell con comando codificado en Base64 (posible downloader/stager)", "Lumma / Stealc Dropper", "CRITICA"),
    (re.compile(r"powershell.*(downloadstring|iex|invoke-expression).*http", re.IGNORECASE),
     "PowerShell descargando y ejecutando payload en memoria (IEX/DownloadString)", "Infostealer Downloader", "CRITICA"),
    (re.compile(r"certutil.*(-urlcache|-split).*(http|\.zip|\.exe)", re.IGNORECASE),
     "Uso anómalo de certutil para descargar binarios (Living-off-the-Land)", "Downloader genérico", "ALTA"),
    (re.compile(r"bitsadmin.*(/transfer|http)", re.IGNORECASE),
     "Descarga en segundo plano con BITSAdmin", "Downloader genérico", "ALTA"),
    (re.compile(r"cmd\.exe.*/c.*(curl|powershell).*\.exe", re.IGNORECASE),
     "Invocación de consola oculta para descargar ejecutables", "Dropper sospechoso", "ALTA"),
]

# Navegadores legítimos para filtrar falsos positivos
KNOWN_BROWSERS = {
    "chrome", "chrome.exe", "msedge", "msedge.exe", "brave", "brave.exe",
    "opera", "opera.exe", "opera_gx.exe", "firefox", "firefox.exe",
    "waterfox", "waterfox.exe", "vivaldi", "vivaldi.exe", "chromium",
    "google-chrome", "google-chrome-stable", "microsoft-edge", "brave-browser"
}


def _list_processes_quick() -> list[dict]:
    """Lista procesos con pid, ppid, name, cmd y exe."""
    procs = []
    if IS_WIN:
        code, out, _ = ps("Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine,"
                          "ExecutablePath | ConvertTo-Json -Compress", 60)
        try:
            data = json.loads(out) if out.strip() else []
            if isinstance(data, dict):
                data = [data]
            for d in data:
                procs.append({
                    "pid": d.get("ProcessId"),
                    "ppid": d.get("ParentProcessId"),
                    "name": d.get("Name") or "",
                    "cmd": d.get("CommandLine") or "",
                    "exe": d.get("ExecutablePath") or ""
                })
        except Exception as e:
            log(f"process_hunter win list: {e}")
    elif IS_LINUX:
        for d in Path("/proc").iterdir():
            if not d.name.isdigit():
                continue
            try:
                pid = int(d.name)
                cmd = (d / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace").strip()
                comm = (d / "comm").read_text(encoding="utf-8", errors="replace").strip()
                stat = (d / "stat").read_text(encoding="utf-8", errors="replace")
                ppid = int(stat.rsplit(")", 1)[1].split()[1])
                try:
                    exe = os.readlink(d / "exe")
                except OSError:
                    exe = ""
                procs.append({"pid": pid, "ppid": ppid, "name": comm, "cmd": cmd, "exe": exe})
            except (OSError, ValueError, IndexError):
                continue
    return procs


def scan_processes(procs: list[dict] | None = None) -> dict:
    """Escanea la lista de procesos y devuelve resumen y lista de sospechosos."""
    if procs is None:
        procs = _list_processes_quick()

    sospechosos = []

    for p in procs:
        pid = p.get("pid")
        name = (p.get("name") or "").lower()
        cmd = p.get("cmd") or ""
        exe = (p.get("exe") or "").lower()
        exe_orig = p.get("exe") or ""

        # Omitir CookieGuard y procesos de pruebas
        if "cookieguard" in cmd.lower() or "cookieguard" in exe:
            continue

        # 1. Suplantación de binarios del sistema en Windows (Masquerading T1036)
        if IS_WIN and name in SYSTEM_BINARIES_WIN:
            if exe and not (r"\windows\system32" in exe or r"\windows\syswow64" in exe):
                sospechosos.append({
                    "pid": pid,
                    "name": p.get("name"),
                    "exe": exe_orig,
                    "cmd": cmd,
                    "familia": "Masquerading (Suplantación crítica de sistema)",
                    "severidad": "CRITICA",
                    "motivo": f"El proceso '{p.get('name')}' se ejecuta desde '{exe_orig}' fuera de System32 (troyano evidente).",
                    "comando": f"taskkill /F /PID {pid}"
                })
                continue

        # 2. Ejecutable corriendo desde directorios de alto riesgo (Temp / Public / /tmp / /dev/shm)
        if IS_WIN:
            for rdir in HIGH_RISK_DIRS_WIN:
                if rdir in exe:
                    # Comprobar si parece binario aleatorio o troyano
                    fname = os.path.basename(exe)
                    es_sospechoso = False
                    motivo = ""
                    if re.match(r"^[a-f0-9]{8,64}\.exe$", fname, re.IGNORECASE):
                        es_sospechoso = True
                        motivo = "Ejecutable con nombre de hash en carpeta temporal (patrón Lumma/Stealc)"
                    elif name not in KNOWN_BROWSERS and not any(legit in exe for legit in ["pip-", "vscode", "discord", "slack"]):
                        es_sospechoso = True
                        motivo = f"Binario no habitual ejecutándose desde carpeta de usuario temporal ({fname})"

                    if es_sospechoso:
                        sospechosos.append({
                            "pid": pid,
                            "name": p.get("name"),
                            "exe": exe_orig,
                            "cmd": cmd,
                            "familia": "Posible Infostealer / Malware en Temp",
                            "severidad": "ALTA",
                            "motivo": motivo,
                            "comando": f"taskkill /F /PID {pid}"
                        })
                        break
        elif IS_LINUX:
            for rdir in HIGH_RISK_DIRS_LINUX:
                if exe.startswith(rdir) or (cmd and cmd.startswith(rdir)):
                    sospechosos.append({
                        "pid": pid,
                        "name": p.get("name"),
                        "exe": exe_orig or cmd.split()[0],
                        "cmd": cmd,
                        "familia": "Binario en carpeta temporal /tmp o /dev/shm",
                        "severidad": "ALTA",
                        "motivo": f"Proceso ejecutándose desde directorio temporal '{rdir}' (típico de scripts o payloads maliciosos)",
                        "comando": f"kill -9 {pid}"
                    })
                    break

        # 3. Patrones de downloaders e infostealers en línea de comandos
        if cmd:
            for pat, desc, fam, sev in SUSPICIOUS_CMD_PATTERNS:
                if pat.search(cmd):
                    sospechosos.append({
                        "pid": pid,
                        "name": p.get("name"),
                        "exe": exe_orig,
                        "cmd": cmd,
                        "familia": fam,
                        "severidad": sev,
                        "motivo": desc,
                        "comando": f"taskkill /F /PID {pid}" if IS_WIN else f"kill -9 {pid}"
                    })
                    break

    # 4. Descriptores abiertos en Linux hacia ficheros de cookies por procesos que no son navegadores
    if IS_LINUX:
        for p in procs:
            pid = p.get("pid")
            name = (p.get("name") or "").lower()
            if name in KNOWN_BROWSERS or not pid:
                continue
            fd_dir = Path(f"/proc/{pid}/fd")
            if not fd_dir.exists():
                continue
            try:
                for fd in fd_dir.iterdir():
                    try:
                        target = os.readlink(fd).lower()
                        if any(term in target for term in ["cookies.sqlite", "network/cookies", "local state"]):
                            if not any(s["pid"] == pid for s in sospechosos):
                                sospechosos.append({
                                    "pid": pid,
                                    "name": p.get("name"),
                                    "exe": p.get("exe") or "",
                                    "cmd": p.get("cmd") or "",
                                    "familia": "Acceso directo a cookies (Extractor activo)",
                                    "severidad": "CRITICA",
                                    "motivo": f"El proceso tiene abierto el fichero de cookies: {target}",
                                    "comando": f"kill -9 {pid}"
                                })
                                break
                    except OSError:
                        continue
            except OSError:
                continue

    return {
        "total_procesos": len(procs),
        "sospechosos_count": len(sospechosos),
        "sospechosos": sospechosos,
        "limpio": len(sospechosos) == 0
    }
