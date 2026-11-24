"""
Detector de depuración remota e inyección DevTools Protocol (CDP).
Identifica navegadores ejecutándose con puertos de depuración abiertos o pipes CDP,
una técnica habitual empleada por infostealers para extraer cookies y tokens en memoria
sin tocar las bases de datos SQLite en disco.
Opera de forma 100% pasiva y local, sin abrir sockets ni requerir módulos de red.
"""

import os
import sys
import subprocess
from typing import Dict, Any, List, Optional

# Banderas críticas que habilitan control remoto o extracción silenciosa
CRITICAL_FLAGS = [
    ("--remote-debugging-port", "Puerto de depuración remota activo (CDP)"),
    ("--remote-debugging-pipe", "Pipe de depuración remota activa (CDP sin socket)"),
    ("--remote-allow-origins", "Orígenes remotos permitidos en interfaz de depuración"),
    ("--enable-automation", "Modo automatización WebDriver/Puppeteer activo"),
]

SUSPICIOUS_FLAGS = [
    ("--headless", "Navegador en modo sin interfaz (headless)"),
    ("--disable-web-security", "Seguridad web y Same-Origin Policy desactivados"),
    ("--user-data-dir", "Uso de directorio de perfil personalizado/clonado"),
]

COMMON_CDP_PORTS = [9222, 9223, 9224, 9229]


def _is_port_listening_passive(port: int, test_proc_tcp: Optional[str] = None) -> bool:
    """
    Comprueba de forma pasiva si un puerto local está en escucha (LISTEN)
    leyendo /proc/net/tcp en Linux o consultando netstat local en Windows.
    No realiza ninguna conexión ni importa módulos de red.
    """
    # 1. Linux: lectura pasiva de /proc/net/tcp
    if sys.platform != "win32" or test_proc_tcp is not None:
        tcp_path = test_proc_tcp or "/proc/net/tcp"
        if os.path.exists(tcp_path):
            try:
                port_hex = f"{port:04X}"
                with open(tcp_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            local_addr = parts[1]
                            state = parts[3]
                            if ":" in local_addr:
                                _, p_hex = local_addr.split(":", 1)
                                # 0A representa TCP_LISTEN
                                if p_hex.upper() == port_hex and state.upper() == "0A":
                                    return True
            except Exception:
                pass

    # 2. Windows: consulta pasiva a netstat local
    if sys.platform == "win32":
        try:
            out = subprocess.check_output(
                ["netstat", "-ano", "-p", "tcp"],
                text=True,
                timeout=4,
                stderr=subprocess.DEVNULL
            )
            needle = f":{port} "
            for line in out.splitlines():
                if needle in line and "LISTENING" in line.upper():
                    return True
        except Exception:
            pass

    return False


def _get_linux_processes(proc_dir: str = "/proc") -> List[Dict[str, Any]]:
    """Obtiene procesos en Linux leyendo /proc/[pid]/cmdline."""
    processes = []
    if not os.path.exists(proc_dir):
        return processes

    for entry in os.listdir(proc_dir):
        if not entry.isdigit():
            continue
        pid = int(entry)
        cmdline_path = os.path.join(proc_dir, entry, "cmdline")
        try:
            with open(cmdline_path, "rb") as f:
                content = f.read()
            if not content:
                continue
            args = [arg.decode("utf-8", errors="replace") for arg in content.split(b"\x00") if arg]
            if not args:
                continue
            exe = args[0]
            cmdline = " ".join(args)
            processes.append({"pid": pid, "exe": exe, "cmdline": cmdline, "args": args})
        except Exception:
            continue
    return processes


def _get_windows_processes() -> List[Dict[str, Any]]:
    """Obtiene procesos en Windows mediante PowerShell / WMIC / tasklist."""
    processes = []
    if sys.platform != "win32":
        return processes

    # Intento 1: PowerShell Get-CimInstance
    ps_cmd = 'Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine | ConvertTo-Json -Compress'
    try:
        out = subprocess.check_output(["powershell", "-NoProfile", "-Command", ps_cmd], text=True, timeout=5, stderr=subprocess.DEVNULL)
        import json
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        for p in data:
            cmd = p.get("CommandLine") or ""
            name = p.get("Name") or ""
            pid = p.get("ProcessId") or 0
            processes.append({"pid": pid, "exe": name, "cmdline": cmd, "args": cmd.split()})
        return processes
    except Exception:
        pass

    # Intento 2: tasklist /v /fo csv
    try:
        out = subprocess.check_output(["tasklist", "/v", "/fo", "csv"], text=True, timeout=5, stderr=subprocess.DEVNULL)
        import csv
        import io
        reader = csv.reader(io.StringIO(out))
        header = next(reader, None)
        for row in reader:
            if len(row) >= 2:
                name = row[0]
                pid = int(row[1]) if row[1].isdigit() else 0
                title = row[8] if len(row) > 8 else ""
                processes.append({"pid": pid, "exe": name, "cmdline": title, "args": [name, title]})
    except Exception:
        pass

    return processes


def audit_remote_debugging(
    test_processes: Optional[List[Dict[str, Any]]] = None,
    test_ports: Optional[List[int]] = None,
    proc_dir: str = "/proc",
    test_proc_tcp: Optional[str] = None
) -> Dict[str, Any]:
    """
    Audita procesos de navegadores en ejecución y puertos locales para detectar CDP/depuración remota.
    """
    # 1. Obtener lista de procesos
    if test_processes is not None:
        procs = test_processes
    elif sys.platform == "win32":
        procs = _get_windows_processes()
    else:
        procs = _get_linux_processes(proc_dir)

    # 2. Filtrar y analizar navegadores
    navegadores_target = ["chrome", "msedge", "edge", "brave", "firefox", "chromium", "opera", "vivaldi"]
    alertas = []
    procesos_sospechosos = []

    for p in procs:
        exe_lower = p.get("exe", "").lower()
        cmdline = p.get("cmdline", "")
        cmdline_lower = cmdline.lower()

        is_browser = any(nav in exe_lower for nav in navegadores_target) or any(nav in cmdline_lower for nav in navegadores_target)
        if not is_browser:
            continue

        hallazgos_proceso = []
        criticidad_proceso = "Informativo"

        # Evaluar flags críticas
        for flag, desc in CRITICAL_FLAGS:
            if flag in cmdline:
                hallazgos_proceso.append({"flag": flag, "descripcion": desc, "severidad": "Crítico"})
                criticidad_proceso = "Crítico"

        # Evaluar flags sospechosas
        for flag, desc in SUSPICIOUS_FLAGS:
            if flag in cmdline:
                hallazgos_proceso.append({"flag": flag, "descripcion": desc, "severidad": "Medio"})
                if criticidad_proceso != "Crítico":
                    criticidad_proceso = "Medio"

        if hallazgos_proceso:
            item = {
                "pid": p.get("pid"),
                "exe": p.get("exe"),
                "cmdline": cmdline[:300] + ("..." if len(cmdline) > 300 else ""),
                "hallazgos": hallazgos_proceso,
                "severidad": criticidad_proceso
            }
            procesos_sospechosos.append(item)
            for h in hallazgos_proceso:
                alertas.append({
                    "pid": p.get("pid"),
                    "proceso": p.get("exe"),
                    "flag": h["flag"],
                    "descripcion": h["descripcion"],
                    "severidad": h["severidad"]
                })

    # 3. Comprobar puertos de depuración locales de forma pasiva
    puertos_activos = []
    ports_to_check = test_ports if test_ports is not None else COMMON_CDP_PORTS
    for port in ports_to_check:
        if test_ports is not None:
            # En test directo con puertos forzados
            puertos_activos.append(port)
        else:
            if _is_port_listening_passive(port, test_proc_tcp=test_proc_tcp):
                puertos_activos.append(port)

    for p in puertos_activos:
        alertas.append({
            "pid": None,
            "proceso": "Puerto Local",
            "flag": f"Puerto {p}",
            "descripcion": f"Puerto {p} (típico CDP/DevTools) escuchando activamente en 127.0.0.1",
            "severidad": "Alto"
        })

    # 4. Determinar nivel general
    has_crit = any(a["severidad"] == "Crítico" for a in alertas)
    has_alt = any(a["severidad"] == "Alto" for a in alertas)
    has_med = any(a["severidad"] == "Medio" for a in alertas)

    if has_crit:
        nivel_general = "Crítico"
        rec = "⚠️ ATENCIÓN: Se detectaron navegadores con depuración remota activa. Un atacante o malware local puede extraer sesiones sin contraseña. Cierra inmediatamente el navegador afectado."
    elif has_alt:
        nivel_general = "Alto"
        rec = "Se detectaron puertos de depuración CDP abiertos en localhost. Verifica si estás realizando tareas de desarrollo o si un proceso no autorizado los abrió."
    elif has_med:
        nivel_general = "Medio"
        rec = "Se encontraron banderas sospechosas (ej. modo headless o perfiles personalizados). Supervisa los procesos del sistema."
    else:
        nivel_general = "Limpio"
        rec = "No se detectaron puertos de depuración remota ni argumentos CDP sospechosos en los navegadores."

    return {
        "total_procesos_auditados": len(procs),
        "procesos_sospechosos": procesos_sospechosos,
        "puertos_cdp_activos": puertos_activos,
        "total_alertas": len(alertas),
        "alertas": alertas,
        "nivel_general": nivel_general,
        "recomendacion": rec
    }
