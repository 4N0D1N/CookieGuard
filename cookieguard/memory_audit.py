"""Módulo de auditoría de inyección en memoria y hooking en procesos del navegador.

Detecta técnicas avanzadas empleadas por infostealers como DLL Injection,
Process Hollowing y cargadores dinámicos que se inyectan en navegadores en ejecución
para capturar cookies y credenciales antes de ser cifradas en disco.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from .common import IS_LINUX, IS_WIN, log, ps, run


SUSPICIOUS_PATHS_REGEX = re.compile(
    r"((\\temp\\|\\tmp\\|/tmp/|/dev/shm|/var/tmp|\\users\\public\\|\\appdata\\local\\temp\\|\\appdata\\roaming\\temp\\))",
    re.I
)

KNOWN_HOOK_NAMES = {
    "hook.dll", "minhook.dll", "sqlite3_hook.dll", "crypt_hook.dll", "stealer.dll", "inject.dll",
    "libhook.so", "libinject.so", "libpreload.so"
}

BROWSER_PROCESS_NAMES = {
    "chrome", "chrome.exe", "msedge", "msedge.exe", "brave", "brave.exe",
    "firefox", "firefox.exe", "opera", "opera.exe", "vivaldi", "vivaldi.exe"
}


def audit_browser_memory(procs: list[dict] | None = None) -> dict[str, Any]:
    """Audita los procesos del navegador buscando módulos o librerías sospechosas inyectadas."""
    anomalias = []
    auditados = 0

    if IS_LINUX:
        anomalias.extend(_audit_linux_proc_maps())
    elif IS_WIN:
        anomalias.extend(_audit_windows_modules())

    return {
        "limpio": len(anomalias) == 0,
        "total_anomalias": len(anomalias),
        "anomalias": anomalias
    }


def _audit_linux_proc_maps() -> list[dict[str, Any]]:
    """Inspecciona /proc/[pid]/maps de los navegadores en Linux buscando librerías en /tmp o (deleted)."""
    anomalias = []
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return anomalias

    for d in proc_root.iterdir():
        if not d.name.isdigit():
            continue
        try:
            comm = (d / "comm").read_text().strip().lower()
            if not any(b in comm for b in BROWSER_PROCESS_NAMES):
                continue

            maps_file = d / "maps"
            if not maps_file.is_file():
                continue

            for line in maps_file.read_text(errors="replace").splitlines():
                parts = line.split()
                if len(parts) < 6:
                    continue
                perms = parts[1]
                path = parts[5]

                # Revisar librerías ejecutables cargadas desde directorios temporales o eliminadas
                if "x" in perms and (SUSPICIOUS_PATHS_REGEX.search(path) or path.endswith("(deleted)")):
                    anomalias.append({
                        "pid": int(d.name),
                        "proceso": comm,
                        "tipo": "LIBRERIA_SOSPECHOSA_EN_MEMORIA",
                        "ruta": path,
                        "permisos": perms,
                        "motivo": "Librería ejecutable mapeada desde ubicación volátil o marcada como eliminada"
                    })
                elif os.path.basename(path).lower() in KNOWN_HOOK_NAMES:
                    anomalias.append({
                        "pid": int(d.name),
                        "proceso": comm,
                        "tipo": "HOOK_CONOCIDO_INYECTADO",
                        "ruta": path,
                        "permisos": perms,
                        "motivo": "Nombre de módulo coincidente con librerías conocidas de intercepción/hooking"
                    })
        except (PermissionError, OSError):
            continue

    return anomalias


def _audit_windows_modules() -> list[dict[str, Any]]:
    """Inspecciona módulos DLL cargados en navegadores mediante PowerShell/tasklist."""
    anomalias = []
    script = (
        "$browsers = @('chrome', 'msedge', 'brave', 'firefox', 'opera');"
        "$res = @();"
        "foreach ($b in $browsers) {"
        "  Get-Process -Name $b -ErrorAction SilentlyContinue | ForEach-Object {"
        "    $p = $_;"
        "    try {"
        "      $p.Modules | Where-Object {"
        "        $_.FileName -match '(\\\\Temp\\\\|\\\\AppData\\\\Local\\\\Temp\\\\|\\\\Users\\\\Public\\\\)' "
        "        -or $_.ModuleName -match '(hook|minhook|inject)'"
        "      } | ForEach-Object {"
        "        $res += @{"
        "          pid = $p.Id;"
        "          proceso = $p.ProcessName;"
        "          modulo = $_.ModuleName;"
        "          ruta = $_.FileName;"
        "        }"
        "      }"
        "    } catch {}"
        "  }"
        "};"
        "$res | ConvertTo-Json -Compress"
    )
    code, out, _ = ps(script, timeout=45)
    if code == 0 and out.strip():
        try:
            import json
            data = json.loads(out)
            data = [data] if isinstance(data, dict) else data
            for item in data:
                anomalias.append({
                    "pid": item.get("pid"),
                    "proceso": item.get("proceso"),
                    "tipo": "DLL_INYECTADA_SOSPECHOSA",
                    "ruta": item.get("ruta"),
                    "motivo": f"Módulo sospechoso '{item.get('modulo')}' cargado en el proceso del navegador"
                })
        except Exception as e:
            log(f"[MemoryAudit] Error parseando módulos Windows: {e}")

    return anomalias
