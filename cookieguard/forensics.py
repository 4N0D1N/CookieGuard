"""Módulo de recolección y captura de evidencias forenses volátiles (Live Forensics).

Genera un snapshot empaquetado y cifrado/hasheado con el estado del sistema en el
momento del incidente: conexiones de red activas, árbol de procesos, caché DNS y
hashes SHA-256 de binarios sospechosos para análisis posterior o reporte al SOC.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import sys
import tempfile
import time
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

from .common import IS_LINUX, IS_WIN, data_dir, log, ps, run


def capture_volatile_snapshot(reason: str = "alerta_detectada", output_dir: Path | None = None) -> str:
    """Captura las evidencias volátiles del sistema y las empaqueta en un ZIP con manifiesto SHA-256."""
    if output_dir is None:
        target_dir = data_dir() / "forense"
    else:
        target_dir = Path(output_dir)

    target_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_path = target_dir / f"snapshot_{timestamp}.zip"

    manifest_entries = {}

    with tempfile.TemporaryDirectory() as td:
        temp_path = Path(td)

        # 1. Información del sistema
        sys_info = {
            "timestamp": datetime.now().isoformat(),
            "motivo": reason,
            "hostname": platform.node(),
            "sistema": platform.system(),
            "version": platform.version(),
            "arquitectura": platform.machine(),
            "usuario": os.environ.get("USERNAME") or os.environ.get("USER") or "desconocido"
        }
        _write_artifact(temp_path, "entorno_sistema.json", sys_info, manifest_entries)

        # 2. Árbol de procesos
        procs = _collect_processes()
        _write_artifact(temp_path, "procesos.json", procs, manifest_entries)

        # 3. Conexiones de red activas
        conns = _collect_network_connections()
        _write_artifact(temp_path, "conexiones_red.json", conns, manifest_entries)

        # 4. Caché DNS
        dns = _collect_dns_cache()
        _write_artifact(temp_path, "dns_cache.json", dns, manifest_entries)

        # 5. Hashes de ejecutables sospechosos
        hashes = _collect_suspicious_hashes(procs)
        _write_artifact(temp_path, "hashes_sospechosos.json", hashes, manifest_entries)

        # 6. Manifiesto final de integridad
        manifest_file = temp_path / "manifest.json"
        manifest_data = {
            "snapshot_id": f"CG-SNAP-{timestamp}",
            "fecha": datetime.now().isoformat(),
            "total_artefactos": len(manifest_entries),
            "artefactos": manifest_entries
        }
        manifest_file.write_text(json.dumps(manifest_data, indent=2, ensure_ascii=False), encoding="utf-8")

        # Empaquetar todo en el archivo ZIP final
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for item in temp_path.iterdir():
                if item.is_file():
                    zf.write(item, arcname=item.name)

    log(f"[Forensics] Snapshot volátil generado con éxito en: {zip_path}")
    return str(zip_path)


def _write_artifact(base: Path, filename: str, data: Any, manifest: dict[str, str]) -> None:
    fpath = base / filename
    content = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
    fpath.write_bytes(content)
    sha256 = hashlib.sha256(content).hexdigest()
    manifest[filename] = sha256


def _collect_processes() -> list[dict[str, Any]]:
    """Recolecta los procesos en ejecución."""
    procs = []
    if IS_WIN:
        code, out, _ = ps("Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath,CreationDate | ConvertTo-Json -Compress", 60)
        try:
            d = json.loads(out) if out.strip() else []
            d = [d] if isinstance(d, dict) else d
            for item in d:
                procs.append({
                    "pid": item.get("ProcessId"),
                    "ppid": item.get("ParentProcessId"),
                    "name": item.get("Name") or "",
                    "cmd": item.get("CommandLine") or "",
                    "exe": item.get("ExecutablePath") or ""
                })
        except Exception:
            pass
    elif IS_LINUX:
        for p in Path("/proc").iterdir():
            if not p.name.isdigit():
                continue
            try:
                cmd = (p / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace").strip()
                comm = (p / "comm").read_text().strip()
                try:
                    exe = os.readlink(p / "exe")
                except OSError:
                    exe = ""
                procs.append({"pid": int(p.name), "name": comm, "cmd": cmd, "exe": exe})
            except (OSError, ValueError):
                continue
    return procs


def _collect_network_connections() -> list[dict[str, Any]]:
    """Recolecta conexiones activas TCP y UDP."""
    conns = []
    if IS_WIN:
        code, out, _ = run(["netstat", "-ano"], timeout=30)
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("TCP") or line.startswith("UDP"):
                parts = line.split()
                if len(parts) >= 4:
                    conns.append({
                        "protocolo": parts[0],
                        "local": parts[1],
                        "remoto": parts[2],
                        "estado": parts[3] if len(parts) > 4 else "N/A",
                        "pid": parts[-1]
                    })
    elif IS_LINUX:
        code, out, _ = run(["ss", "-tunap"], timeout=20)
        if code != 0:
            code, out, _ = run(["netstat", "-tunap"], timeout=20)
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("tcp") or line.startswith("udp"):
                parts = line.split()
                if len(parts) >= 5:
                    conns.append({
                        "protocolo": parts[0],
                        "local": parts[4] if len(parts) > 5 else parts[3],
                        "remoto": parts[5] if len(parts) > 5 else parts[4],
                        "estado": parts[1] if parts[0].startswith("tcp") else "N/A"
                    })
    return conns[:200]


def _collect_dns_cache() -> list[str]:
    """Obtiene entradas de la caché DNS."""
    dns_entries = []
    if IS_WIN:
        code, out, _ = run(["ipconfig", "/displaydns"], timeout=30)
        dns_entries = re.findall(r"(?:Record Name|Nombre de registro)[ .]*:\s*(\S+)", out, re.I)
    return sorted(set(dns_entries))


def _collect_suspicious_hashes(procs: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Calcula el hash SHA-256 de binarios situados en rutas no estándar."""
    hashes = []
    seen = set()
    for p in procs:
        exe = p.get("exe") or ""
        if not exe or exe in seen:
            continue
        seen.add(exe)
        # Priorizar ejecutables en Temp, Downloads, AppData, /tmp
        low = exe.lower()
        if any(k in low for k in ("temp", "downloads", "/tmp", "/dev/shm", "public")):
            try:
                p_file = Path(exe)
                if p_file.is_file() and p_file.stat().st_size < 30_000_000:
                    sha = hashlib.sha256(p_file.read_bytes()).hexdigest()
                    hashes.append({
                        "pid": str(p.get("pid")),
                        "nombre": p.get("name", ""),
                        "ruta": exe,
                        "sha256": sha
                    })
            except Exception:
                continue
    return hashes
