"""
Módulo de Trampa Activa en Tiempo Real con Archivo Cebo / Watch-Canary para CookieGuard v2.4.0.
Despliega archivos de señuelo invisibles con estructura SQLite en perfiles de usuario
y monitoriza en tiempo real o bajo demanda accesos no autorizados a nivel de filesystem.
100% offline, sin dependencias externas, compatible con Windows y Linux.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any

from cookieguard.browsers import discover

TRAP_INDEX_FILE = "canary_traps.json"
CANARY_FILENAME = "CookieGuard_Canary_Vault.db"


def _get_app_config_dir() -> Path:
    """Obtiene el directorio de configuración local de CookieGuard."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path.home() / ".config"
    cg_dir = base / "CookieGuard"
    cg_dir.mkdir(parents=True, exist_ok=True)
    return cg_dir


def _load_trap_index() -> list[dict[str, Any]]:
    """Carga el índice de trampas registradas."""
    idx_path = _get_app_config_dir() / TRAP_INDEX_FILE
    if not idx_path.exists():
        return []
    try:
        with open(idx_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save_trap_index(traps: list[dict[str, Any]]) -> None:
    """Guarda el índice de trampas activas."""
    idx_path = _get_app_config_dir() / TRAP_INDEX_FILE
    idx_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(idx_path, "w", encoding="utf-8") as f:
            json.dump(traps, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def _create_decoy_sqlite(target_path: Path) -> str:
    """Crea una base de datos señuelo SQLite con tablas trampa y devuelve su hash SHA-256."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    if target_path.exists():
        target_path.unlink()

    conn = sqlite3.connect(str(target_path))
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE cookies (
            id INTEGER PRIMARY KEY,
            host_key TEXT,
            name TEXT,
            value TEXT,
            creation_utc INTEGER,
            expires_utc INTEGER
        )
    """)
    cursor.execute("""
        INSERT INTO cookies (host_key, name, value, creation_utc, expires_utc)
        VALUES ('.canary-vault.internal', 'CG_HONEYPOT_TOKEN', 'DO_NOT_EXFILTRATE_CANARY', 13345678900000000, 13645678900000000)
    """)
    conn.commit()
    conn.close()

    # Calcular hash
    h = hashlib.sha256()
    with open(target_path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def deploy_canary_traps(custom_paths: list[Path] | None = None) -> list[dict[str, Any]]:
    """
    Despliega archivos señuelo en las carpetas de perfiles de navegadores detectados
    o en rutas personalizadas.
    """
    traps = _load_trap_index()
    existing_paths = {t["path"] for t in traps}
    deployed = []

    target_dirs = []
    if custom_paths:
        target_dirs.extend(custom_paths)
    else:
        profiles = discover()
        for p in profiles:
            target_dirs.append(p.path)

    if not target_dirs:
        # Fallback a directorio de usuario
        target_dirs.append(Path.home() / ".cookieguard_trap_vault")

    now = time.time()
    for d in target_dirs:
        trap_file = d / CANARY_FILENAME
        str_path = str(trap_file)
        if str_path in existing_paths:
            continue

        try:
            sha256 = _create_decoy_sqlite(trap_file)
            stat = trap_file.stat()
            trap_record = {
                "path": str_path,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
                "baseline_atime": stat.st_atime,
                "baseline_mtime": stat.st_mtime,
                "size_bytes": stat.st_size,
                "sha256": sha256,
                "status": "ARMED"
            }
            traps.append(trap_record)
            deployed.append(trap_record)
        except Exception as e:
            deployed.append({
                "path": str_path,
                "status": "ERROR",
                "error": str(e)
            })

    _save_trap_index(traps)
    return deployed


def check_canary_traps() -> dict[str, Any]:
    """
    Inspecciona todas las trampas armadas y reporta si alguna ha sido
    abierta, leída, manipulada o borrada por malware.
    """
    traps = _load_trap_index()
    triggered = []
    intact = []
    missing = []

    for t in traps:
        p = Path(t["path"])
        if not p.exists():
            t["status"] = "TRIGGERED_DELETED"
            t["incident_reason"] = "El archivo trampa fue eliminado o movido del disco."
            missing.append(t)
            continue

        stat = p.stat()
        anomalies = []

        # 1. Modificación de tamaño o fecha de escritura
        if stat.st_size != t.get("size_bytes"):
            anomalies.append(f"Tamaño alterado (original: {t.get('size_bytes')}B, actual: {stat.st_size}B)")

        # 2. Comprobación de integridad de hash
        try:
            h = hashlib.sha256()
            with open(p, "rb") as f:
                h.update(f.read())
            current_hash = h.hexdigest()
            if current_hash != t.get("sha256"):
                anomalies.append("Hash SHA-256 no coincide; el contenido de la trampa fue modificado")
        except Exception as e:
            anomalies.append(f"Error leyendo trampa: {e}")

        # 3. Comprobación de atime (lectura / volcado por stealer)
        # Nota: solo si el filesystem registra accesos y atime difiere significativamente
        if stat.st_atime > t.get("baseline_atime", 0) + 1.0:
            anomalies.append(f"Acceso de lectura detectado en filesystem (atime: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_atime))})")

        if anomalies:
            t["status"] = "TRIGGERED"
            t["anomalies"] = anomalies
            triggered.append(t)
        else:
            t["status"] = "ARMED_INTACT"
            intact.append(t)

    # Actualizar estado en índice
    _save_trap_index(traps)

    alert_active = len(triggered) > 0 or len(missing) > 0

    return {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "alerta_activa": alert_active,
        "total_trampas": len(traps),
        "intactas": len(intact),
        "activadas": len(triggered),
        "desaparecidas": len(missing),
        "detalle_activadas": triggered + missing,
        "trampas": traps
    }


def cleanup_canary_traps() -> int:
    """Elimina todos los archivos cebo desplegados y limpia el registro."""
    traps = _load_trap_index()
    removed_count = 0
    for t in traps:
        p = Path(t["path"])
        if p.exists():
            try:
                p.unlink()
                removed_count += 1
            except Exception:
                pass
    _save_trap_index([])
    return removed_count


def watch_canary_traps(interval_seconds: int = 5, max_iterations: int = 1) -> dict[str, Any]:
    """
    Monitor activo en bucle para vigilar las trampas.
    Utilizado por scripts de vigilancia o modos de protección continua.
    """
    iterations = 0
    last_res: dict[str, Any] = {}

    while iterations < max_iterations:
        last_res = check_canary_traps()
        if last_res.get("alerta_activa"):
            break
        iterations += 1
        if iterations < max_iterations:
            time.sleep(interval_seconds)

    return last_res
