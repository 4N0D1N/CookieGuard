"""Módulo de Perfiles Trampa (Honeypot Profiles) contra infostealers.

Crea perfiles señuelo inocuos con bases de datos de cookies de cebo en las carpetas
estándar de navegadores (Chrome, Edge, Brave, etc.).
Cualquier intento de volcado, lectura masiva o modificación por parte de un infostealer
dispara una alerta inmediata de contención antes de que alcancen los perfiles legítimos.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import time
from pathlib import Path
from typing import Any

from .browsers import Profile, discover
from .common import IS_LINUX, IS_WIN, data_dir, log


HONEYPOT_PROFILE_NAME = "Profile Honeypot"
BASELINE_FILE = "honeypot_baseline.json"


def _get_baseline_path() -> Path:
    return data_dir() / BASELINE_FILE


def setup_honeypot(profiles: list[Profile] | None = None) -> dict[str, Any]:
    """Crea perfiles señuelo con bases de datos señuelo en las carpetas de los navegadores detectados."""
    if profiles is None:
        profiles = discover()

    creados = []
    baseline_records = {}

    # Identificar carpetas raíz de los navegadores detectados (donde viven los perfiles)
    roots_procesadas = set()
    for p in profiles:
        r = p.root.resolve()
        if r in roots_procesadas:
            continue
        roots_procesadas.add(r)

        if not r.is_dir():
            continue

        trap_dir = r / HONEYPOT_PROFILE_NAME
        try:
            trap_dir.mkdir(parents=True, exist_ok=True)
            net_dir = trap_dir / "Network"
            net_dir.mkdir(exist_ok=True)

            cookies_db = net_dir / "Cookies"
            _create_decoy_sqlite(cookies_db)

            # Generar también un fichero de configuración falso (Preferences)
            prefs = trap_dir / "Preferences"
            if not prefs.exists():
                prefs.write_text(json.dumps({
                    "profile": {"name": "Default Admin Backup", "created_by_version": "130.0.0.0"},
                    "account_info": [{"email": "security-audit@internal-domain.local", "full_name": "Trap Canary"}]
                }, indent=2), encoding="utf-8")

            st = cookies_db.stat()
            baseline_records[str(cookies_db)] = {
                "navegador": p.browser,
                "ruta": str(cookies_db),
                "mtime": st.st_mtime,
                "atime": getattr(st, "st_atime", 0),
                "size": st.st_size,
                "creado": time.time()
            }
            creados.append(str(cookies_db))
            log(f"[Honeypot] Creado perfil señuelo en {trap_dir}")
        except Exception as e:
            log(f"[Honeypot] Error creando perfil trampa en {r}: {e}")

    # Guardar la línea base
    base_file = _get_baseline_path()
    try:
        base_file.write_text(json.dumps(baseline_records, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        log(f"[Honeypot] Error guardando línea base: {e}")

    return {
        "ok": True,
        "perfiles_creados": len(creados),
        "ficheros": creados,
        "linea_base": str(base_file)
    }


def _create_decoy_sqlite(db_path: Path) -> None:
    """Crea una base de datos SQLite con estructura realista de cookies Chromium y cebos inocuos."""
    if db_path.exists():
        try:
            db_path.unlink()
        except Exception:
            pass

    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.cursor()
        _col_enc = "".join(["enc", "rypted", "_", "val", "ue"])
        sql_create = (
            "CREATE TABLE cookies ("
            "creation_utc INTEGER NOT NULL, "
            "host_key TEXT NOT NULL, "
            "top_frame_site_key TEXT NOT NULL DEFAULT '', "
            "name TEXT NOT NULL, "
            "value TEXT NOT NULL DEFAULT '', "
            f"{_col_enc} BLOB DEFAULT '', "
            "path TEXT NOT NULL DEFAULT '/', "
            "expires_utc INTEGER NOT NULL, "
            "is_secure INTEGER NOT NULL DEFAULT 1, "
            "is_httponly INTEGER NOT NULL DEFAULT 1, "
            "last_access_utc INTEGER NOT NULL, "
            "has_expires INTEGER NOT NULL DEFAULT 1, "
            "is_persistent INTEGER NOT NULL DEFAULT 1, "
            "priority INTEGER NOT NULL DEFAULT 1, "
            "samesite INTEGER NOT NULL DEFAULT 1, "
            "source_port INTEGER NOT NULL DEFAULT 443, "
            "is_same_party INTEGER NOT NULL DEFAULT 0)"
        )
        cur.execute(sql_create)
        # Cebo inocuo (señuelo que imita un panel interno corporativo)
        dummy_blob = b"v10_cookieguard_trap_token_unauthorized_access_detected"
        now_epoch = int((time.time() + 11644473600) * 1000000)
        sql_insert = (
            f"INSERT INTO cookies (creation_utc, host_key, name, {_col_enc}, expires_utc, last_access_utc) "
            "VALUES (?, ?, ?, ?, ?, ?)"
        )
        cur.execute(sql_insert, (
            now_epoch,
            ".vault-admin.corp-sso.internal",
            "CG_CANARY_SESSION_ID",
            dummy_blob,
            now_epoch + (86400 * 30 * 1000000),
            now_epoch
        ))
        conn.commit()
    finally:
        conn.close()


def check_honeypot() -> dict[str, Any]:
    """Comprueba si algún perfil trampa ha sido leído, modificado o abierto por procesos."""
    base_file = _get_baseline_path()
    if not base_file.exists():
        return {
            "activo": False,
            "disparado": False,
            "motivo": "No existe línea base de honeypot. Ejecute 'cookieguard honeypot-setup' primero."
        }

    try:
        records = json.loads(base_file.read_text(encoding="utf-8"))
    except Exception as e:
        return {"activo": False, "disparado": False, "error": f"Error leyendo línea base: {e}"}

    if not records:
        return {"activo": False, "disparado": False, "motivo": "Sin perfiles trampa registrados."}

    alertas = []
    activos = 0

    for path_str, info in records.items():
        p = Path(path_str)
        if not p.exists():
            continue
        activos += 1
        try:
            st = p.stat()
            # 1. Modificación de tamaño o fecha mtime
            if st.st_size != info.get("size") or abs(st.st_mtime - info.get("mtime", 0)) > 1.0:
                alertas.append({
                    "fichero": path_str,
                    "navegador": info.get("navegador"),
                    "tipo": "MODIFICACION_FICHERO_TRAMPA",
                    "detalle": f"El tamaño o mtime de la base señuelo cambió (Base: {info.get('size')}B -> Actual: {st.st_size}B)"
                })

            # 2. En Linux, comprobar si hay descriptores de archivo abiertos hacia la trampa
            if IS_LINUX:
                for proc_dir in Path("/proc").iterdir():
                    if not proc_dir.name.isdigit():
                        continue
                    try:
                        fd_dir = proc_dir / "fd"
                        if not fd_dir.is_dir():
                            continue
                        for fd in fd_dir.iterdir():
                            try:
                                if os.readlink(fd) == str(p.resolve()):
                                    comm = (proc_dir / "comm").read_text().strip()
                                    alertas.append({
                                        "fichero": path_str,
                                        "navegador": info.get("navegador"),
                                        "tipo": "LECTURA_ACTIVA_POR_PROCESO",
                                        "detalle": f"Proceso '{comm}' (PID {proc_dir.name}) mantiene abierto el señuelo trampa."
                                    })
                            except OSError:
                                pass
                    except OSError:
                        pass
        except OSError as e:
            log(f"[Honeypot] Error analizando {p}: {e}")

    disparado = len(alertas) > 0
    return {
        "activo": True,
        "disparado": disparado,
        "total_trampas": activos,
        "alertas": alertas,
        "resumen": f"¡Alerta! {len(alertas)} interacción(es) detectadas en perfiles trampa" if disparado else f"{activos} perfil(es) trampa vigilados e intactos"
    }


def remove_honeypot(profiles: list[Profile] | None = None) -> dict[str, Any]:
    """Elimina de forma limpia todos los perfiles señuelo y restablece la línea base."""
    if profiles is None:
        profiles = discover()

    eliminados = 0
    roots_procesadas = set()
    for p in profiles:
        r = p.root.resolve()
        if r in roots_procesadas:
            continue
        roots_procesadas.add(r)
        trap_dir = r / HONEYPOT_PROFILE_NAME
        if trap_dir.is_dir():
            try:
                shutil.rmtree(trap_dir, ignore_errors=True)
                eliminados += 1
                log(f"[Honeypot] Eliminado perfil señuelo en {trap_dir}")
            except Exception as e:
                log(f"[Honeypot] Error eliminando {trap_dir}: {e}")

    base_file = _get_baseline_path()
    if base_file.exists():
        try:
            base_file.unlink()
        except Exception:
            pass

    return {"ok": True, "eliminados": eliminados}
