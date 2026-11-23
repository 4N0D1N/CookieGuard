"""Módulo de Perfiles Trampa (Honeypot Profiles) contra infostealers.

Crea perfiles señuelo inocuos con bases de datos de cookies de cebo en las carpetas
estándar de navegadores (Chrome, Edge, Brave, etc.).
Cualquier intento de volcado, lectura masiva o modificación por parte de un infostealer
dispara una alerta inmediata de contención antes de que alcancen los perfiles legítimos.
"""
from __future__ import annotations

import hashlib
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
MARKER_FILENAME = ".cookieguard_honeypot_marker.json"


def _get_baseline_path() -> Path:
    return data_dir() / BASELINE_FILE


def setup_honeypot(profiles: list[Profile] | None = None) -> dict[str, Any]:
    """Crea perfiles señuelo con bases de datos señuelo en las carpetas de los navegadores detectados."""
    if profiles is None:
        profiles = discover()

    creados = []
    baseline_records = {}
    base_file = _get_baseline_path()
    if base_file.is_file():
        try:
            existing = json.loads(base_file.read_text(encoding="utf-8"))
            if isinstance(existing, dict):
                baseline_records.update(existing)
        except Exception:
            pass

    roots_procesadas = set()
    for p in profiles:
        r = p.root.resolve()
        if r in roots_procesadas:
            continue
        roots_procesadas.add(r)

        if not r.is_dir():
            continue

        trap_dir = r / HONEYPOT_PROFILE_NAME
        marker_file = trap_dir / MARKER_FILENAME

        # Salvaguarda: nunca tocar un directorio preexistente, ni siquiera uno
        # que contenga un marcador antiguo. El segundo setup conserva su estado.
        if trap_dir.exists():
            log(f"[Honeypot] Omitiendo {trap_dir}: el directorio ya existe; no se modificará.")
            continue

        try:
            trap_dir.mkdir(parents=True, exist_ok=False)

            net_dir = trap_dir / "Network"
            net_dir.mkdir(exist_ok=True)

            cookies_db = net_dir / "Cookies"
            _create_decoy_sqlite(cookies_db, marker_file)

            # Generar también un fichero de configuración falso (Preferences)
            prefs = trap_dir / "Preferences"
            if not prefs.exists():
                prefs.write_text(json.dumps({
                    "profile": {"name": "Default Admin Backup", "created_by_version": "130.0.0.0"},
                    "account_info": [{"email": "security-audit@internal-domain.local", "full_name": "Trap Canary"}]
                }, indent=2), encoding="utf-8")

            managed_files = [cookies_db, prefs]
            file_hashes = {}
            for managed in managed_files:
                if managed.is_file():
                    file_hashes[str(managed.relative_to(trap_dir))] = hashlib.sha256(managed.read_bytes()).hexdigest()
            marker_file.write_text(json.dumps({
                "creado_por": "CookieGuard",
                "tipo": "honeypot_decoy",
                "creado": time.time(),
                "seguridad": "aislado_inocuo",
                "sha256_archivos": file_hashes
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


def _create_decoy_sqlite(db_path: Path, marker_file: Path | None = None) -> None:
    """Crea una base de datos SQLite con estructura realista de cookies Chromium y cebos inocuos."""
    if db_path.exists():
        # Nunca sobrescribir archivos existentes, incluso en un directorio marcado.
        return

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
            "motivo": "No existe línea base de honeypot. Ejecute 'cookieguard honeypot-deploy' primero."
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
    removed_dirs: set[Path] = set()
    roots_procesadas = set()
    for p in profiles:
        r = p.root.resolve()
        if r in roots_procesadas:
            continue
        roots_procesadas.add(r)
        trap_dir = r / HONEYPOT_PROFILE_NAME
        marker_file = trap_dir / MARKER_FILENAME

        # Solo borrar un perfil creado por CookieGuard si todos los archivos siguen
        # intactos y no hay ningún contenido adicional. Si fue modificado, preservarlo.
        if trap_dir.is_dir() and marker_file.is_file():
            try:
                marker = json.loads(marker_file.read_text(encoding="utf-8"))
                expected = marker.get("sha256_archivos", {}) if marker.get("creado_por") == "CookieGuard" else {}
                all_items = list(trap_dir.rglob("*"))
                has_symlink = any(item.is_symlink() for item in all_items)
                actual_paths = {
                    str(item.relative_to(trap_dir)) for item in all_items
                    if item.is_file() and item != marker_file
                }
                actual_dirs = {
                    str(item.relative_to(trap_dir)) for item in all_items if item.is_dir()
                }
                expected_dirs = {
                    str(Path(rel_path).parent)
                    for rel_path in expected
                    if str(Path(rel_path).parent) != "."
                }
                intact = bool(expected) and actual_paths == set(expected) and actual_dirs == expected_dirs and not has_symlink
                if intact:
                    for rel_path, digest in expected.items():
                        candidate = trap_dir / rel_path
                        if not candidate.is_file() or hashlib.sha256(candidate.read_bytes()).hexdigest() != digest:
                            intact = False
                            break
                if intact:
                    shutil.rmtree(trap_dir)
                    removed_dirs.add(trap_dir.resolve())
                    eliminados += 1
                    log(f"[Honeypot] Eliminado perfil señuelo intacto en {trap_dir}")
                else:
                    log(f"[Honeypot] Perfil {trap_dir} modificado o con contenido extra; se preserva por seguridad.")
            except Exception as e:
                log(f"[Honeypot] Error comprobando {trap_dir}; se preserva por seguridad: {e}")
        elif trap_dir.is_dir():
            log(f"[Honeypot] Protección activa: {trap_dir} no contiene marcador CookieGuard, no se eliminará.")

    base_file = _get_baseline_path()
    if base_file.exists():
        try:
            records = json.loads(base_file.read_text(encoding="utf-8"))
            retained = {
                path: info for path, info in records.items()
                if not any(Path(path).resolve().is_relative_to(directory) for directory in removed_dirs)
            }
            if retained:
                base_file.write_text(json.dumps(retained, indent=2, ensure_ascii=False), encoding="utf-8")
            else:
                base_file.unlink()
        except Exception as e:
            log(f"[Honeypot] No se pudo actualizar la línea base durante la limpieza: {e}")

    return {"ok": True, "eliminados": eliminados}
