"""Módulo de auditoría de integridad y análisis forense de bases de datos SQLite de navegadores.

Detecta anomalías físicas en ficheros SQLite de cookies y credenciales (Cookies, Login Data):
- Corrupción de cabecera mágica (magic bytes 'SQLite format 3\000').
- Anomalías de marcas de tiempo / Time-Stomping entre fichero principal y ficheros WAL/SHM.
- Conteo elevado de páginas en Freelist (indicio de borrado masivo de registros para cubrir huellas).
- Verificación rápida de integridad (PRAGMA quick_check).
"""
from __future__ import annotations

import os
import sqlite3
import struct
import time
from pathlib import Path
from typing import Any

from .browsers import discover
from .common import log

SQLITE_HEADER_MAGIC = b"SQLite format 3\x00"


def inspect_sqlite_file(db_path: Path) -> dict[str, Any]:
    """Realiza una inspección física y lógica de bajo nivel sobre una base de datos SQLite."""
    res: dict[str, Any] = {
        "archivo": str(db_path),
        "nombre": db_path.name,
        "existe": db_path.exists(),
        "tamano_bytes": 0,
        "mtime": None,
        "mtime_legible": None,
        "magic_valido": False,
        "page_size": 0,
        "page_count": 0,
        "freelist_count": 0,
        "wal_presente": False,
        "wal_tamano": 0,
        "wal_mtime": None,
        "shm_presente": False,
        "quick_check": None,
        "hallazgos": []
    }

    if not db_path.exists() or not db_path.is_file():
        return res

    try:
        stat = db_path.stat()
        res["tamano_bytes"] = stat.st_size
        res["mtime"] = stat.st_mtime
        res["mtime_legible"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime))
    except Exception as e:
        res["hallazgos"].append({"severidad": "Baja", "descripcion": f"No se pudo obtener metadatos stat: {e}"})
        return res

    # 1. Inspección de cabecera SQLite
    if res["tamano_bytes"] < 100:
        res["hallazgos"].append({"severidad": "Alta", "descripcion": "Archivo SQLite truncado o de tamaño inferior a cabecera mínima (100 bytes)"})
        return res

    try:
        with open(db_path, "rb") as f:
            header = f.read(100)
            if header.startswith(SQLITE_HEADER_MAGIC):
                res["magic_valido"] = True
                page_size = struct.unpack(">H", header[16:18])[0]
                if page_size == 1:
                    page_size = 65536
                res["page_size"] = page_size
                res["freelist_count"] = struct.unpack(">I", header[36:40])[0]
            else:
                res["hallazgos"].append({
                    "severidad": "Crítica",
                    "descripcion": "Cabecera SQLite inválida: magic bytes no coinciden con 'SQLite format 3'"
                })
    except Exception as e:
        res["hallazgos"].append({"severidad": "Alta", "descripcion": f"Error leyendo cabecera binaria: {e}"})

    # 2. Análisis de ficheros WAL y SHM y verificación de Time-Stomping
    wal_path = db_path.with_name(db_path.name + "-wal")
    shm_path = db_path.with_name(db_path.name + "-shm")

    if wal_path.exists():
        res["wal_presente"] = True
        try:
            wal_stat = wal_path.stat()
            res["wal_tamano"] = wal_stat.st_size
            res["wal_mtime"] = wal_stat.st_mtime
            # Detección de Time-Stomping: WAL modificado recientemente pero DB principal con mtime antigua
            time_diff = wal_stat.st_mtime - stat.st_mtime
            if time_diff > 3600:  # Más de 1 hora de diferencia
                res["hallazgos"].append({
                    "severidad": "Media",
                    "descripcion": f"Posible Time-Stomping o desincronización WAL: WAL modificado {int(time_diff/60)} minutos después de la base de datos principal"
                })
        except Exception:
            pass

    if shm_path.exists():
        res["shm_presente"] = True

    # 3. Verificación de integridad lógica con SQLite
    try:
        uri = f"file:{db_path.resolve().as_posix()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=2.0)
        try:
            cur = conn.cursor()
            cur.execute("PRAGMA quick_check;")
            row = cur.fetchone()
            res["quick_check"] = row[0] if row else "unknown"
            if res["quick_check"] != "ok":
                res["hallazgos"].append({
                    "severidad": "Alta",
                    "descripcion": f"Fallo en PRAGMA quick_check: {res['quick_check']}"
                })

            cur.execute("PRAGMA page_count;")
            p_row = cur.fetchone()
            if p_row:
                res["page_count"] = p_row[0]

            cur.execute("PRAGMA freelist_count;")
            f_row = cur.fetchone()
            if f_row:
                res["freelist_count"] = f_row[0]

            # Alerta si más del 40% de las páginas están en la lista libre (borrado masivo reciente)
            if res["page_count"] > 10 and (res["freelist_count"] / res["page_count"]) > 0.4:
                pct = int((res["freelist_count"] / res["page_count"]) * 100)
                res["hallazgos"].append({
                    "severidad": "Media",
                    "descripcion": f"Alto porcentaje de páginas libres ({pct}% freelist): posible borrado reciente de registros"
                })
        finally:
            conn.close()
    except sqlite3.OperationalError as e:
        # DB bloqueada por navegador abierto o en uso
        res["hallazgos"].append({
            "severidad": "Baja",
            "descripcion": f"Base de datos bloqueada o en uso concurrente ({e})"
        })
    except Exception as e:
        res["hallazgos"].append({
            "severidad": "Media",
            "descripcion": f"Error en comprobación de integridad SQLite: {e}"
        })

    return res


def audit_browser_databases() -> dict[str, Any]:
    """Audita todas las bases de datos de cookies y credenciales encontradas en los perfiles instalados."""
    profiles = discover()
    results: list[dict[str, Any]] = []
    total_alertas = 0

    target_filenames = [
        "Cookies", "Network/Cookies", "cookies.sqlite",
        "Login Data", "Web Data"
    ]

    for p in profiles:
        p_path = p.path
        nav = p.name
        perf = p.profile_name

        for tf in target_filenames:
            db_p = p_path / tf
            if db_p.exists() and db_p.is_file():
                info = inspect_sqlite_file(db_p)
                info["navegador"] = nav
                info["perfil"] = perf
                info["tipo_almacen"] = tf
                results.append(info)
                total_alertas += len(info["hallazgos"])

    return {
        "total_dbs_analizadas": len(results),
        "total_alertas": total_alertas,
        "bases_de_datos": results,
        "recomendacion": "Si detectas corrupción de cabecera o anomalías de integridad, examina posibles procesos no autorizados accediendo a los ficheros." if total_alertas > 0 else None
    }
