"""Lectura SEGURA de metadatos de bases SQLite de navegadores.

PRINCIPIO NO NEGOCIABLE: nunca se leen valores de cookies ni contrasenas.
Se usa una LISTA BLANCA de columnas de metadatos: cualquier otra columna provoca un error.
Se trabaja siempre sobre una COPIA temporal; el original no se modifica.
"""
from __future__ import annotations

import shutil
import sqlite3
import tempfile
from pathlib import Path

from .common import IS_WIN, data_dir, is_admin, run

# Unicas columnas que el programa puede pedir (solo metadatos).
ALLOWED_COLUMNS = frozenset({
    # Chromium: tabla cookies
    "host_key", "name", "path", "creation_utc", "expires_utc", "last_access_utc", "last_update_utc",
    "is_secure", "is_httponly", "samesite", "is_persistent", "has_expires", "source_scheme",
    # Firefox: tabla moz_cookies
    "host", "expiry", "lastAccessed", "creationTime", "isSecure", "isHttpOnly", "sameSite",
})
ALLOWED_TABLES = frozenset({"cookies", "moz_cookies"})


class DbLocked(Exception):
    pass


def _win_copy(src: str, dst: str) -> None:
    """Copia con CreateFileW compartiendo lectura/escritura/borrado (equivale a FileShare.ReadWrite)."""
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    k32.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                             ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    h = k32.CreateFileW(src, 0x80000000, 7, None, 3, 0x80, None)  # GENERIC_READ, share RWD, OPEN_EXISTING
    if h is None or h == ctypes.c_void_p(-1).value:
        raise DbLocked(f"no se puede abrir (error {ctypes.get_last_error()})")
    try:
        buf = ctypes.create_string_buffer(1 << 20)
        got = wintypes.DWORD(0)
        with open(dst, "wb") as out:
            while True:
                ok = k32.ReadFile(h, buf, len(buf), ctypes.byref(got), None)
                if not ok:
                    raise DbLocked(f"lectura fallida (error {ctypes.get_last_error()})")
                if got.value == 0:
                    break
                out.write(buf.raw[:got.value])
    finally:
        k32.CloseHandle(h)


def _copy_file(src: Path, dst: Path) -> None:
    if IS_WIN:
        try:
            _win_copy(str(src), str(dst))
            return
        except DbLocked:
            # Plan B: Volume Shadow Copy (solo con administrador)
            if is_admin():
                code, _, _ = run(["esentutl.exe", "/y", str(src), "/vss", "/d", str(dst)], timeout=120)
                if code == 0 and dst.exists():
                    return
            raise
    shutil.copyfile(src, dst)


def safe_copy(src: Path) -> Path:
    """Copia la BD (y -wal/-journal/-shm) a una carpeta temporal privada. Devuelve la ruta de la copia."""
    tmp = Path(tempfile.mkdtemp(prefix="cg_", dir=str(data_dir() / "tmp")))
    dst = tmp / "db.sqlite"
    try:
        _copy_file(src, dst)
    except Exception as e:  # noqa: BLE001
        shutil.rmtree(tmp, ignore_errors=True)
        raise DbLocked(f"{Path(src).name} bloqueada o sin permiso: {e}")
    for suf in ("-wal", "-journal", "-shm"):
        s = Path(str(src) + suf)
        if s.exists():
            try:
                _copy_file(s, Path(str(dst) + suf))
            except Exception:
                pass
    return dst


def cleanup_copy(copy_path: Path) -> None:
    shutil.rmtree(copy_path.parent, ignore_errors=True)


def read_metadata(src: Path, table: str, wanted: list[str]) -> list[dict]:
    """Devuelve filas con SOLO las columnas de metadatos permitidas que existan en la tabla."""
    if table not in ALLOWED_TABLES:
        raise ValueError("tabla no permitida")
    bad = [c for c in wanted if c not in ALLOWED_COLUMNS]
    if bad:
        raise ValueError(f"columna no permitida (solo metadatos): {bad}")
    try:
        cp = safe_copy(src)
        try:
            con = sqlite3.connect(str(cp))
            try:
                existing = {r[1] for r in con.execute(f"PRAGMA table_info({table})")}
                cols = [c for c in wanted if c in existing]
                if not cols:
                    return []
                cur = con.execute(f"SELECT {', '.join(cols)} FROM {table}")
                return [dict(zip(cols, row)) for row in cur]
            finally:
                con.close()
        finally:
            cleanup_copy(cp)
    except DbLocked as err:
        # Fallback de solo lectura inmutable directo si la copia está bloqueada por el navegador activo:
        try:
            uri = f"{Path(src).resolve().as_uri()}?mode=ro&immutable=1"
            con = sqlite3.connect(uri, uri=True)
            try:
                existing = {r[1] for r in con.execute(f"PRAGMA table_info({table})")}
                cols = [c for c in wanted if c in existing]
                if not cols:
                    return []
                cur = con.execute(f"SELECT {', '.join(cols)} FROM {table}")
                return [dict(zip(cols, row)) for row in cur]
            finally:
                con.close()
        except Exception:
            raise err


def table_names(path: Path) -> list[str]:
    """Nombres de tabla de una BD (para detectar copias sospechosas). No lee filas."""
    try:
        cp = safe_copy(path)
        try:
            con = sqlite3.connect(str(cp))
            try:
                return [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            finally:
                con.close()
        finally:
            cleanup_copy(cp)
    except DbLocked as err:
        try:
            uri = f"{Path(path).resolve().as_uri()}?mode=ro&immutable=1"
            con = sqlite3.connect(uri, uri=True)
            try:
                return [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            finally:
                con.close()
        except Exception:
            raise err
