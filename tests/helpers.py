"""Utilidades de prueba: perfiles falsos de Chromium/Firefox con un valor centinela que NUNCA debe salir."""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SENTINEL = "SENTINEL_SECRET_VALUE_9f8e7d6c"
CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def chrome_us(dt: datetime) -> int:
    """datetime local ingenuo -> microsegundos desde 1601 (UTC)."""
    return int((dt.astimezone(timezone.utc) - CHROME_EPOCH).total_seconds() * 1_000_000)


def make_chromium(root: Path, rows: list[dict], profile: str = "Default") -> Path:
    """Crea root/<profile>/Network/Cookies con el esquema de Chromium (incluye columnas de valor con centinela)."""
    pdir = root / profile
    (pdir / "Network").mkdir(parents=True, exist_ok=True)
    (root / "Local State").write_text("{}")
    db = pdir / "Network" / "Cookies"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE cookies (creation_utc INTEGER, host_key TEXT, top_frame_site_key TEXT, name TEXT, "
                "value TEXT, encrypted_value BLOB, path TEXT, expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, "
                "last_access_utc INTEGER, has_expires INTEGER, is_persistent INTEGER, priority INTEGER, samesite INTEGER, "
                "source_scheme INTEGER, source_port INTEGER, last_update_utc INTEGER)")
    now = datetime.now()
    for r in rows:
        con.execute("INSERT INTO cookies VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
            chrome_us(r.get("created", now - timedelta(days=30))), r["host"], "", r["name"], SENTINEL,
            SENTINEL.encode(), r.get("path", "/"), chrome_us(r["expires"]) if r.get("expires") else 0,
            int(r.get("secure", True)), int(r.get("httponly", True)), chrome_us(r.get("last_access", now)),
            int(bool(r.get("expires"))), int(bool(r.get("expires"))), 1, 0, 2, 443,
            chrome_us(r.get("updated", r.get("last_access", now)))))
    con.commit()
    con.close()
    return db


def make_firefox(root: Path, rows: list[dict], profile: str = "abc.default-release") -> Path:
    pdir = root / profile
    pdir.mkdir(parents=True, exist_ok=True)
    (root / "profiles.ini").write_text(f"[Profile0]\nName=default-release\nIsRelative=1\nPath={profile}\nDefault=1\n")
    db = pdir / "cookies.sqlite"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, originAttributes TEXT, name TEXT, value TEXT, host TEXT, "
                "path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, "
                "sameSite INTEGER)")
    now = datetime.now()
    for r in rows:
        con.execute("INSERT INTO moz_cookies (name,value,host,path,expiry,lastAccessed,creationTime,isSecure,isHttpOnly,sameSite) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (r["name"], SENTINEL, r["host"], "/", int(r["expires"].timestamp()),
                     int(r.get("last_access", now).timestamp() * 1e6), int(now.timestamp() * 1e6), 1, 1, 0))
    con.commit()
    con.close()
    return db


class TmpHome(unittest.TestCase):
    """Cada test usa una carpeta de datos temporal (no toca la del usuario)."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)
        self._old = os.environ.get("COOKIEGUARD_HOME")
        os.environ["COOKIEGUARD_HOME"] = str(self.tmp / "cg_home")
        from cookieguard import classifier
        classifier.catalog.cache_clear()

    def tearDown(self):
        if self._old is None:
            os.environ.pop("COOKIEGUARD_HOME", None)
        else:
            os.environ["COOKIEGUARD_HOME"] = self._old
        try:
            self._td.cleanup()
        except Exception:
            pass

    def sample_rows(self):
        now = datetime.now()
        return [
            {"host": ".google.com", "name": "SID", "expires": now + timedelta(days=900), "last_access": now - timedelta(days=200)},
            {"host": ".google.com", "name": "__Secure-1PSID", "expires": now + timedelta(days=900), "last_access": now - timedelta(days=200)},
            {"host": ".github.com", "name": "user_session", "expires": now + timedelta(days=3), "last_access": now - timedelta(days=1)},
            {"host": ".example.com", "name": "my_session_id", "expires": now + timedelta(days=30), "last_access": now},
            {"host": ".example.com", "name": "_ga", "expires": now + timedelta(days=400), "last_access": now},
            {"host": ".bbva.es", "name": "sessionid", "expires": None, "last_access": now, "httponly": True},
        ]
