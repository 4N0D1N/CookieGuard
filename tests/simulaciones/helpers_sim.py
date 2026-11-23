"""Perfil falso de Chromium para las simulaciones (solo metadatos, sin valores)."""
import sqlite3
from pathlib import Path

from cookieguard.browsers import Profile


def fake_profile(root: Path) -> Profile:
    root = Path(root)
    (root / "Default" / "Network").mkdir(parents=True, exist_ok=True)
    (root / "Local State").write_text("{}")
    db = root / "Default" / "Network" / "Cookies"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE IF NOT EXISTS cookies (host_key TEXT, name TEXT, path TEXT)")
    con.execute("INSERT INTO cookies VALUES ('falso.test','sesion','/')")
    con.commit()
    con.close()
    return Profile("Chromium (simulacion)", "chromium", "Default", root / "Default", db, root)
