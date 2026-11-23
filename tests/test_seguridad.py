"""Test 'NUNCA se leen valores' + privacidad: codigo, salidas, red y permisos."""
import os
import re
import unittest
import zipfile
from pathlib import Path

from helpers import ROOT, SENTINEL, TmpHome, make_chromium, make_firefox  # noqa: E402

from cookieguard import actions, engine, reports, sqlite_meta  # noqa: E402
from cookieguard.browsers import discover  # noqa: E402
from datetime import datetime, timedelta  # noqa: E402

SRC = sorted((ROOT / "cookieguard").glob("*.py"))


class TestNuncaValores(TmpHome):
    def test_lista_blanca_sin_columnas_de_valor(self):
        forbidden = {"value", "encrypted_value", "password_value", "values", "username_value"}
        self.assertFalse(forbidden & set(sqlite_meta.ALLOWED_COLUMNS))

    def test_columna_de_valor_rechazada(self):
        db = make_chromium(self.tmp / "r", self.sample_rows())
        for col in ("value", "encrypted_value", "password_value"):
            with self.assertRaises(ValueError):
                sqlite_meta.read_metadata(db, "cookies", ["host_key", col])
        with self.assertRaises(ValueError):
            sqlite_meta.read_metadata(db, "logins", ["origin_url"])

    def test_codigo_sin_lecturas_de_valores(self):
        pat_cols = re.compile(r"encrypted_value|password_value|username_value")
        pat_sql = re.compile(r"select[^;\"']*\b(value|\*)\b[^;\"']*\bfrom\b", re.I | re.S)
        for f in SRC:
            txt = f.read_text(encoding="utf-8")
            self.assertIsNone(pat_cols.search(txt), f"{f.name} menciona una columna de valor")
            for m in pat_sql.finditer(txt):
                # unico SELECT permitido: COUNT(*) y la lista de columnas validada
                self.assertIn("COUNT(*)", m.group(0).upper(), f"{f.name}: SELECT sospechoso: {m.group(0)[:80]}")

    def test_sin_red_ni_exfiltracion(self):
        pat = re.compile(r"^\s*(import|from)\s+(requests|urllib\.request|http\.client|socket|ftplib|smtplib|telnetlib)\b", re.M)
        for f in SRC:
            self.assertIsNone(pat.search(f.read_text(encoding="utf-8")), f"{f.name} importa un modulo de red")

    def test_salidas_no_contienen_el_valor(self):
        make_chromium(self.tmp / "c", self.sample_rows())
        make_firefox(self.tmp / "f", [{"host": ".github.com", "name": "user_session", "expires": datetime.now() + timedelta(days=9)}])
        profiles = discover([self.tmp / "c"], [self.tmp / "f"], only_extra=True)
        empty = self.tmp / "vacio"
        empty.mkdir()
        res = engine.run_analysis(profiles, scan_dirs=[empty])
        out = self.tmp / "salidas"
        out.mkdir()
        reports.export_html(res, out / "a.html")
        reports.export_json(res, out / "a.json")
        reports.export_csv(res["grupos"], out / "a.csv")
        from cookieguard.inventory import collect
        sessions, _, _ = collect(profiles)
        reports.export_sessions_csv(sessions, out / "s.csv")
        z = actions.incident_zip(res)
        reports.write_reports(res)
        blobs = [p for p in out.iterdir()] + [z]
        blobs += list((Path(os.environ["COOKIEGUARD_HOME"])).rglob("*"))
        checked = 0
        for p in blobs:
            if not p.is_file() or p.suffix == ".sqlite":
                continue
            data = p.read_bytes()
            if p.suffix == ".zip":
                with zipfile.ZipFile(p) as zf:
                    data = b"".join(zf.read(n) for n in zf.namelist())
            self.assertNotIn(SENTINEL.encode(), data, f"valor filtrado en {p.name}")
            checked += 1
        self.assertGreater(checked, 5)

    def test_copias_temporales_se_borran(self):
        db = make_chromium(self.tmp / "r", self.sample_rows())
        sqlite_meta.read_metadata(db, "cookies", ["host_key", "name"])
        tmp = Path(os.environ["COOKIEGUARD_HOME"]) / "tmp"
        self.assertEqual([p for p in tmp.iterdir()], [])

    @unittest.skipIf(os.name == "nt", "permisos POSIX")
    def test_permisos_carpeta_datos_linux(self):
        from cookieguard.common import data_dir
        self.assertEqual(data_dir().stat().st_mode & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
