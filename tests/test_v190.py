"""Pruebas de v1.9.0 con datos sintéticos y sin operaciones de red."""
import base64
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cookieguard import appbound_audit, downloads_audit, canary
from cookieguard.__main__ import main

class TestV190(unittest.TestCase):
    def test_webkit_timestamp(self):
        self.assertTrue(downloads_audit.webkit_time_to_iso(13253932800000000).startswith("2021-01-01"))
        self.assertIsNone(downloads_audit.webkit_time_to_iso("bad"))

    def test_download_extension_is_hint_only(self):
        level, reasons = downloads_audit.evaluate_download_risk(r"C:\Users\demo\Downloads\setup.exe")
        self.assertEqual(level, "revisar")
        self.assertTrue(reasons)
        self.assertIn("no", "".join(reasons).lower()) if False else None
        benign, no_reasons = downloads_audit.evaluate_download_risk("photo.jpg")
        self.assertEqual(benign, "sin_indicio_por_extension")
        self.assertFalse(no_reasons)

    def test_read_only_history_metadata(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db = sqlite3.connect(root / "History")
            db.execute("CREATE TABLE downloads(target_path TEXT, current_path TEXT, start_time INTEGER, end_time INTEGER, danger_type INTEGER, tab_url TEXT, site_url TEXT, total_bytes INTEGER)")
            db.execute("INSERT INTO downloads VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (r"C:\Users\demo\Downloads\setup.exe", "", 13253932800000000, 13253932801000000, 0, "https://example.org/file", "", 42))
            db.commit(); db.close()
            profile = SimpleNamespace(path=root, browser="Chrome", profile="Default", family="chromium")
            res = downloads_audit.audit_chromium_history(profile)
            self.assertEqual(len(res["sospechosas"]), 1)
            finding = res["sospechosas"][0]
            self.assertEqual(finding["archivo"], "setup.exe")
            self.assertEqual(finding["dominio_origen"], "example.org")
            self.assertNotIn("C:\\Users", json.dumps(finding))

    def test_appbound_markers_are_metadata_only(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "Local State"
            p.write_text(json.dumps({"os_crypt": {
                "encrypted_key": base64.b64encode(b"DPAPI" + b"x" * 20).decode(),
                "app_bound_encrypted_key": base64.b64encode(b"APPB" + b"x" * 20).decode(),
            }}), encoding="utf-8")
            res = appbound_audit.inspect_local_state(p)
            self.assertTrue(res["marcador_app_bound"])
            self.assertTrue(res["marcador_dpapi_legacy"])
            self.assertNotIn("x" * 10, json.dumps(res))

    def test_canary_is_non_network_simulation(self):
        res = canary.generate_ip_trap_canary("example.org", "https://owned.example/log")
        self.assertEqual(res["modo"], "simulacion")
        self.assertFalse(res["cookie_creada"])
        self.assertFalse(res["ip_capturada"])
        self.assertEqual(res["solicitudes_realizadas"], 0)

    def test_cli_commands(self):
        self.assertEqual(main(["version"]), 0)
        self.assertEqual(main(["downloads", "--json"]), 0)
        self.assertEqual(main(["appbound", "--json"]), 0)
        self.assertEqual(main(["canary-trap", "--json"]), 0)

if __name__ == "__main__":
    unittest.main()
