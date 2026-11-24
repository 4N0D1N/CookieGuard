"""
Pruebas unitarias para las novedades de CookieGuard v2.4.0 (unittest standard library):
- Asistente de Rescate Cero-Confianza (rescue_wizard)
- Auditoría de Descargas Recientes Sospechosas (downloads_audit)
- Trampa Activa con Archivo Cebo (canary_trap)
- Comandos CLI y compatibilidad multiplataforma
"""

import io
import json
import os
import shutil
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cookieguard import canary_trap, downloads_audit, rescue_wizard
from cookieguard.__main__ import main


class TestRescueWizard(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="cg_test_rescue_")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_run_rescue_plan(self):
        res = rescue_wizard.run_rescue_plan(auto=True, killswitch=False, kill_browsers=False, output_dir=self.tmp_dir)
        self.assertEqual(res["fase_actual"], "Completada")
        self.assertEqual(len(res["rotacion_prioritaria"]), 5)
        self.assertIn("archivo_reporte_html", res)
        self.assertTrue(Path(res["archivo_reporte_html"]).exists())
        self.assertIn("archivo_reporte_json", res)
        self.assertTrue(Path(res["archivo_reporte_json"]).exists())

        # Verificar contenido HTML
        html_content = Path(res["archivo_reporte_html"]).read_text(encoding="utf-8")
        self.assertIn("Protocolo de Rescate", html_content)
        self.assertIn("Google (Gmail)", html_content)

    def test_terminate_running_browsers_dry_run(self):
        res = rescue_wizard.terminate_running_browsers(dry_run=True)
        self.assertGreater(len(res), 0)
        self.assertEqual(res[0]["status"], "simulado")


class TestDownloadsAudit(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="cg_test_downloads_")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_classify_risk(self):
        # 1. Doble extensión
        level, reasons = downloads_audit._classify_risk("factura.pdf.exe", "http://example.com")
        self.assertEqual(level, "CRÍTICO")
        self.assertTrue(any("Doble extensión" in r for r in reasons))

        # 2. Extensión de riesgo
        level, reasons = downloads_audit._classify_risk("setup.scr", "http://example.com")
        self.assertEqual(level, "ALTO")

        # 3. Archivo normal pero desde CDN discord
        level, reasons = downloads_audit._classify_risk("documento.zip", "https://cdn.discordapp.com/attachments/123/payload.zip")
        self.assertEqual(level, "CRÍTICO")

        # 4. Inocuo
        level, reasons = downloads_audit._classify_risk("foto.png", "https://example.com/foto.png")
        self.assertEqual(level, "BAJO")

    def test_audit_chromium_downloads(self):
        history_db = Path(self.tmp_dir) / "History"
        conn = sqlite3.connect(str(history_db))
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE downloads (
                id INTEGER PRIMARY KEY,
                target_path TEXT,
                start_time INTEGER,
                total_bytes INTEGER,
                state INTEGER
            )
        """)
        cursor.execute("""
            CREATE TABLE downloads_url_chains (
                id INTEGER,
                chain_index INTEGER,
                url TEXT
            )
        """)

        # Insertar descarga sospechosa reciente
        now_unix = time.time()
        webkit_ts = int((now_unix + 11644473600.0) * 1_000_000.0)
        cursor.execute("INSERT INTO downloads VALUES (1, '/home/user/Downloads/crack_photoshop.exe', ?, 1048576, 1)", (webkit_ts,))
        cursor.execute("INSERT INTO downloads_url_chains VALUES (1, 0, 'https://cdn.discordapp.com/files/crack.exe')")
        conn.commit()
        conn.close()

        res = downloads_audit.audit_chromium_downloads(history_db, max_age_hours=24)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["archivo"], "crack_photoshop.exe")
        self.assertEqual(res[0]["nivel_riesgo"], "CRÍTICO")


class TestCanaryTrap(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="cg_test_canary_")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_deploy_and_check_traps(self):
        cfg_dir = Path(self.tmp_dir) / "cg_cfg"
        target_profile = Path(self.tmp_dir) / "browser_profile"
        target_profile.mkdir(parents=True, exist_ok=True)

        with patch.object(canary_trap, "_get_app_config_dir", return_value=cfg_dir):
            # 1. Desplegar
            deployed = canary_trap.deploy_canary_traps(custom_paths=[target_profile])
            self.assertEqual(len(deployed), 1)
            trap_file = Path(deployed[0]["path"])
            self.assertTrue(trap_file.exists())

            # 2. Comprobar intacta
            check1 = canary_trap.check_canary_traps()
            self.assertFalse(check1["alerta_activa"])
            self.assertEqual(check1["total_trampas"], 1)
            self.assertEqual(check1["intactas"], 1)

            # 3. Simular manipulación (modificar contenido)
            with open(trap_file, "a") as f:
                f.write("malware_tampering")

            check2 = canary_trap.check_canary_traps()
            self.assertTrue(check2["alerta_activa"])
            self.assertEqual(check2["activadas"], 1)

            # 4. Limpieza
            cleaned = canary_trap.cleanup_canary_traps()
            self.assertEqual(cleaned, 1)
            self.assertFalse(trap_file.exists())
            check3 = canary_trap.check_canary_traps()
            self.assertEqual(check3["total_trampas"], 0)


class TestCLIv240(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="cg_test_cliv240_")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_cli_rescue(self):
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            code = main(["rescue", "--auto", "--salida", self.tmp_dir])
        self.assertEqual(code, 0)
        out = captured.getvalue()
        self.assertIn("PROTOCOLO DE RESCATE", out)
        self.assertIn("Fase 1", out)

    def test_cli_descargas(self):
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            code = main(["descargas", "--hours", "72"])
        self.assertIn(code, (0, 1))
        out = captured.getvalue()
        self.assertIn("AUDITORÍA DE DESCARGAS RECIENTES", out)

    def test_cli_trap(self):
        cfg_dir = Path(self.tmp_dir) / "trap_cfg"
        with patch.object(canary_trap, "_get_app_config_dir", return_value=cfg_dir):
            captured = io.StringIO()
            with patch("sys.stdout", captured):
                code = main(["trap", "--check"])
            self.assertIn(code, (0, 2))
            out = captured.getvalue()
            self.assertIn("ESTADO DE TRAMPAS CANARY", out)


if __name__ == "__main__":
    unittest.main()
