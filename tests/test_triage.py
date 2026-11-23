"""Tests para el módulo de rescate y triaje USB."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cookieguard.triage import run_triage


class TestTriage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out_dir = Path(self.tmp.name) / "rescate_test"

    def tearDown(self):
        self.tmp.cleanup()

    @patch("cookieguard.engine.run_login")
    @patch("cookieguard.process_hunter.scan_processes")
    @patch("webbrowser.open")
    def test_run_triage_generates_files(self, mock_browser, mock_ph, mock_engine):
        mock_engine.return_value = {
            "veredicto": {"nombre": "Rojo", "puntos": 45, "texto": "Alerta"},
            "estadisticas": {"cookies_sesion": 10, "perfiles": 2},
            "grupos": [
                {
                    "nombre": "Google",
                    "dominio": ".google.com",
                    "criticidad": "Critica",
                    "total_cookies": 4,
                    "url_revocacion": "https://myaccount.google.com/security"
                }
            ],
            "indicadores": [],
            "informe": str(self.out_dir / "informe.html")
        }
        mock_ph.return_value = {
            "limpio": False,
            "sospechosos": [
                {
                    "pid": 5555,
                    "name": "malware.exe",
                    "exe": "C:\\Temp\\malware.exe",
                    "familia": "LummaC2",
                    "severidad": "CRITICA",
                    "motivo": "Firma maliciosa detectada",
                    "comando": "taskkill /F /PID 5555"
                }
            ]
        }

        # Crear archivo informe dummy
        self.out_dir.mkdir(parents=True, exist_ok=True)
        (self.out_dir / "informe.html").write_text("<html>Dummy</html>", encoding="utf-8")

        res = run_triage(salida_dir=self.out_dir, open_report=False)

        self.assertTrue(Path(res["txt"]).exists())
        self.assertTrue(Path(res["json"]).exists())

        txt_content = Path(res["txt"]).read_text(encoding="utf-8")
        self.assertIn("COOKIEGUARD - PROTOCOLO DE RESCATE", txt_content)
        self.assertIn("Google (.google.com)", txt_content)
        self.assertIn("malware.exe", txt_content)
        self.assertIn("taskkill /F /PID 5555", txt_content)


if __name__ == "__main__":
    unittest.main()
