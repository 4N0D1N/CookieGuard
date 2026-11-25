"""Pruebas unitarias para la interfaz de escritorio moderna con PyWebView."""
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path

from cookieguard.common import VERSION
from cookieguard.webview_app import BridgeApi, get_dashboard_html


class TestWebviewApp(unittest.TestCase):
    def setUp(self):
        self.api = BridgeApi()

    def test_get_initial_data(self):
        data = self.api.get_initial_data()
        self.assertIsInstance(data, dict)
        self.assertEqual(data.get("version"), VERSION)
        self.assertIn("theme", data)
        self.assertIn("canary", data)

    def test_get_dashboard_html_structure(self):
        html = get_dashboard_html()
        self.assertIsInstance(html, str)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("CookieGuard", html)
        self.assertIn("svg-gauge", html)
        self.assertIn("grid-kpi", html)
        self.assertIn("view-resumen", html)
        self.assertIn("view-sesiones", html)
        self.assertIn("view-indicadores", html)
        self.assertIn("view-canary", html)
        self.assertIn("view-playbooks", html)
        self.assertIn("view-herramientas", html)
        self.assertIn("callApi", html)

    def test_check_canary(self):
        res = self.api.check_canary()
        self.assertIsInstance(res, dict)
        self.assertIn("alerta_activa", res)
        self.assertIn("total_trampas", res)

    def test_save_theme_preference(self):
        ok = self.api.save_theme_preference("oscuro")
        self.assertTrue(ok)

    def test_run_specialized_tool_persistence(self):
        res = self.api.run_specialized_tool("persistence")
        self.assertTrue(res.get("ok"))
        self.assertIn("data", res)

    def test_run_specialized_tool_unknown(self):
        res = self.api.run_specialized_tool("herramienta_inexistente")
        self.assertFalse(res.get("ok"))
        self.assertIn("error", res)

    def test_open_url_safety(self):
        # Enlaces no válidos no deben abrir navegador
        self.assertFalse(self.api.open_url("javascript:alert(1)"))
        self.assertFalse(self.api.open_url("file:///etc/passwd"))

    @patch("cookieguard.engine.run_analysis")
    @patch("cookieguard.browsers.discover")
    def test_run_scan(self, mock_discover, mock_run_analysis):
        mock_discover.return_value = []
        mock_run_analysis.return_value = {
            "veredicto": {"nivel": "verde", "nombre": "Verde", "puntos": 0, "texto": "Limpio"},
            "estadisticas": {"total_cookies": 10, "servicios_unicos": 2, "servicios_criticos": 0, "total_perfiles": 1, "alertas_activas": 0},
            "grupos": [{"nombre": "Google", "dominio": "google.com", "total_cookies": 5, "critico": False}],
            "indicadores": []
        }
        res = self.api.run_scan()
        self.assertEqual(res["veredicto"]["nivel"], "verde")
        self.assertEqual(self.api.last_res, res)


if __name__ == "__main__":
    unittest.main()
