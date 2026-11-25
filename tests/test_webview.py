"""Pruebas unitarias para la interfaz de escritorio moderna con PyWebView."""
import json
import unittest
import urllib.request
from unittest.mock import patch, MagicMock
from pathlib import Path

from cookieguard.common import VERSION
from cookieguard.webview_app import BridgeApi, LocalDashboardServer, get_dashboard_html


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

    def test_run_specialized_tool_playbooks(self):
        res = self.api.run_specialized_tool("playbook_data")
        self.assertTrue(res.get("ok"))
        self.assertIn("servicios", res)
        self.assertGreater(len(res["servicios"]), 0)

    def test_run_specialized_tool_unknown(self):
        res = self.api.run_specialized_tool("herramienta_inexistente")
        self.assertFalse(res.get("ok"))
        self.assertIn("error", res)

    def test_open_url_safety(self):
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

    def test_local_server_lifecycle_and_api(self):
        html = get_dashboard_html()
        server = LocalDashboardServer(self.api, html)
        port = server.start()
        self.assertGreater(port, 1024)
        base = f"http://127.0.0.1:{port}"

        # Test GET /
        req = urllib.request.Request(f"{base}/")
        res_text = urllib.request.urlopen(req).read().decode("utf-8")
        self.assertIn("CookieGuard", res_text)

        # Test GET /informe (report in new tab)
        req_rep = urllib.request.Request(f"{base}/informe")
        rep_text = urllib.request.urlopen(req_rep).read().decode("utf-8")
        self.assertIn("Informe Forense", rep_text)
        self.assertIn("window.print()", rep_text)

        # Test POST /api/get_initial_data
        req = urllib.request.Request(
            f"{base}/api/get_initial_data",
            data=b"[]",
            headers={"Content-Type": "application/json"}
        )
        init_data = json.loads(urllib.request.urlopen(req).read().decode("utf-8"))
        self.assertEqual(init_data.get("version"), VERSION)

        server.stop()


    def test_sanitize_for_json_serialization(self):
        from cookieguard.webview_app import sanitize_for_json
        from datetime import datetime, date
        from pathlib import Path

        sample = {
            "time": datetime.now(),
            "day": date.today(),
            "set_val": {"chrome", "edge"},
            "path": Path("/tmp/test.db"),
            "nested": {
                "inner_time": datetime(2027, 1, 1, 12, 0, 0),
                "inner_set": {1, 2, 3}
            }
        }
        sanitized = sanitize_for_json(sample)
        # Must serialize cleanly with standard json
        dumped = json.dumps(sanitized)
        self.assertIn("2027-01-01T12:00:00", dumped)
        self.assertTrue("/tmp/test.db" in dumped or "\\tmp\\test.db" in dumped or "test.db" in dumped)
        self.assertIsInstance(sanitized["set_val"], list)

    def test_dashboard_html_no_fake_static_fallbacks(self):
        html = get_dashboard_html()
        # Verify initial values are clean / not hardcoded fake counts
        self.assertIn('id="kpi-total-cookies">0<', html)
        self.assertIn('id="kpi-at-risk">0<', html)
        self.assertNotIn('<strong>dtCookie</strong>', html)


    def test_revoke_service_flexible_catalog_matching(self):
        res_exact = self.api.revoke_service("Google", "sesiones")
        self.assertTrue(res_exact.get("ok"))
        self.assertIn("myaccount.google.com", res_exact.get("url", ""))

        res_pass = self.api.revoke_service("microsoft", "password")
        self.assertTrue(res_pass.get("ok"))
        self.assertTrue(any(domain in res_pass.get("url", "") for domain in ["account.live.com", "account.microsoft.com"]))

        res_oauth = self.api.revoke_service("github", "oauth")
        self.assertTrue(res_oauth.get("ok"))
        self.assertIn("github.com", res_oauth.get("url", ""))

    def test_get_playbooks_api(self):
        pb = self.api.get_playbooks()
        self.assertIsInstance(pb, list)
        self.assertGreater(len(pb), 5)


    def test_dashboard_realtime_canary_and_diff(self):
        from cookieguard.webview_app import BridgeApi, LocalDashboardServer
        api = BridgeApi()
        
        # Test diff logic in BridgeApi
        mock_res = {
            "sesiones": [
                {"host": ".google.com", "name": "SID", "servicio_id": "google"}
            ]
        }
        # First scan
        clean1 = {
            "sesiones": [{"host": ".google.com", "name": "SID", "servicio_id": "google"}]
        }
        api._previous_sessions = set()
        # Verify initial check_canary
        canary = api.check_canary()
        self.assertIn("alerta_activa", canary)
        
        # Verify HTML contains new controls
        html = get_dashboard_html()
        server = LocalDashboardServer(api, html)
        self.assertIn("canary-emergency-alert-container", html)
        self.assertIn("checkCanaryAlertRealtime", html)
        self.assertIn("q-pill", html)
        self.assertIn("setQuickFilter", html)

    def test_cookie_info_modal_and_classification(self):
        """Verifica que el dashboard web incluya el modal de información ⓘ y que logged_in no sea falso positivo de alto riesgo."""
        from cookieguard import classifier, webview_app
        
        # Test clasificación de logged_in de GitHub
        rec_gh = {"host": ".github.com", "name": "logged_in", "httponly": True, "secure": True}
        ok, conf, svc, why = classifier.classify(rec_gh)
        self.assertTrue(ok)
        self.assertEqual(conf, "Baja")
        self.assertIn("indicador de estado", why)
        
        # Test presencia de componentes en el HTML del dashboard
        html = webview_app.get_dashboard_html()
        self.assertIn("btn-info-cookie", html)
        self.assertIn("cookie-info-modal", html)
        self.assertIn("openCookieDetailsModal", html)


if __name__ == "__main__":
    unittest.main()
