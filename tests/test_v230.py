"""
Pruebas unitarias de las funcionalidades añadidas en v2.3.0:
1. Auditoría de depuración remota y puertos CDP (remote_debugging_audit).
2. Generador y validador de directivas de hardening para navegadores (browser_hardening).
3. Chequeo integral de salud de sensores locales Doctor (sensor_health).
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
from unittest.mock import patch

from cookieguard.remote_debugging_audit import audit_remote_debugging
from cookieguard.browser_hardening import (
    generate_windows_reg_script,
    generate_linux_policy_json,
    generate_firefox_policy_json,
    generate_hardening_bundle,
    audit_system_policies,
    CHROMIUM_RECOMMENDED_POLICIES
)
from cookieguard.sensor_health import (
    run_sensor_diagnostic,
    format_sensor_diagnostic_cli
)
from cookieguard import __main__ as cg_main


class TestRemoteDebuggingAudit(unittest.TestCase):
    def test_clean_processes(self):
        clean_procs = [
            {"pid": 100, "exe": "chrome.exe", "cmdline": "chrome.exe https://example.com", "args": ["chrome.exe", "https://example.com"]},
            {"pid": 200, "exe": "firefox", "cmdline": "/usr/bin/firefox", "args": ["/usr/bin/firefox"]}
        ]
        res = audit_remote_debugging(test_processes=clean_procs, test_ports=[])
        self.assertEqual(res["total_alertas"], 0)
        self.assertEqual(res["nivel_general"], "Limpio")
        self.assertEqual(len(res["procesos_sospechosos"]), 0)

    def test_remote_debugging_port_detected(self):
        malicious_procs = [
            {
                "pid": 1337,
                "exe": "chrome.exe",
                "cmdline": "chrome.exe --remote-debugging-port=9222 --user-data-dir=C:\\Temp\\Profile",
                "args": ["chrome.exe", "--remote-debugging-port=9222"]
            }
        ]
        res = audit_remote_debugging(test_processes=malicious_procs, test_ports=[])
        self.assertGreater(res["total_alertas"], 0)
        self.assertEqual(res["nivel_general"], "Crítico")
        self.assertEqual(len(res["procesos_sospechosos"]), 1)
        self.assertIn("depuración remota", res["recomendacion"].lower())

    def test_automation_and_pipe_detected(self):
        procs = [
            {
                "pid": 2048,
                "exe": "msedge.exe",
                "cmdline": "msedge.exe --remote-debugging-pipe --enable-automation",
                "args": ["msedge.exe", "--remote-debugging-pipe", "--enable-automation"]
            }
        ]
        res = audit_remote_debugging(test_processes=procs, test_ports=[])
        self.assertEqual(res["nivel_general"], "Crítico")
        flags = [h["flag"] for h in res["procesos_sospechosos"][0]["hallazgos"]]
        self.assertIn("--remote-debugging-pipe", flags)
        self.assertIn("--enable-automation", flags)

    def test_cdp_port_active(self):
        res = audit_remote_debugging(test_processes=[], test_ports=[9222, 9229])
        self.assertIn(9222, res["puertos_cdp_activos"])
        self.assertIn(9229, res["puertos_cdp_activos"])
        self.assertIn(res["nivel_general"], ("Alto", "Crítico"))


class TestBrowserHardening(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="cg_test_hardening_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_windows_reg_script(self):
        reg_text = generate_windows_reg_script()
        self.assertIn("Windows Registry Editor Version 5.00", reg_text)
        self.assertIn("SOFTWARE\\Policies\\Google\\Chrome", reg_text)
        self.assertIn("SOFTWARE\\Policies\\Microsoft\\Edge", reg_text)
        self.assertIn('"RemoteDebuggingAllowed"=dword:00000000', reg_text)
        self.assertIn('"SitePerProcess"=dword:00000001', reg_text)

    def test_linux_policy_json(self):
        json_str = generate_linux_policy_json()
        data = json.loads(json_str)
        self.assertFalse(data["RemoteDebuggingAllowed"])
        self.assertTrue(data["SitePerProcess"])
        self.assertTrue(data["CommandLineFlagSecurityWarningsEnabled"])

    def test_firefox_policy_json(self):
        json_str = generate_firefox_policy_json()
        data = json.loads(json_str)
        self.assertIn("policies", data)
        self.assertTrue(data["policies"]["DisablePasswordReveal"])

    def test_generate_bundle(self):
        bundle = generate_hardening_bundle(output_dir=self.temp_dir)
        self.assertEqual(bundle["total_archivos"], 4)
        for f in bundle["archivos_generados"]:
            self.assertTrue(os.path.exists(f))
            self.assertGreater(os.path.getsize(f), 0)

    def test_audit_system_policies(self):
        mock_data = {
            "politicas_activas": True,
            "hallazgos": ["[OK] Clave de registro configurada"],
            "recomendaciones": []
        }
        res = audit_system_policies(test_data=mock_data)
        self.assertTrue(res["politicas_activas"])
        self.assertEqual(len(res["hallazgos"]), 1)


class TestSensorHealthDiagnostic(unittest.TestCase):
    def test_run_diagnostic_structure(self):
        res = run_sensor_diagnostic()
        self.assertIn("puntuacion_salud", res)
        self.assertIn("estado_general", res)
        self.assertIn("sensores", res)
        self.assertTrue(0 <= res["puntuacion_salud"] <= 100)
        self.assertIn(res["estado_general"], ("OPERATIVO", "ADVERTENCIA", "DEGRADADO"))
        self.assertGreater(len(res["sensores"]), 4)

    def test_format_cli_output(self):
        mock_res = {
            "puntuacion_salud": 95,
            "estado_general": "OPERATIVO",
            "color_resumen": "Verde",
            "sistema_operativo": "linux",
            "sensores": [
                {
                    "categoria": "Alertas",
                    "nombre": "Subsistema de Notificaciones",
                    "estado": "OK",
                    "detalle": "notify-send",
                    "nota": "Alertas visuales operativas."
                }
            ],
            "resumen": "Salud 95/100: Todo en orden."
        }
        text = format_sensor_diagnostic_cli(mock_res)
        self.assertIn("COOKIEGUARD DOCTOR", text)
        self.assertIn("OPERATIVO", text)
        self.assertIn("95/100", text)
        self.assertIn("Subsistema de Notificaciones", text)


class TestV230CLIIntegration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="cg_test_cli_v23_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_cli_doctor(self):
        code = cg_main.main(["doctor", "--json"])
        self.assertEqual(code, 0)

    def test_cli_remote_debug(self):
        code = cg_main.main(["remote-debug", "--json"])
        self.assertEqual(code, 0)

    def test_cli_politicas_generation(self):
        target = os.path.join(self.temp_dir, "policies_out")
        code = cg_main.main(["politicas", "--salida", target, "--json"])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(target))
        self.assertTrue(os.path.exists(os.path.join(target, "chrome_policies_managed.json")))

    def test_cli_politicas_audit(self):
        code = cg_main.main(["politicas", "--audit", "--json"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
