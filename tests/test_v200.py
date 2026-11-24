"""
Pruebas de regresión y validación para las 4 mejoras de CookieGuard v2.0.0:
1. Resumen 'Modo Dummy' (Semáforo de estado y primeros pasos).
2. Auditoría heurística de persistencia (autostart, cron, scheduled tasks).
3. Verificación de integridad de binarios de navegadores.
4. Auditoría de archivo hosts y resolución DNS.
"""

import unittest
from pathlib import Path
import tempfile

from cookieguard.dummy_summary import (
    compute_traffic_light,
    format_dummy_summary_cli,
    generate_dummy_summary_html,
)
from cookieguard.persistence_audit import (
    audit_linux_autostart,
    analyze_command_heuristics,
    run_persistence_audit,
)
from cookieguard.binary_integrity import (
    audit_binary_integrity,
    verify_linux_binary_integrity,
)
from cookieguard.network_audit import (
    parse_hosts_file,
    audit_hosts_entries,
    run_network_audit,
)


class TestV200Mejoras(unittest.TestCase):

    def test_dummy_summary_green_clean(self):
        summary = compute_traffic_light(
            has_critical_detections=False,
            active_critical_sessions=0,
            has_persistence_alerts=False,
            has_hosts_hijack=False,
        )
        self.assertEqual(summary["color"], "VERDE")
        self.assertIn("TRANQUILIDAD", summary["titulo"])
        self.assertEqual(len(summary["acciones"]), 3)
        cli_out = format_dummy_summary_cli(summary)
        self.assertIn("COOKIEGUARD", cli_out)
        self.assertIn("VERDE", cli_out)

    def test_dummy_summary_yellow_warning(self):
        summary = compute_traffic_light(
            has_critical_detections=False,
            active_critical_sessions=3,
            has_persistence_alerts=False,
            has_hosts_hijack=False,
        )
        self.assertEqual(summary["color"], "AMARILLO")
        self.assertIn("ATENCIÓN", summary["titulo"])
        self.assertIn("3 sesión(es)", summary["explicacion"])

    def test_dummy_summary_red_when_critical(self):
        summary = compute_traffic_light(
            has_critical_detections=True,
            active_critical_sessions=1,
            has_persistence_alerts=False,
            has_hosts_hijack=False,
        )
        self.assertEqual(summary["color"], "ROJO")
        self.assertIn("PELIGRO", summary["titulo"])
        self.assertIn("Desconecta la red", summary["acciones"][0]["accion"])

    def test_dummy_summary_html_generation(self):
        summary = compute_traffic_light(
            has_critical_detections=False,
            active_critical_sessions=0,
            has_persistence_alerts=False,
            has_hosts_hijack=False,
        )
        html = generate_dummy_summary_html(summary)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("CookieGuard", html)
        self.assertIn("VERDE", html)

    def test_persistence_audit_linux_autostart_heuristic(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            autostart_dir = Path(tmpdir) / "autostart"
            autostart_dir.mkdir()
            entry = autostart_dir / "test_malware.desktop"
            entry.write_text("[Desktop Entry]\nExec=/tmp/suspicious_payload.sh\nName=FakeUpdater\n")

            entries = audit_linux_autostart(autostart_dir)
            self.assertEqual(len(entries), 1)
            self.assertTrue(entries[0]["sospechoso"])
            self.assertIn("directorios volátiles", entries[0]["alertas"][0]["descripcion"])

    def test_binary_integrity_shape(self):
        res = audit_binary_integrity()
        self.assertIsInstance(res, dict)
        self.assertIn("total_audited", res)
        self.assertIn("results", res)
        self.assertIn("has_tampered_risk", res)

    def test_hosts_file_hijack_detection(self):
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
            f.write("127.0.0.1 localhost\n")
            f.write("192.0.2.1 login.microsoftonline.com\n")
            f.flush()
            temp_hosts = Path(f.name)

        try:
            entries = parse_hosts_file(temp_hosts)
            alerts = audit_hosts_entries(entries)
            self.assertGreater(len(alerts), 0)
            self.assertEqual(alerts[0]["dominio"], "login.microsoftonline.com")
            self.assertIn("posible MITM", alerts[0]["detalle"])
        finally:
            if temp_hosts.exists():
                temp_hosts.unlink()


if __name__ == "__main__":
    unittest.main()
