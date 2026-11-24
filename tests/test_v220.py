from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from cookieguard.unpacked_extension_audit import (
    audit_profile_unpacked_extensions,
    audit_running_browser_flags,
)
from cookieguard.guardian import GuardianMonitor
from cookieguard.forensic_custody import generate_forensic_custody_package
from cookieguard.revocation_scripts import generate_revocation_scripts


class TestUnpackedExtensionAudit(unittest.TestCase):
    def test_detects_unpacked_extension_and_dev_mode(self):
        with tempfile.TemporaryDirectory() as td:
            profile = Path(td)
            prefs = {
                "extensions": {
                    "ui": {"developer_mode": True},
                    "settings": {
                        "abc123": {
                            "location": 4,
                            "path": str(profile / "Downloads" / "malext"),
                            "manifest": {"name": "Test", "permissions": ["cookies", "<all_urls>"]},
                        }
                    },
                }
            }
            (profile / "Preferences").write_text(json.dumps(prefs), encoding="utf-8")
            findings = audit_profile_unpacked_extensions(profile)
            self.assertEqual(2, len(findings))
            unpacked = next(x for x in findings if x["tipo"] == "extension_desempaquetada")
            self.assertEqual("Crítica", unpacked["nivel"])
            self.assertTrue(unpacked["ubicacion_sospechosa"])

    def test_detects_suspicious_browser_flags_on_both_platforms(self):
        proc = [{"name": "chrome.exe", "pid": 12, "cmd": "chrome.exe --load-extension=C:\\temp\\ext"}]
        findings = audit_running_browser_flags(processes=proc)
        self.assertEqual(1, len(findings))
        self.assertEqual("--load-extension", findings[0]["flag"])


class TestGuardian(unittest.TestCase):
    def test_check_once_without_findings(self):
        with tempfile.TemporaryDirectory() as td:
            with patch("cookieguard.guardian.data_dir", return_value=Path(td)), \
                 patch("cookieguard.guardian.scan_processes", return_value={"sospechosos": []}), \
                 patch("cookieguard.guardian.audit_running_browser_flags", return_value=[]), \
                 patch("cookieguard.guardian.audit_clipboard", return_value={"has_alerts": False}), \
                 patch("cookieguard.guardian.notify"):
                guardian = GuardianMonitor(enable_clipboard_check=True)
                self.assertEqual([], guardian.check_once())
                self.assertEqual(1, guardian.stats["rondas_ejecutadas"])
                self.assertTrue((Path(td) / "guardian_status.json").exists())


class TestForensicCustody(unittest.TestCase):
    def test_creates_zip_and_manifest_without_cookie_values(self):
        with tempfile.TemporaryDirectory() as td:
            with patch("cookieguard.forensic_custody.discover", return_value=[]), \
                 patch("cookieguard.forensic_custody.audit_all_persistence", return_value={"total_findings": 0}):
                result = generate_forensic_custody_package(
                    output_dir=Path(td), analyst_name="<script>test</script>", incident_id="TEST-1"
                )
            zip_path = Path(result["archivo_zip"])
            self.assertTrue(zip_path.is_file())
            self.assertTrue(result["sha256_zip"])
            with zipfile.ZipFile(zip_path) as archive:
                manifest = json.loads(archive.read("cadena_de_custodia.json"))
            self.assertEqual("TEST-1", manifest["expediente_id"])
            self.assertIn("no es un informe pericial oficial", " ".join(manifest["limitaciones"]))
            self.assertTrue(all(item["sha256"] is None for item in manifest["artefactos_metadatos"]))
            html = Path(result["informe_html_path"]).read_text(encoding="utf-8")
            self.assertIn("&lt;script&gt;", html)


class TestRevocationScripts(unittest.TestCase):
    def test_generates_non_destructive_scripts(self):
        with tempfile.TemporaryDirectory() as td:
            result = generate_revocation_scripts(Path(td))
            ps1 = Path(result["windows_ps1"]).read_text(encoding="utf-8")
            bash = Path(result["linux_sh"]).read_text(encoding="utf-8")
            self.assertIn("[switch]$DryRun", ps1)
            self.assertIn("--dry-run", bash)
            self.assertNotIn("Stop-Process", ps1)
            self.assertNotIn("pkill", bash)
            self.assertIn("github.com/settings/sessions", ps1)
            self.assertIn("github.com/settings/sessions", bash)


if __name__ == "__main__":
    unittest.main()
