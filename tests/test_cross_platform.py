"""
Pruebas de compatibilidad multiplataforma (Windows y Linux) para CookieGuard:
- Auditoría de persistencia (systemd user units en Linux, Registro Run en Windows simulado).
- Auditoría de red y DNS (netsh/PowerShell en Windows, resolv.conf en Linux).
- Fallbacks de portapapeles para Windows (ctypes + PowerShell).
- Hardening del sistema (LSA Protection en Windows, sysctl ptrace/protected_regular en Linux).
- Integridad de binarios (Authenticode en Windows simulado, ELF/rutas en Linux).
"""

from __future__ import annotations
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import tempfile
import sys

from cookieguard.persistence_audit import (
    audit_linux_systemd_user,
    audit_windows_registry_run,
    run_persistence_audit,
)
from cookieguard.network_audit import (
    audit_windows_dns,
    audit_linux_resolv_conf,
    run_network_audit,
)
from cookieguard.clipboard_audit import (
    _read_clipboard_windows,
    _clear_clipboard_windows,
    audit_clipboard,
)
from cookieguard.actions import hardening_checks
from cookieguard.binary_integrity import verify_windows_authenticode


class TestCrossPlatformCompatibility(unittest.TestCase):

    def test_linux_systemd_user_service_suspicious(self):
        """Verifica que un servicio systemd de usuario con payload en /tmp o -enc sea detectado."""
        with tempfile.TemporaryDirectory() as tmpdir:
            unit_dir = Path(tmpdir) / "systemd" / "user"
            unit_dir.mkdir(parents=True)
            unit_file = unit_dir / "stealer_updater.service"
            unit_file.write_text(
                "[Unit]\nDescription=Update Service\n[Service]\nExecStart=/tmp/updater.sh\nRestart=always\n",
                encoding="utf-8"
            )

            results = audit_linux_systemd_user(base_dir=unit_dir)
            self.assertEqual(len(results), 1)
            item = results[0]
            self.assertEqual(item["tipo"], "linux_systemd_user")
            self.assertTrue(item["sospechoso"])
            self.assertTrue(any("volátiles" in a["descripcion"] for a in item["alertas"]))

    def test_windows_registry_run_mock(self):
        """Simula winreg de Windows para auditoría de Run / RunOnce."""
        mock_winreg = MagicMock()
        mock_winreg.HKEY_CURRENT_USER = 1
        mock_winreg.HKEY_LOCAL_MACHINE = 2
        mock_winreg.KEY_READ = 131097

        mock_key = MagicMock()
        mock_winreg.OpenKey.return_value.__enter__.return_value = mock_key

        mock_winreg.EnumValue.side_effect = [
            ("FakeAgent", "powershell.exe -w hidden -enc JABhID0gMQ==", 1),
            OSError("No more data"),
            OSError("No more data"),
            OSError("No more data"),
            OSError("No more data"),
        ]

        with patch("sys.platform", "win32"):
            with patch.dict("sys.modules", {"winreg": mock_winreg}):
                entries = audit_windows_registry_run()
                suspicious = [e for e in entries if e.get("sospechoso")]
                self.assertGreater(len(suspicious), 0)
                self.assertIn("FakeAgent", suspicious[0]["nombre"])
                self.assertTrue(any("ocultos o codificados" in a["descripcion"] for a in suspicious[0]["alertas"]))

    @patch("subprocess.run")
    def test_windows_dns_netsh_mock(self, mock_subproc):
        """Simula la salida de 'netsh interface ipv4 show dnsservers' en Windows."""
        with patch("sys.platform", "win32"):
            netsh_out = (
                "Configuration for interface \"Wi-Fi\"\n"
                "    DNS servers configured through DHCP:  1.1.1.1\n"
                "                                          8.8.8.8\n"
            )
            mock_subproc.return_value = MagicMock(returncode=0, stdout=netsh_out, stderr="")
            dns_res = audit_windows_dns()
            self.assertEqual(dns_res["count"], 2)
            self.assertIn("1.1.1.1", dns_res["nameservers"])
            self.assertIn("8.8.8.8", dns_res["nameservers"])

    @patch("subprocess.run")
    def test_windows_clipboard_powershell_fallback(self, mock_subproc):
        """Simula el fallback de lectura y borrado de portapapeles en Windows mediante PowerShell."""
        mock_subproc.return_value = MagicMock(returncode=0, stdout="Texto Secreto Copiado\n", stderr="")
        with patch("sys.platform", "win32"):
            with patch("ctypes.windll", create=True) as mock_windll:
                mock_windll.user32.OpenClipboard.side_effect = Exception("OpenClipboard failed")
                text = _read_clipboard_windows()
                self.assertIn("Texto Secreto Copiado", text)

    @patch("subprocess.run")
    def test_windows_authenticode_powershell_mock(self, mock_subproc):
        """Simula la verificación de Authenticode en Windows mediante Get-AuthenticodeSignature."""
        mock_subproc.return_value = MagicMock(
            returncode=0,
            stdout="Valid\nCN=Google LLC, O=Google LLC, L=Mountain View, S=California, C=US\n",
            stderr=""
        )
        fake_binary = Path(tempfile.gettempdir()) / "fake_chrome.exe"
        fake_binary.touch()
        try:
            with patch("sys.platform", "win32"):
                res = verify_windows_authenticode(str(fake_binary))
                self.assertEqual(res["status"], "Valid")
                self.assertTrue(res["valid"])
                self.assertIn("Google LLC", res["subject"])
                self.assertFalse(res["tampered_risk"])
        finally:
            if fake_binary.exists():
                fake_binary.unlink()

    def test_hardening_checks_execution(self):
        """Verifica que hardening_checks se ejecute sin excepciones en cualquier SO y contenga claves pertinentes."""
        checks = hardening_checks([])
        self.assertIsInstance(checks, list)
        self.assertGreaterEqual(len(checks), 3)
        check_ids = [c["id"] for c in checks]
        if sys.platform.startswith("linux"):
            self.assertTrue(any(k in check_ids for k in ("clear_exit", "passkeys", "ptrace", "protected_regular")))
        elif sys.platform.startswith("win"):
            self.assertTrue(any("def_" in cid or "lsa_" in cid or "asr_" in cid for cid in check_ids))


if __name__ == "__main__":
    unittest.main()
