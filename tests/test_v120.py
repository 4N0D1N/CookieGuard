"""Tests unitarios para CookieGuard v1.2.0: I14 DPAPI/MasterKey, Hardening, DBSC, Tray y Reglas Sigma."""
import json
from pathlib import Path
import unittest

from helpers import TmpHome

from cookieguard import hardening, dbsc, tray
from cookieguard.browsers import Profile
from cookieguard.common import VERSION
from cookieguard.detections import Ctx, i14


class TestV120(TmpHome):
    def test_version_1_2_0(self):
        self.assertIn(VERSION, ["1.2.0", "1.3.0"])

    def test_i14_localstate_clean(self):
        ctx = Ctx(cfg={"puntos": {"I14_dpapi_masterkey": 40}}, profiles=[], sessions=[], state={})
        res = i14(ctx)
        self.assertEqual(res["id"], "I14_dpapi_masterkey")
        self.assertIn(res["estado"], {"ok", "sin_datos"})

    def test_i14_suspicious_dpapi_process(self):
        ctx = Ctx(cfg={"puntos": {"I14_dpapi_masterkey": 40}}, profiles=[], sessions=[], state={})
        # Inyectar proceso sospechoso con nombre de herramienta de volcado DPAPI
        ctx._procs = [{"pid": 9999, "ppid": 1, "name": "sharpdpapi.exe", "cmd": "sharpdpapi.exe cookies", "exe": ""}]
        res = i14(ctx)
        self.assertEqual(res["estado"], "alerta")
        self.assertGreater(res["puntos"], 0)
        self.assertTrue(any("sharpdpapi" in h.lower() for h in res["hallazgos"]))

    def test_hardening_audit(self):
        pdir = self.tmp / "test_profile"
        pdir.mkdir(parents=True, exist_ok=True)
        pref_file = pdir / "Preferences"
        pref_file.write_text(json.dumps({
            "extensions": {"ui": {"developer_mode": True}},
            "safebrowsing": {"enabled": False}
        }))

        prof = Profile(browser="Chrome", family="chromium", profile="Default", path=pdir, cookies_db=None, root=pdir.parent)
        res = hardening.audit_profile_preferences(prof)
        self.assertEqual(res["estado"], "alerta")
        self.assertLess(res["puntuacion"], 100)
        self.assertTrue(any("desarrollador" in h.lower() for h in res["hallazgos"]))
        self.assertTrue(any("safebrowsing" in h.lower() for h in res["hallazgos"]))

        # Probar backup
        bfile = hardening.backup_preferences(prof)
        self.assertIsNotNone(bfile)
        self.assertTrue(bfile.is_file())

    def test_dbsc_readiness(self):
        r1 = self.tmp / "chrome_root"
        pdir1 = r1 / "Default"
        pdir1.mkdir(parents=True, exist_ok=True)
        (r1 / "Last Version").write_text("128.0.6613.119")
        prof_modern = Profile(browser="Google Chrome", family="chromium", profile="Default", path=pdir1, cookies_db=None, root=r1)

        r2 = self.tmp / "old_root"
        pdir2 = r2 / "Default"
        pdir2.mkdir(parents=True, exist_ok=True)
        (r2 / "Last Version").write_text("115.0.0.0")
        prof_old = Profile(browser="Chromium", family="chromium", profile="Default", path=pdir2, cookies_db=None, root=r2)

        sessions = [
            {"dominio": "accounts.google.com", "servicio": "Google", "criticidad": "critica"},
            {"dominio": "example.com", "servicio": "Example", "criticidad": "baja"}
        ]

        res = dbsc.evaluate_dbsc_readiness([prof_modern, prof_old], sessions)
        self.assertTrue(res["compatible"])
        self.assertEqual(res["total_sesiones_protegibles"], 1)
        self.assertEqual(res["sesiones_protegibles"][0]["dominio"], "accounts.google.com")

    def test_tray_fallback(self):
        # has_pystray devuelve booleano sin lanzar excepciones
        res = tray.has_pystray()
        self.assertIsInstance(res, bool)

    def test_sigma_rules_exist_and_valid(self):
        sigma_dir = Path(__file__).resolve().parent.parent / "reglas" / "sigma"
        self.assertTrue(sigma_dir.is_dir())
        rules = list(sigma_dir.glob("*.yml"))
        self.assertGreaterEqual(len(rules), 4)

        mandatory_fields = ["title", "id", "status", "description", "logsource", "detection", "level"]
        for r in rules:
            content = r.read_text(encoding="utf-8")
            for mf in mandatory_fields:
                self.assertIn(mf + ":", content, f"Campo {mf} ausente en regla Sigma {r.name}")


if __name__ == "__main__":
    unittest.main()
