"""Tests de los indicadores con datos controlados (sin tocar el sistema real)."""
import json
import os
import sqlite3
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from helpers import TmpHome, make_chromium  # noqa: E402

from cookieguard import detections as D  # noqa: E402
from cookieguard.browsers import discover  # noqa: E402
from cookieguard.common import load_config  # noqa: E402

VALID_STATES = {"ok", "alerta", "sin_datos", "no_aplica", "error"}


def ctx(profiles=None, sessions=None, state=None, scan_dirs=None, procs=None):
    c = D.Ctx(load_config(), profiles or [], sessions or [], state or {}, scan_dirs)
    if procs is not None:
        c._procs = procs
    return c


class TestIndicadores(TmpHome):
    def test_i02_depuracion_remota(self):
        procs = [{"pid": 10, "ppid": 1, "name": "chrome.exe", "cmd": "chrome.exe --remote-debugging-port=9222 --user-data-dir=C:\\Temp\\x", "exe": ""},
                 {"pid": 11, "ppid": 1, "name": "explorer.exe", "cmd": "", "exe": ""}]
        r = D.i02(ctx(procs=procs))
        self.assertEqual(r["estado"], "alerta")
        self.assertGreaterEqual(r["puntos"], 30)

    def test_i02_navegador_normal_ok(self):
        procs = [{"pid": 10, "ppid": 1, "name": "chrome.exe", "cmd": "chrome.exe --type=renderer", "exe": ""}]
        r = D.i02(ctx(procs=procs))
        self.assertEqual(r["estado"], "ok")

    def test_i06_copia_de_bd(self):
        d = self.tmp / "temp"
        d.mkdir()
        con = sqlite3.connect(d / "Cookies_copy.db")
        con.execute("CREATE TABLE cookies (host_key TEXT, name TEXT)")
        con.executemany("INSERT INTO cookies VALUES (?,?)", [("a.com", "x")] * 400)
        con.commit()
        con.close()
        (d / "passwords.txt").write_text("falso")
        r = D.i06(ctx(scan_dirs=[d]))
        self.assertEqual(r["estado"], "alerta")
        self.assertTrue(any("Cookies_copy.db" in h for h in r["hallazgos"]))
        self.assertTrue(any("passwords.txt" in h for h in r["hallazgos"]))

    def test_i06_ignora_perfil_de_app_electron(self):
        d = self.tmp / "AppData" / "MiApp"
        (d / "Network").mkdir(parents=True)
        (d / "Local State").write_text("{}")
        con = sqlite3.connect(d / "Network" / "Cookies")
        con.execute("CREATE TABLE cookies (host_key TEXT)")
        con.executemany("INSERT INTO cookies VALUES (?)", [("a.com",)] * 500)
        con.commit()
        con.close()
        r = D.i06(ctx(scan_dirs=[self.tmp / "AppData"]))
        self.assertEqual(r["estado"], "ok")

    def test_i05_extension_peligrosa_nueva(self):
        root = self.tmp / "UD"
        make_chromium(root, self.sample_rows())
        ext = root / "Default" / "Extensions" / ("a" * 32) / "1.0_0"
        ext.mkdir(parents=True)
        (ext / "manifest.json").write_text(json.dumps({"name": "Falsa", "version": "1.0", "permissions": ["cookies", "webRequest"],
                                                       "host_permissions": ["<all_urls>"]}))
        (root / "Default" / "Preferences").write_text(json.dumps({"extensions": {"settings": {"a" * 32: {"location": 4}}}}))
        profiles = discover([root], only_extra=True)
        # primera ejecucion: crea la linea base; no es 'nueva' (pero modo dev + permisos peligrosos ya avisa)
        c1 = ctx(profiles)
        r1 = D.i05(c1)
        self.assertEqual(len(c1.new_state["baseline_extensiones"]), 1)
        self.assertFalse(c1.extensions[0]["nueva"])
        self.assertEqual(r1["estado"], "alerta")
        self.assertIn("modo desarrollador", r1["hallazgos"][0])
        # segunda: la extension no estaba en la base -> nueva + peligrosa + modo dev
        c2 = ctx(profiles, state={"baseline_extensiones": []})
        r = D.i05(c2)
        self.assertEqual(r["estado"], "alerta")
        self.assertIn("cookies", r["hallazgos"][0])
        self.assertTrue(c2.extensions[0]["modo_dev"])

    def test_i09_persistencia_nueva(self):
        orig = D._persistence_snapshot
        try:
            D._persistence_snapshot = lambda: {"run|HKCU|a|x.exe"}
            c = ctx(state={"baseline_persistencia": ["run|HKCU|a|x.exe"]})
            self.assertEqual(D.i09(c)["estado"], "ok")
            D._persistence_snapshot = lambda: {"run|HKCU|a|x.exe", "run|HKCU|CookieGuardSim|cmd /c C:\\Users\\x\\AppData\\evil.exe"}
            r = D.i09(ctx(state={"baseline_persistencia": ["run|HKCU|a|x.exe"]}))
            self.assertEqual(r["estado"], "alerta")
            self.assertEqual(D.i09(ctx(state={}))["estado"], "ok")     # primera vez: solo base
        finally:
            D._persistence_snapshot = orig

    def test_i12_rafaga_de_cookies_criticas(self):
        t = datetime.now().replace(hour=3, minute=0, second=0, microsecond=0) - timedelta(days=1)
        hosts = ["google.com", "github.com", "bbva.es", "facebook.com", "x.com", "linkedin.com", "dropbox.com"]
        sessions = [{"host": h, "created": t, "last_update": t} for h in hosts]
        r = D.i12(ctx(sessions=sessions))
        self.assertEqual(r["estado"], "alerta")
        self.assertIn("hora inusual", r["hallazgos"][0])

    def test_i10_ejecutable_reciente(self):
        d = self.tmp / "Downloads"
        d.mkdir()
        if os.name == "nt":
            (d / "instalador.exe").write_bytes(b"MZ" + b"\0" * 200)
        else:
            f = d / "instalador"
            f.write_bytes(b"\x7fELF" + b"\0" * 200)
            f.chmod(0o755)
        r = D.i10(ctx(scan_dirs=[d]))
        self.assertEqual(r["estado"], "alerta")

    def test_todos_los_indicadores_terminan_sin_excepcion(self):
        empty = self.tmp / "e"
        empty.mkdir()
        c = ctx(procs=[], scan_dirs=[empty])
        res = D.run_all(c)
        self.assertEqual(len(res), 15)
        for r in res:
            self.assertIn(r["estado"], VALID_STATES, r["id"])
            for k in ("nombre", "mitre", "explicacion", "resumen", "hallazgos", "puntos"):
                self.assertIn(k, r)
        self.assertEqual(len({r["id"] for r in res}), 15)




    def test_i15_procesos_infostealer(self):
        c = ctx(procs=[])
        r = D.i15(c)
        self.assertIn(r["estado"], ("ok", "sin_datos", "alerta"))

    def test_i13_canary_cookie(self):
        r = D.i13(ctx())
        self.assertIn(r["estado"], {"ok", "sin_datos", "alerta"})


    def test_i14_dpapi_masterkey(self):
        r = D.i14(ctx())
        self.assertIn(r["estado"], {"ok", "sin_datos", "alerta"})
        self.assertEqual(r["id"], "I14_dpapi_masterkey")

if __name__ == "__main__":
    unittest.main()
