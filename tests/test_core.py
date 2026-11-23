"""Tests: fechas, clasificacion, agrupacion, riesgo, configuracion, descubrimiento, borrado/restauracion."""
import hashlib
import unittest
from datetime import datetime, timedelta

from helpers import TmpHome, chrome_us, make_chromium, make_firefox  # noqa: E402

from cookieguard import actions, classifier, inventory, risk  # noqa: E402
from cookieguard.browsers import discover  # noqa: E402
from cookieguard.common import DEFAULT_CONFIG, load_config, save_user_config  # noqa: E402


class TestFechas(unittest.TestCase):
    def test_chrome_ida_y_vuelta(self):
        d = datetime(2026, 3, 1, 12, 30, 0)
        self.assertEqual(inventory.chrome_time(chrome_us(d)), d)

    def test_chrome_cero_y_basura(self):
        self.assertIsNone(inventory.chrome_time(0))
        self.assertIsNone(inventory.chrome_time(None))
        self.assertIsNone(inventory.chrome_time(2 ** 62))
        self.assertIsNone(inventory.chrome_time("x"))

    def test_firefox_unidades(self):
        d = datetime(2027, 1, 2, 3, 4, 5)
        self.assertEqual(inventory.firefox_expiry(int(d.timestamp())), d)            # segundos
        self.assertEqual(inventory.firefox_expiry(int(d.timestamp() * 1000)), d)     # milisegundos
        self.assertEqual(inventory.unix_time(int(d.timestamp() * 1e6), "us"), d)     # microsegundos
        self.assertIsNone(inventory.firefox_expiry(0))


class TestClasificador(unittest.TestCase):
    def rec(self, host, name, **k):
        return {"host": host, "name": name, "httponly": k.get("httponly", True), "secure": k.get("secure", True),
                "expires": k.get("expires"), "now": datetime.now()}

    def test_catalogo_alta(self):
        for host, name in ((".google.com", "SID"), (".google.com", "__Secure-3PSID"), ("login.microsoftonline.com", "ESTSAUTHPERSISTENT"),
                           (".facebook.com", "c_user"), (".x.com", "auth_token"), (".linkedin.com", "li_at"),
                           ("github.com", "user_session")):
            ok, conf, svc, _ = classifier.classify(self.rec(host, name))
            self.assertTrue(ok, name)
            self.assertEqual(conf, "Alta", name)
            self.assertIsNotNone(svc)

    def test_trackers_no_son_sesion(self):
        for n in ("_ga", "_gid", "_fbp", "__cf_bm", "NID", "OptanonConsent"):
            self.assertFalse(classifier.classify(self.rec(".example.com", n))[0], n)

    def test_heuristica(self):
        self.assertEqual(classifier.classify(self.rec("a.com", "session_token"))[1], "Media")
        self.assertEqual(classifier.classify(self.rec("a.com", "sessionid", httponly=False, secure=False))[1], "Baja")
        self.assertFalse(classifier.classify(self.rec("a.com", "theme"))[0])

    def test_dominio_registrable(self):
        self.assertEqual(classifier.registrable(".mail.google.com"), "google.com")
        self.assertEqual(classifier.registrable("a.b.example.co.uk"), "example.co.uk")


class TestInventario(TmpHome):
    def setUp(self):
        super().setUp()
        self.cr = self.tmp / "chromium_root"
        make_chromium(self.cr, self.sample_rows())
        self.ff = self.tmp / "ff_root"
        make_firefox(self.ff, [{"host": ".github.com", "name": "user_session", "expires": datetime.now() + timedelta(days=4)}])
        self.profiles = discover([self.cr], [self.ff], only_extra=True)

    def test_descubre_chromium_y_firefox(self):
        fam = sorted(p.family for p in self.profiles)
        self.assertEqual(fam, ["chromium", "firefox"])

    def test_lectura_y_agrupacion(self):
        sessions, stats, errors = inventory.collect(self.profiles)
        self.assertEqual(errors, [])
        names = {(s["host"], s["name"]) for s in sessions}
        self.assertNotIn((".example.com", "_ga"), names)       # tracker fuera
        self.assertIn((".google.com", "SID"), names)
        groups = {g["id"]: g for g in inventory.group_sessions(sessions)}
        self.assertEqual(groups["google"]["cookies"], 2)
        self.assertTrue(groups["google"]["zombie"])             # caduca a ~2,5 anos y sin uso >90 d
        self.assertFalse(groups["github"]["zombie"])
        self.assertEqual(groups["github"]["estado"], "Caduca pronto")
        self.assertEqual(sorted(groups["github"]["navegadores"]), ["Chromium (chromium_root)", "Firefox (prueba)"])
        self.assertTrue(groups["google"]["critico"])
        self.assertEqual(groups["bbva"]["estado"], "Solo hasta cerrar el navegador")
        self.assertEqual(groups["example.com"]["categoria"], "otros")

    def test_nuevas_respecto_a_linea_base(self):
        sessions, _, _ = inventory.collect(self.profiles)
        base = set(inventory.session_keys(sessions))
        base.discard(next(k for k in base if "user_session" in k and "Firefox" in k))
        groups = {g["id"]: g for g in inventory.group_sessions(sessions, baseline=base)}
        self.assertEqual(groups["github"]["nuevas"], 1)
        self.assertEqual(groups["google"]["nuevas"], 0)

    def test_originales_intactos(self):
        before = {p.cookies_db: hashlib.sha256(p.cookies_db.read_bytes()).hexdigest() for p in self.profiles}
        inventory.collect(self.profiles)
        after = {p.cookies_db: hashlib.sha256(p.cookies_db.read_bytes()).hexdigest() for p in self.profiles}
        self.assertEqual(before, after)

    def test_borrado_con_copia_y_restauracion(self):
        sessions, _, _ = inventory.collect(self.profiles)
        n0 = len(sessions)
        r = actions.delete_local(self.profiles, ["github.com"], force_closed_check=False)
        self.assertTrue(r["ok"])
        self.assertEqual(r["borradas"], 2)
        after, _, _ = inventory.collect(self.profiles)
        self.assertEqual(len(after), n0 - 2)
        self.assertTrue(actions.list_backups())
        rr = actions.restore_backup(r["copia"], check_browsers=False)
        self.assertTrue(rr["ok"])
        again, _, _ = inventory.collect(self.profiles)
        self.assertEqual(len(again), n0)

    def test_url_busqueda_para_dominio_desconocido(self):
        sessions, _, _ = inventory.collect(self.profiles)
        g = {x["id"]: x for x in inventory.group_sessions(sessions)}
        url, _, es_busqueda = actions.url_for(g["example.com"], "password")
        self.assertTrue(es_busqueda)
        self.assertTrue(url.startswith("https://"))
        url, _, es_busqueda = actions.url_for(g["github"], "sesiones")
        self.assertFalse(es_busqueda)
        self.assertIn("github.com", url)

    def test_rotacion_guarda_progreso(self):
        sessions, _, _ = inventory.collect(self.profiles)
        grupos = inventory.group_sessions(sessions)
        plan = actions.rotation_plan(grupos)
        self.assertEqual(actions.rotation_progress(plan)[0], 0)
        # orden por criticidad: sso (google) antes que redes u otros
        cats = [p["categoria"] for p in plan]
        self.assertLess(cats.index("sso"), cats.index("otros"))
        actions.mark_step("google", "sesiones")
        actions.mark_step("google", "password")
        plan = actions.rotation_plan(grupos)
        self.assertEqual(actions.rotation_progress(plan)[0], 2)
        self.assertTrue(next(p for p in plan if p["id"] == "google")["rotado"])


class TestRiesgoYConfig(TmpHome):
    def test_semaforo(self):
        cfg = load_config()
        mk = lambda p: [{"estado": "alerta", "puntos": p, "nombre": "x", "resumen": "r"}]  # noqa: E731
        self.assertEqual(risk.evaluate([], cfg)["nivel"], "verde")
        self.assertEqual(risk.evaluate(mk(cfg["umbrales"]["amarillo"]), cfg)["nivel"], "amarillo")
        self.assertEqual(risk.evaluate(mk(cfg["umbrales"]["rojo"]), cfg)["nivel"], "rojo")
        # sin_datos no suma
        self.assertEqual(risk.evaluate([{"estado": "sin_datos", "puntos": 99, "nombre": "x", "resumen": ""}], cfg)["nivel"], "verde")

    def test_config_defecto_y_usuario(self):
        cfg = load_config()
        self.assertEqual(cfg["umbrales"], DEFAULT_CONFIG["umbrales"])
        self.assertEqual(set(cfg["puntos"]) >= {"I01_acceso_ficheros", "I12_anomalias_cookies"}, True)
        save_user_config({"umbrales": {"rojo": 99}, "silencioso": True})
        cfg = load_config()
        self.assertEqual(cfg["umbrales"], {"amarillo": 15, "rojo": 99})
        self.assertTrue(cfg["silencioso"])


if __name__ == "__main__":
    unittest.main()
