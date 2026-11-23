"""Tests para las mejoras v1.1.0: Killswitch, Canary activo y Webhook seguro."""
import json
import unittest

from helpers import TmpHome

from cookieguard import actions, canary, killswitch, webhook
from cookieguard.common import VERSION


class TestNuevasMejoras(TmpHome):
    def test_version_1_1_0(self):
        self.assertIn(VERSION, ["1.1.0", "1.2.0", "1.3.0", "1.4.0", "1.5.0", "1.6.0", "1.7.0"])

    def test_killswitch_dry_run_y_status(self):
        st = killswitch.status()
        self.assertIn("activo", st)
        self.assertIn("metodo", st)

        ok_en, msg_en = killswitch.enable(dry_run=True)
        self.assertTrue(ok_en)
        self.assertIn("Simulacion", msg_en)

        ok_dis, msg_dis = killswitch.disable(dry_run=True)
        self.assertTrue(ok_dis)
        self.assertIn("Simulacion", msg_dis)

    def test_actions_killswitch_wrappers(self):
        st = actions.killswitch_status()
        self.assertIn("activo", st)
        ok, _ = actions.enable_killswitch(dry_run=True)
        self.assertTrue(ok)
        ok2, _ = actions.disable_killswitch(dry_run=True)
        self.assertTrue(ok2)

    def test_canary_helpers(self):
        self.assertTrue(canary.valid_url("https://canarytokens.org/feedback/123"))
        self.assertFalse(canary.valid_url("http://inseguro.org"))
        self.assertFalse(canary.valid_url("ftp://algo"))

        canaries = canary.list_planted_canaries()
        self.assertIsInstance(canaries, list)

        res = canary.verify_canaries([])
        self.assertIn("activos", res)
        self.assertIn("disparados", res)

    def test_webhook_sin_url(self):
        ok, msg = webhook.send_alert({"nivel": "CRITICO"}, webhook_url="")
        self.assertFalse(ok)
        self.assertIn("No hay webhook configurado", msg)

    def test_webhook_test_helper(self):
        # Con URL vacia debe fallar amigablemente sin excepciones
        ok, msg = webhook.test_webhook("")
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
