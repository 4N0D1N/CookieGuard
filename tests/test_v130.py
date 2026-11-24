"""Tests para las novedades de CookieGuard v1.3.0."""
import os
import unittest
from pathlib import Path

from helpers import ROOT, TmpHome
from cookieguard.common import VERSION, load_config
from cookieguard.detections import INDICATORS
from cookieguard.process_hunter import scan_processes


class TestV130(TmpHome):
    def test_version_1_3_0(self):
        self.assertIn(VERSION, ["1.3.0", "1.4.0", "1.5.0", "1.6.0", "1.7.0", "1.8.0", "1.9.0", "2.0.0", "2.1.0", "2.2.0", "2.3.0"])

    def test_indicador_i15_registrado(self):
        ind_names = [fn.__name__ for fn in INDICATORS]
        self.assertIn("i15", ind_names)
        self.assertGreaterEqual(len(INDICATORS), 15)

    def test_config_puntos_i15(self):
        cfg = load_config()
        self.assertIn("I15_procesos_infostealer", cfg.get("puntos", {}))
        self.assertGreaterEqual(cfg["puntos"]["I15_procesos_infostealer"], 40)

    def test_scripts_rescate_existen(self):
        win_cmd = ROOT / "Rescate-USB.cmd"
        linux_sh = ROOT / "rescate-usb.sh"
        self.assertTrue(win_cmd.exists(), "Falta Rescate-USB.cmd")
        self.assertTrue(linux_sh.exists(), "Falta rescate-usb.sh")
        if os.name != "nt":
            self.assertTrue(os.access(linux_sh, os.X_OK), "rescate-usb.sh debe ser ejecutable")

    def test_herramienta_compilar_existe(self):
        comp = ROOT / "tools" / "compilar.py"
        self.assertTrue(comp.exists(), "Falta tools/compilar.py")


if __name__ == "__main__":
    unittest.main()
