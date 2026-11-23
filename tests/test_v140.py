"""Tests unitarios para las novedades de CookieGuard v1.4.0:
- Auto-actualizador de IoCs maliciosos (Threat Intelligence)
- Indicador I16_ioc_malicioso
- Indicador I17_sesiones_escritorio
- Auditor detallado de extensiones
- Simulador seguro de escenarios de ataque (Test Harness)
- Gestor de servicio en segundo plano y autoarranque
- Emisor de eventos SIEM (CEF / JSON Lines)
"""
import json
import os
import unittest
from pathlib import Path

from helpers import ROOT, TmpHome
from cookieguard import desktop_sessions, extensions, ioc_updater, service, siem, simulator
from cookieguard.common import VERSION, data_dir, load_config
from cookieguard.detections import INDICATORS, Ctx, i16, i17


class TestV140(TmpHome):
    def test_version_1_4_0(self):
        self.assertIn(VERSION, ("1.4.0", "1.5.0", "1.6.0"))

    def test_indicadores_i16_e_i17_registrados(self):
        ind_names = [fn.__name__ for fn in INDICATORS]
        self.assertIn("i16", ind_names)
        self.assertIn("i17", ind_names)
        self.assertGreaterEqual(len(INDICATORS), 17)

    def test_catalogo_iocs_cargado(self):
        iocs = ioc_updater.get_active_iocs()
        self.assertIn("c2_dominios", iocs)
        self.assertIn("stealer_hashes_sha256", iocs)
        self.assertIn("stealer_nombres_ejecutables", iocs)
        self.assertGreater(len(iocs["stealer_hashes_sha256"]), 0)
        self.assertGreater(len(iocs["c2_dominios"]), 0)

    def test_ioc_matcher_hash_y_ejecutable(self):
        # Muestra de prueba de hash inocuo
        test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        hits = ioc_updater.match_process_against_iocs(nombre="stealc.exe", sha256=test_hash)
        self.assertGreaterEqual(len(hits), 2)
        tipos = [h["tipo"] for h in hits]
        self.assertIn("sha256_stealer", tipos)
        self.assertIn("nombre_stealer", tipos)

    def test_ioc_matcher_red_c2(self):
        hits_dom = ioc_updater.match_network_against_iocs(dominio="api.telegram.org")
        self.assertGreaterEqual(len(hits_dom), 1)
        self.assertEqual(hits_dom[0]["tipo"], "c2_dominio")

        hits_ip = ioc_updater.match_network_against_iocs(ip="194.87.68.50")
        self.assertGreaterEqual(len(hits_ip), 1)

    def test_desktop_sessions_auditor(self):
        res = desktop_sessions.audit_desktop_sessions()
        self.assertIn("apps_detectadas", res)
        self.assertIn("sesiones", res)
        self.assertIn("resumen_criticidad", res)

    def test_browser_extensions_auditor(self):
        res = extensions.audit_browser_extensions()
        self.assertIsInstance(res, list)

    def test_simulador_ataque_limpio(self):
        res = simulator.run_attack_simulation(interactive=False)
        self.assertTrue(res["completado"])
        self.assertTrue(res["todas_pasadas"])
        self.assertGreaterEqual(len(res["pruebas"]), 3)

    def test_service_status(self):
        st = service.status_service()
        self.assertIn("instalado", st)

    def test_siem_event_cef_and_jsonl(self):
        cef = siem.to_cef("I16_ioc_malicioso", "CRITICA", "Prueba Titulo", "Detalle de evento", {"pid": 1234})
        self.assertIn(f"CEF:0|CookieGuard|CookieGuard|{VERSION}|I16_ioc_malicioso", cef)
        self.assertIn("msg=Detalle de evento", cef)

        siem.emit_siem_event("I16_ioc_malicioso", "CRITICA", "Titulo Test", "Mensaje Test")
        jsonl_path = data_dir() / "logs" / "cookieguard_siem.jsonl"
        self.assertTrue(jsonl_path.exists())
        lines = jsonl_path.read_text(encoding="utf-8").strip().splitlines()
        self.assertGreaterEqual(len(lines), 1)
        ultimo = json.loads(lines[-1])
        self.assertEqual(ultimo["indicador"], "I16_ioc_malicioso")
        self.assertEqual(ultimo["severidad"], "CRITICA")

    def test_indicadores_i16_e_i17_ejecutan_en_ctx(self):
        c = Ctx(cfg=load_config(), profiles=[], sessions=[], state={})
        res16 = i16(c)
        self.assertEqual(res16["id"], "I16_ioc_malicioso")
        self.assertIn(res16["estado"], {"ok", "alerta"})

        res17 = i17(c)
        self.assertEqual(res17["id"], "I17_sesiones_escritorio")
        self.assertIn(res17["estado"], {"ok", "alerta"})
