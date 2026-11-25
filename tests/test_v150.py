"""Tests unitarios para las novedades de CookieGuard v1.5.0:
- Perfil Honeypot / Trampa contra Infostealers (I18)
- Auditoría de Memoria y DLLs Inyectadas en Navegadores (I19)
- Captura de Evidencias Volátiles (Live Forensics Snapshot ZIP)
- Dossier de Incidente formal alineado con MITRE ATT&CK (HTML / Markdown)
- Generador de scripts de revocación por lotes de sesiones
- Integración en Triaje Forense USB
"""
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

from helpers import ROOT, TmpHome
from cookieguard import forensics, honeypot, incident_report, invalidation, memory_audit, triage
from cookieguard.browsers import Profile
from cookieguard.common import VERSION, data_dir, load_config
from cookieguard.detections import INDICATORS, Ctx, i18, i19


class TestV150(TmpHome):
    def test_version_1_5_0(self):
        self.assertIn(VERSION, ["1.5.0", "1.6.0", "1.7.0", "1.8.0", "1.9.0", "2.0.0", "2.1.0", "2.2.0", "2.3.0", "2.4.0", "2.4.1", "2.5.0", "2.5.1", "2.6.0", "2.6.1", "2.7.0", "2.7.1", "2.7.2", "2.7.3"])

    def test_indicadores_i18_e_i19_registrados(self):
        ind_names = [fn.__name__ for fn in INDICATORS]
        self.assertIn("i18", ind_names)
        self.assertIn("i19", ind_names)
        self.assertEqual(len(INDICATORS), 19)

    def test_honeypot_ciclo_completo(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            p1 = Profile(browser="Chrome", family="chromium", profile="Profile 1", path=tmp_p / "p1" / "Default", cookies_db=tmp_p / "p1" / "Default" / "Network" / "Cookies", root=tmp_p / "p1")
            p1.cookies_db.parent.mkdir(parents=True, exist_ok=True)
            p1.cookies_db.touch()

            # 1. Setup
            setup_res = honeypot.setup_honeypot([p1])
            self.assertEqual(setup_res["perfiles_creados"], 1)
            self.assertTrue(Path(setup_res["ficheros"][0]).exists())

            # 2. Check (debe estar activo y sin disparar)
            chk1 = honeypot.check_honeypot()
            self.assertTrue(chk1["activo"])
            self.assertFalse(chk1["disparado"])

            # 3. Simular alteración/lectura escribiendo en la base
            with open(setup_res["ficheros"][0], "ab") as f:
                f.write(b"modificacion_test")

            chk2 = honeypot.check_honeypot()
            self.assertTrue(chk2["disparado"])
            self.assertGreater(len(chk2["alertas"]), 0)

            # 4. Cleanup preserves a modified honeypot rather than deleting evidence/user data.
            rem = honeypot.remove_honeypot([p1])
            self.assertEqual(rem["eliminados"], 0)
            self.assertTrue(Path(setup_res["ficheros"][0]).exists())
            self.assertTrue(honeypot.check_honeypot()["activo"])

    def test_memory_audit_interfaz(self):
        procs = [{"pid": 99999, "name": "chrome.exe", "cmd": "chrome.exe", "exe": "/usr/bin/chrome"}]
        res = memory_audit.audit_browser_memory(procs)
        self.assertIn("limpio", res)
        self.assertIn("total_anomalias", res)
        self.assertIn("anomalias", res)

    def test_forensics_volatile_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_zip = forensics.capture_volatile_snapshot(reason="test_unitario", output_dir=Path(tmp))
            self.assertTrue(Path(out_zip).exists())
            self.assertTrue(zipfile.is_zipfile(out_zip))

            with zipfile.ZipFile(out_zip, "r") as zf:
                nombres = zf.namelist()
                self.assertIn("manifest.json", nombres)
                self.assertIn("entorno_sistema.json", nombres)
                self.assertIn("procesos.json", nombres)
                self.assertIn("conexiones_red.json", nombres)

    def test_incident_dossier_mitre_html_y_md(self):
        dummy_res = {
            "veredicto": {"nombre": "rojo", "puntos": 85, "texto": "Peligro Crítico", "aviso": "Rotar credenciales"},
            "estadisticas": {"cookies_sesion": 12, "perfiles": 2},
            "duracion_s": 1.2,
            "grupos": [
                {
                    "nombre": "Google",
                    "criticidad": "critica",
                    "cuentas": [{"cuenta": "admin@example.com"}],
                    "cookies": [{"nombre": "SID", "perfil": "Default", "navegador": "Chrome"}]
                }
            ],
            "indicadores": [
                {
                    "id": "I15_procesos_infostealer",
                    "nombre": "Procesos Infostealer en Memoria",
                    "mitre": "T1055 / T1555",
                    "estado": "alerta",
                    "puntos": 45,
                    "resumen": "Proceso malicioso detectado",
                    "hallazgos": ["PID 1234 (stealc.exe): coincide con IoC conocido"]
                }
            ],
            "errores": []
        }

        with tempfile.TemporaryDirectory() as tmp:
            html_p = Path(tmp) / "dossier.html"
            md_p = Path(tmp) / "dossier.md"

            out_html = incident_report.generate_incident_dossier(dummy_res, output_path=html_p, formato="html")
            self.assertTrue(Path(out_html).exists())
            html_content = html_p.read_text(encoding="utf-8")
            self.assertIn("MITRE ATT&CK", html_content)
            self.assertIn("I15_procesos_infostealer", html_content)
            self.assertIn("Google", html_content)

            out_md = incident_report.generate_incident_dossier(dummy_res, output_path=md_p, formato="md")
            self.assertTrue(Path(out_md).exists())
            md_content = md_p.read_text(encoding="utf-8")
            self.assertIn("# CookieGuard - Dossier Forense de Incidente", md_content)
            self.assertIn("MITRE ATT&CK", md_content)

    def test_invalidation_targets_and_batch_script(self):
        grupos = [
            {"nombre": "Google", "criticidad": "critica", "cuentas": []},
            {"nombre": "GitHub", "criticidad": "alta", "cuentas": []},
            {"nombre": "ServicioDesconocido", "criticidad": "media", "cuentas": []}
        ]
        targets = invalidation.get_revocation_targets(grupos)
        self.assertGreaterEqual(len(targets), 2)
        nombres = [t["servicio"] for t in targets]
        self.assertIn("Google", nombres)
        self.assertIn("GitHub", nombres)

        with tempfile.TemporaryDirectory() as tmp:
            script_path = invalidation.generate_batch_revocation_script(grupos, output_dir=Path(tmp))
            self.assertTrue(Path(script_path).exists())
            content = Path(script_path).read_text(encoding="utf-8")
            self.assertIn("Google", content)
            self.assertIn("GitHub", content)

    def test_indicadores_i18_e_i19_ctx(self):
        c = Ctx(cfg=load_config(), profiles=[], sessions=[], state={})
        res18 = i18(c)
        self.assertEqual(res18["id"], "I18_perfil_trampa")
        self.assertIn(res18["estado"], {"ok", "alerta", "sin_datos"})

        res19 = i19(c)
        self.assertEqual(res19["id"], "I19_inyeccion_memoria")
        self.assertIn(res19["estado"], {"ok", "alerta"})
