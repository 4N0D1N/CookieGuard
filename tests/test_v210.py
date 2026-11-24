"""Pruebas unitarias para las novedades de CookieGuard v2.1.0:
- Modo Simulacro de Incidente (drill / simulacro)
- Generador de Informe Ejecutivo Forense (report / dossier)
- Detector Heurístico de Clipper y Auditor de Portapapeles (clipboard / clipper)
"""
from __future__ import annotations

import unittest
from pathlib import Path
import tempfile
import shutil

from cookieguard.clipboard_audit import audit_clipboard, clear_system_clipboard
from cookieguard.simulator import run_incident_drill
from cookieguard.incident_report import generate_incident_dossier


class TestCookieGuardV210(unittest.TestCase):

    def test_clipboard_audit_clean_text(self):
        """Auditoría de portapapeles con texto inocuo debe devolver 0 alertas."""
        res = audit_clipboard(sample_text="Hola mundo, esto es una prueba normal de texto.")
        self.assertTrue(res["accesible"])
        self.assertFalse(res["has_alerts"])
        self.assertFalse(res["has_critical"])
        self.assertEqual(res["total_alertas"], 0)

    def test_clipboard_audit_jwt_token(self):
        """Auditoría de portapapeles con token JWT debe disparar alerta CRITICA."""
        sample_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        res = audit_clipboard(sample_text=f"Bearer {sample_jwt}")
        self.assertTrue(res["has_alerts"])
        self.assertTrue(res["has_critical"])
        tipos = [a["tipo"] for a in res["alertas"]]
        self.assertIn("JWT_TOKEN", tipos)

    def test_clipboard_audit_crypto_address(self):
        """Auditoría de portapapeles con dirección Bitcoin y Ethereum debe marcar objetivo Clipper."""
        btc = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
        eth = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
        res = audit_clipboard(sample_text=f"Enviar fondos a {btc} o {eth}")
        self.assertTrue(res["has_alerts"])
        self.assertEqual(len(res["cripto_detectadas"]), 2)

    def test_clear_system_clipboard(self):
        """La función de purga de portapapeles no debe lanzar excepciones."""
        # En entornos headless Linux puede devolver False si no hay display/xclip, pero no debe fallar
        res = clear_system_clipboard()
        self.assertIsInstance(res, bool)

    def test_run_incident_drill(self):
        """El simulacro de incidente debe completarse en sandbox y reportar semáforo ROJO."""
        res = run_incident_drill(interactive=False)
        self.assertEqual(res["estado_semaforo"], "ROJO")
        self.assertTrue(res["listo_para_contencion"])
        self.assertIn("LummaC2 / RedLine (Simulacro)", res["familia_stealer_simulada"])
        self.assertGreater(len(res["pasos_completados"]), 3)

    def test_generate_incident_dossier(self):
        """La generación de dossier forense debe producir archivos HTML y Markdown válidos."""
        mock_analysis = {
            "veredicto": {"nombre": "rojo", "puntos": 85, "aviso": "Peligro de infostealer"},
            "estadisticas": {"cookies_sesion": 12, "perfiles": 2},
            "indicadores": [
                {"id": "I06_copias_bd", "nombre": "Copia de BD", "estado": "alerta", "resumen": "BD copiada", "hallazgos": ["/tmp/cookies.sqlite"]}
            ],
            "errores": [],
            "grupos": []
        }
        temp_dir = Path(tempfile.mkdtemp(prefix="cg_test_rep_"))
        try:
            html_p = generate_incident_dossier(mock_analysis, output_path=temp_dir / "report.html", formato="html")
            self.assertTrue(Path(html_p).exists())
            self.assertIn("CookieGuard", Path(html_p).read_text(encoding="utf-8"))

            md_p = generate_incident_dossier(mock_analysis, output_path=temp_dir / "report.md", formato="md")
            self.assertTrue(Path(md_p).exists())
            self.assertIn("MITRE ATT&CK", Path(md_p).read_text(encoding="utf-8"))
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
