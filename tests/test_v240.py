"""
Pruebas unitarias para las novedades de CookieGuard v2.4.0:
- Asistente de Rescate Cero-Confianza (rescue_wizard)
- Auditoría de Descargas Recientes Sospechosas (downloads_audit)
- Trampa Activa en Tiempo Real con Archivo Cebo (canary_trap)
- Comandos CLI y compatibilidad multiplataforma
"""

import json
import sqlite3
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from cookieguard import canary_trap, downloads_audit, rescue_wizard
from cookieguard.__main__ import main


class TestRescueWizard:
    def test_run_rescue_plan(self, tmp_path):
        res = rescue_wizard.run_rescue_plan(auto=True, killswitch=False, kill_browsers=False, output_dir=tmp_path)
        assert res["fase_actual"] == "Completada"
        assert len(res["rotacion_prioritaria"]) == 5
        assert "archivo_reporte_html" in res
        assert Path(res["archivo_reporte_html"]).exists()
        assert "archivo_reporte_json" in res
        assert Path(res["archivo_reporte_json"]).exists()

        # Verificar contenido HTML
        html_content = Path(res["archivo_reporte_html"]).read_text(encoding="utf-8")
        assert "Protocolo de Rescate" in html_content
        assert "Google (Gmail)" in html_content

    def test_terminate_running_browsers_dry_run(self):
        res = rescue_wizard.terminate_running_browsers(dry_run=True)
        assert len(res) > 0
        assert res[0]["status"] == "simulado"


class TestDownloadsAudit:
    def test_classify_risk(self):
        # 1. Doble extensión
        level, reasons = downloads_audit._classify_risk("factura.pdf.exe", "http://example.com")
        assert level == "CRÍTICO"
        assert any("Doble extensión" in r for r in reasons)

        # 2. Extensión de riesgo
        level, reasons = downloads_audit._classify_risk("setup.scr", "http://example.com")
        assert level == "ALTO"

        # 3. Archivo normal pero desde CDN discord
        level, reasons = downloads_audit._classify_risk("documento.zip", "https://cdn.discordapp.com/attachments/123/payload.zip")
        assert level == "CRÍTICO"

        # 4. Inocuo
        level, reasons = downloads_audit._classify_risk("foto.png", "https://example.com/foto.png")
        assert level == "BAJO"

    def test_audit_chromium_downloads(self, tmp_path):
        history_db = tmp_path / "History"
        conn = sqlite3.connect(str(history_db))
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE downloads (
                id INTEGER PRIMARY KEY,
                target_path TEXT,
                start_time INTEGER,
                total_bytes INTEGER,
                state INTEGER
            )
        """)
        cursor.execute("""
            CREATE TABLE downloads_url_chains (
                id INTEGER,
                chain_index INTEGER,
                url TEXT
            )
        """)

        # Insertar descarga sospechosa reciente
        now_unix = time.time()
        webkit_ts = int((now_unix + 11644473600.0) * 1_000_000.0)
        cursor.execute("INSERT INTO downloads VALUES (1, '/home/user/Downloads/crack_photoshop.exe', ?, 1048576, 1)", (webkit_ts,))
        cursor.execute("INSERT INTO downloads_url_chains VALUES (1, 0, 'https://cdn.discordapp.com/files/crack.exe')")
        conn.commit()
        conn.close()

        res = downloads_audit.audit_chromium_downloads(history_db, max_age_hours=24)
        assert len(res) == 1
        assert res[0]["archivo"] == "crack_photoshop.exe"
        assert res[0]["nivel_riesgo"] == "CRÍTICO"


class TestCanaryTrap:
    def test_deploy_and_check_traps(self, tmp_path, monkeypatch):
        # Aislar directorio de configuración
        cfg_dir = tmp_path / "cg_cfg"
        monkeypatch.setattr(canary_trap, "_get_app_config_dir", lambda: cfg_dir)

        target_profile = tmp_path / "browser_profile"
        target_profile.mkdir()

        # 1. Desplegar
        deployed = canary_trap.deploy_canary_traps(custom_paths=[target_profile])
        assert len(deployed) == 1
        trap_file = Path(deployed[0]["path"])
        assert trap_file.exists()

        # 2. Comprobar intacta
        check1 = canary_trap.check_canary_traps()
        assert not check1["alerta_activa"]
        assert check1["total_trampas"] == 1
        assert check1["intactas"] == 1

        # 3. Simular manipulación (modificar contenido)
        with open(trap_file, "a") as f:
            f.write("malware_tampering")

        check2 = canary_trap.check_canary_traps()
        assert check2["alerta_activa"]
        assert check2["activadas"] == 1

        # 4. Limpieza
        cleaned = canary_trap.cleanup_canary_traps()
        assert cleaned == 1
        assert not trap_file.exists()
        check3 = canary_trap.check_canary_traps()
        assert check3["total_trampas"] == 0


class TestCLIv240:
    def test_cli_rescue(self, tmp_path, capsys):
        code = main(["rescue", "--auto", "--salida", str(tmp_path)])
        assert code == 0
        captured = capsys.readouterr()
        assert "PROTOCOLO DE RESCATE" in captured.out
        assert "Fase 1" in captured.out

    def test_cli_descargas(self, capsys):
        code = main(["descargas", "--hours", "72"])
        assert code in (0, 1)
        captured = capsys.readouterr()
        assert "AUDITORÍA DE DESCARGAS RECIENTES" in captured.out

    def test_cli_trap(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(canary_trap, "_get_app_config_dir", lambda: tmp_path)
        code = main(["trap", "--check"])
        assert code in (0, 2)
        captured = capsys.readouterr()
        assert "ESTADO DE TRAMPAS CANARY" in captured.out
