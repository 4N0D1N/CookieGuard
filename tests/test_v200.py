# -*- coding: utf-8 -*-
"""Pruebas unitarias para las mejoras de CookieGuard v2.0.0:
- Modo Dummy (Resumen Semáforo y 3 pasos prioritarios)
- Auditoría Heurística de Persistencia y Tareas Programadas
- Verificación de Integridad y Firmas de Binarios de Navegador
- Auditoría de Red Local (Archivo hosts y DNS)
"""

import sys
import tempfile
from pathlib import Path
import pytest

from cookieguard import dummy_summary, persistence_audit, binary_integrity, network_audit


def test_dummy_summary_traffic_lights():
    """Verifica que el semáforo calcule correctamente VERDE, AMARILLO y ROJO."""
    # Caso 1: Verde (sin alertas)
    s_verde = dummy_summary.compute_traffic_light(
        has_critical_detections=False,
        active_critical_sessions=0,
        has_persistence_alerts=False,
        has_hosts_hijack=False
    )
    assert s_verde["color"] == "VERDE"
    assert len(s_verde["acciones"]) == 3

    # Caso 2: Amarillo (sesiones críticas abiertas)
    s_amarillo = dummy_summary.compute_traffic_light(
        has_critical_detections=False,
        active_critical_sessions=3,
        has_persistence_alerts=False
    )
    assert s_amarillo["color"] == "AMARILLO"
    assert len(s_amarillo["acciones"]) == 3

    # Caso 3: Rojo (detección crítica o persistencia)
    s_rojo = dummy_summary.compute_traffic_light(
        has_critical_detections=True,
        active_critical_sessions=1,
        has_persistence_alerts=True
    )
    assert s_rojo["color"] == "ROJO"
    assert len(s_rojo["acciones"]) == 3


def test_dummy_summary_formats(tmp_path):
    """Verifica la generación de texto CLI y documento HTML."""
    s = dummy_summary.compute_traffic_light(has_critical_detections=False)
    cli_txt = dummy_summary.format_dummy_summary_cli(s)
    assert "COOKIEGUARD - RESUMEN DE SEGURIDAD" in cli_txt
    assert "3 PASOS PRIORITARIOS" in cli_txt

    html_file = tmp_path / "dummy_report.html"
    html_out = dummy_summary.generate_dummy_summary_html(s, str(html_file))
    assert html_file.is_file()
    assert "<!DOCTYPE html>" in html_out
    assert "Semáforo para Dummies" in html_out


def test_persistence_command_heuristics():
    """Verifica la detección de comandos sospechosos en persistencia."""
    safe_cmd = "/usr/bin/python3 -m app.server"
    assert len(persistence_audit.analyze_command_heuristics(safe_cmd)) == 0

    susp_powershell = "powershell.exe -w hidden -enc aW52b2tl"
    alerts_ps = persistence_audit.analyze_command_heuristics(susp_powershell)
    assert len(alerts_ps) > 0
    assert any("PowerShell" in a["descripcion"] for a in alerts_ps)

    susp_temp = r"C:\Users\test\AppData\Local\Temp\update_payload.exe"
    alerts_temp = persistence_audit.analyze_command_heuristics(susp_temp)
    assert len(alerts_temp) > 0


def test_persistence_autostart_audit(tmp_path):
    """Verifica la auditoría de archivos autostart / .desktop."""
    autostart_dir = tmp_path / "autostart"
    autostart_dir.mkdir()

    # Archivo .desktop sospechoso
    bad_desktop = autostart_dir / "malicious.desktop"
    bad_desktop.write_text("[Desktop Entry]\nType=Application\nExec=/tmp/stealer_payload.sh\n", encoding="utf-8")

    findings = persistence_audit.audit_linux_autostart(str(autostart_dir))
    assert len(findings) == 1
    assert findings[0]["sospechoso"] is True
    assert len(findings[0]["alertas"]) > 0


def test_binary_integrity_verification():
    """Verifica la comprobación de binarios del sistema."""
    res = binary_integrity.audit_binary_integrity()
    assert isinstance(res, dict)
    assert "total_audited" in res
    assert "tampered_count" in res
    assert isinstance(res["results"], list)


def test_network_hosts_parsing_and_sinkhole_detection(tmp_path):
    """Verifica que se detecte sinkholing de antivirus y spoofing de autenticación."""
    mock_hosts = tmp_path / "mock_hosts"
    mock_hosts.write_text(
        "127.0.0.1 localhost\n"
        "127.0.0.1 virustotal.com # Bloqueo antivirus malicioso\n"
        "0.0.0.0 kaspersky.com\n"
        "192.168.1.200 accounts.google.com # Phishing local\n",
        encoding="utf-8"
    )

    entries = network_audit.parse_hosts_file(mock_hosts)
    assert len(entries) >= 4

    anomalies = network_audit.audit_hosts_entries(entries)
    assert len(anomalies) >= 3

    tipos = [a["tipo"] for a in anomalies]
    assert "security_sinkhole" in tipos
    assert "auth_spoofing" in tipos

    report = network_audit.run_network_audit(custom_hosts_path=mock_hosts)
    assert report["has_anomalies"] is True
    assert report["has_critical"] is True
