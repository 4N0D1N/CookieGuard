"""Emisor de eventos estructurados para SIEM y monitorizacion (Syslog, JSON Lines, CEF).

Permite que CookieGuard envíe incidentes de seguridad y detecciones forenses a sistemas
SIEM corporativos o locales (Splunk, Elastic, Wazuh, Microsoft Sentinel, syslog-ng).

Garantias de privacidad y arquitectura CookieGuard:
- Cero modulos de red en Python: utiliza logging estructurado en disco (JSON Lines/CEF)
  y utilidades del sistema (logger en Linux o PowerShell en Windows) si se requiere Syslog.
- No procesa ni transmite valores de cookies.
"""
from __future__ import annotations

import json
import os
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .common import IS_WIN, VERSION, data_dir, log, ps, run

SEVERITY_MAP = {
    "CRITICA": 10,
    "ALTA": 8,
    "MEDIA": 5,
    "BAJA": 2,
    "INFO": 1
}


def to_cef(indicador: str, severidad: str, titulo: str, detalle: str, extra: dict[str, Any] | None = None) -> str:
    """Convierte un evento al formato estandar Common Event Format (CEF)."""
    sev_num = SEVERITY_MAP.get(severidad.upper(), 5)
    cef_header = f"CEF:0|CookieGuard|CookieGuard|{VERSION}|{indicador}|{titulo}|{sev_num}|"
    ext_fields = [f"msg={detalle}"]
    if extra:
        for k, v in extra.items():
            ext_fields.append(f"cs_{k}={str(v)[:150]}")
    return cef_header + " ".join(ext_fields)


def emit_siem_event(
    indicador: str,
    severidad: str,
    titulo: str,
    detalle: str,
    extra: dict[str, Any] | None = None,
    dest_syslog_host: str = ""
) -> None:
    """Registra y emite un evento en JSON Lines local y opcionalmente a Syslog del sistema."""
    ahora_utc = datetime.now(timezone.utc).isoformat()
    host = platform.node() or "equipo-local"
    record = {
        "timestamp": ahora_utc,
        "app": "CookieGuard",
        "version": VERSION,
        "indicador": indicador,
        "severidad": severidad,
        "severidad_num": SEVERITY_MAP.get(severidad.upper(), 5),
        "titulo": titulo,
        "detalle": detalle,
        "host": host,
        "extra": extra or {}
    }

    # 1. Guardar en archivo rotado jsonl local
    try:
        siem_log = data_dir() / "logs" / "cookieguard_siem.jsonl"
        with open(siem_log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as e:
        log(f"Error escribiendo en cookieguard_siem.jsonl: {e}")

    # 2. Emision a syslog via utilidades del SO si aplica
    if dest_syslog_host:
        cef_msg = to_cef(indicador, severidad, titulo, detalle, extra)
        if not IS_WIN:
            run(["logger", "-n", dest_syslog_host, "-t", "CookieGuard", cef_msg], timeout=5)
        else:
            ps(f"Write-EventLog -LogName Application -Source CookieGuard -EntryType Warning -EventId 1001 -Message '{cef_msg}'", timeout=5)
