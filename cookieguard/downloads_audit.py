"""Auditoría local, de solo lectura, del historial de descargas Chromium."""
from __future__ import annotations

import base64
import json
import ntpath
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

# Extensiones que justifican revisar el contexto. La extensión sola no prueba malware.
_RISKY = {
    ".exe", ".dll", ".msi", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".hta", ".lnk", ".iso", ".img", ".jar", ".sh", ".appimage", ".deb", ".rpm",
}
_ARCHIVES = {".zip", ".7z", ".rar", ".tar", ".gz"}
_WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def webkit_time_to_iso(value: object) -> str | None:
    try:
        n = int(value)
        if n <= 0:
            return None
        return (_WEBKIT_EPOCH + timedelta(microseconds=n)).isoformat()
    except (TypeError, ValueError, OverflowError):
        return None


def _basename(value: str) -> str:
    return ntpath.basename(value.replace("/", "\\").rstrip("\\/"))


def _host(value: str) -> str | None:
    try:
        return urlsplit(value).hostname
    except ValueError:
        return None


def evaluate_download_risk(path: str, danger_type: object = None) -> tuple[str, list[str]]:
    ext = Path(_basename(path)).suffix.lower()
    reasons: list[str] = []
    if ext in _RISKY:
        reasons.append(f"Extensión ejecutable o activa: {ext}")
    elif ext in _ARCHIVES:
        reasons.append(f"Archivo comprimido: {ext}; revisar su contenido y origen")
    if str(danger_type or "0") not in ("0", "", "None"):
        reasons.append("El historial conserva un indicador de seguridad del navegador")
    level = "revisar" if reasons else "sin_indicio_por_extension"
    return level, reasons


def _history_path(profile) -> Path:
    return Path(profile.path) / "History"


def audit_chromium_history(profile, limit: int = 500) -> dict:
    db = _history_path(profile)
    result = {"navegador": profile.browser, "perfil": profile.profile,
              "analizadas": 0, "sospechosas": [], "error": None}
    if not db.is_file():
        result["error"] = "No se encontró el historial Chromium"
        return result
    try:
        uri = db.resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=2)
        conn.row_factory = sqlite3.Row
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(downloads)")}
            if not cols:
                result["error"] = "La tabla de descargas no está disponible"
                return result
            fields = [c for c in ("target_path", "current_path", "start_time", "end_time", "danger_type", "tab_url", "site_url", "total_bytes") if c in cols]
            rows = conn.execute(f"SELECT {', '.join(fields)} FROM downloads ORDER BY start_time DESC LIMIT ?", (max(1, min(int(limit), 5000)),)).fetchall()
            result["analizadas"] = len(rows)
            for row in rows:
                path = str(row["target_path"] or row["current_path"] or "")
                level, reasons = evaluate_download_risk(path, row["danger_type"] if "danger_type" in row.keys() else None)
                if not reasons:
                    continue
                source = str((row["tab_url"] if "tab_url" in row.keys() else "") or (row["site_url"] if "site_url" in row.keys() else "") or "")
                stamp = row["end_time"] if "end_time" in row.keys() and row["end_time"] else row["start_time"] if "start_time" in row.keys() else None
                result["sospechosas"].append({
                    "archivo": _basename(path) or "(sin nombre)",
                    "fecha": webkit_time_to_iso(stamp),
                    "dominio_origen": _host(source),
                    "bytes": row["total_bytes"] if "total_bytes" in row.keys() else None,
                    "nivel": level,
                    "motivos": reasons,
                })
        finally:
            conn.close()
    except (OSError, sqlite3.Error, ValueError) as exc:
        result["error"] = f"No se pudo leer el historial: {type(exc).__name__}"
    return result


def audit_all_downloads(profiles) -> dict:
    details = [audit_chromium_history(p) for p in profiles if getattr(p, "family", None) == "chromium"]
    findings = [item for profile in details for item in profile["sospechosas"]]
    findings.sort(key=lambda x: x.get("fecha") or "", reverse=True)
    return {
        "perfiles_analizados": sum(1 for d in details if d["error"] is None),
        "total_sospechosas": len(findings),
        "candidata_mas_reciente": findings[0] if findings else None,
        "detalles": details,
        "recomendacion": "Revisa manualmente origen, fecha y archivo; extensión y metadatos no confirman infección." if findings else "No se encontraron descargas con extensiones marcadas en los historiales disponibles.",
    }
