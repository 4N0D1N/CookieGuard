"""
Módulo de Auditoría de Descargas Recientes Sospechosas para CookieGuard v2.4.0.
Inspecciona de forma pasiva el historial de descargas de Chromium y Firefox
en busca de vectores comunes de entrada de infostealers (falsos instaladores,
archivos ejecutables camuflados, scripts y fuentes no confiables).
100% offline, sin dependencias externas, compatible con Windows y Linux.
"""

from __future__ import annotations

import ntpath
import os
import shutil
import sqlite3
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cookieguard.browsers import discover

# Extensiones de alto riesgo asociadas a campañas de infostealers
_RISKY = {
    ".exe", ".dll", ".msi", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".hta", ".lnk", ".iso", ".img", ".jar", ".sh", ".appimage", ".deb", ".rpm",
    ".vbe", ".jse", ".wsf", ".wsh", ".cpl", ".msp", ".com", ".vhd", ".vhdx", ".pif"
}
HIGH_RISK_EXTENSIONS = _RISKY
_ARCHIVES = {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz"}
ARCHIVE_EXTENSIONS = _ARCHIVES
_WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

SUSPICIOUS_DOMAINS_PATTERNS = [
    "cdn.discordapp.com", "attachments.discord.net", "mediafire.com",
    "mega.nz", "anonfiles", "gofile.io", "catbox.moe", "transfer.sh",
    "file.io", "wetransfer.com", "temp.sh", "raw.githubusercontent.com"
]


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


def _webkit_time_to_unix(webkit_timestamp: int) -> float:
    """Convierte microsegundos WebKit (desde 1601-01-01) a Unix timestamp."""
    if not webkit_timestamp:
        return 0.0
    return (webkit_timestamp / 1_000_000.0) - 11644473600.0


def _firefox_time_to_unix(prtime: int) -> float:
    """Convierte microsegundos PRTime (desde 1970-01-01) a Unix timestamp."""
    if not prtime:
        return 0.0
    return prtime / 1_000_000.0


def _classify_risk(filename: str, url: str) -> tuple[str, list[str]]:
    """Evalúa el nivel de riesgo de una descarga y los motivos."""
    name_lower = filename.lower()
    url_lower = url.lower()
    reasons = []
    level = "BAJO"

    ext = Path(name_lower).suffix

    # 1. Doble extensión peligrosa (ej: factura.pdf.exe)
    parts = name_lower.split(".")
    if len(parts) > 2:
        penultimate = f".{parts[-2]}"
        if penultimate in {".pdf", ".docx", ".xlsx", ".png", ".jpg"} and ext in HIGH_RISK_EXTENSIONS:
            reasons.append(f"Doble extensión engañosa ({penultimate}{ext}) comúnmente usada para camuflar malware")
            level = "CRÍTICO"

    # 2. Extensión de alta peligrosidad directa
    if ext in HIGH_RISK_EXTENSIONS:
        reasons.append(f"Archivo ejecutable directo ({ext})")
        if level != "CRÍTICO":
            level = "ALTO"

    # 3. Archivo comprimido sospechoso
    elif ext in ARCHIVE_EXTENSIONS:
        reasons.append(f"Archivo comprimido ({ext}) susceptible de contener instaladores trampa")
        if level == "BAJO":
            level = "MEDIO"

    # 4. Fuente de descarga sospechosa
    for dom in SUSPICIOUS_DOMAINS_PATTERNS:
        if dom in url_lower:
            reasons.append(f"Descargado desde servicio de alojamiento/CDN efímero ({dom})")
            if level in ("MEDIO", "ALTO"):
                level = "CRÍTICO"
            elif level == "BAJO":
                level = "MEDIO"
            break

    return level, reasons


def audit_chromium_downloads(history_path: Path, max_age_hours: int = 48) -> list[dict[str, Any]]:
    """Inspecciona la tabla downloads en la base de datos History de Chromium."""
    if not history_path.exists():
        return []

    cutoff_unix = time.time() - (max_age_hours * 3600)
    cutoff_webkit = int((cutoff_unix + 11644473600.0) * 1_000_000.0)

    results = []
    temp_dir = tempfile.mkdtemp(prefix="cg_dl_")
    copy_path = Path(temp_dir) / "History_copy"

    try:
        shutil.copy2(history_path, copy_path)
        conn = sqlite3.connect(f"file:{copy_path}?mode=ro", uri=True)
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='downloads'")
        if not cursor.fetchone():
            conn.close()
            return []

        query = """
            SELECT d.target_path, d.start_time, d.total_bytes, d.state, u.url
            FROM downloads d
            LEFT JOIN downloads_url_chains u ON d.id = u.id AND u.chain_index = 0
            WHERE d.start_time >= ?
            ORDER BY d.start_time DESC
        """
        cursor.execute(query, (cutoff_webkit,))
        rows = cursor.fetchall()
        conn.close()

        for row in rows:
            target_path_str, start_time_raw, total_bytes, state, url = row
            target_path = Path(target_path_str or "desconocido")
            filename = target_path.name
            unix_ts = _webkit_time_to_unix(start_time_raw or 0)
            date_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(unix_ts)) if unix_ts > 0 else "N/A"
            url_str = url or ""

            risk_level, reasons = _classify_risk(filename, url_str)

            results.append({
                "browser_type": "Chromium",
                "archivo": filename,
                "ruta_destino": str(target_path),
                "bytes": total_bytes or 0,
                "fecha": date_str,
                "timestamp_unix": unix_ts,
                "url_origen": url_str,
                "nivel_riesgo": risk_level,
                "motivos": reasons
            })
    except Exception:
        pass
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return results


def audit_firefox_downloads(places_path: Path, max_age_hours: int = 48) -> list[dict[str, Any]]:
    """Inspecciona descargas registradas en places.sqlite de Firefox."""
    if not places_path.exists():
        return []

    cutoff_unix = time.time() - (max_age_hours * 3600)
    cutoff_prtime = int(cutoff_unix * 1_000_000.0)

    results = []
    temp_dir = tempfile.mkdtemp(prefix="cg_ff_dl_")
    copy_path = Path(temp_dir) / "places_copy"

    try:
        shutil.copy2(places_path, copy_path)
        conn = sqlite3.connect(f"file:{copy_path}?mode=ro", uri=True)
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='moz_annos'")
        if not cursor.fetchone():
            conn.close()
            return []

        query = """
            SELECT p.url, p.title, a.content, a.dateAdded
            FROM moz_annos a
            JOIN moz_places p ON a.place_id = p.id
            JOIN moz_anno_attributes n ON a.anno_attribute_id = n.id
            WHERE n.name = 'downloads/destinationFileURI' AND a.dateAdded >= ?
            ORDER BY a.dateAdded DESC
        """
        cursor.execute(query, (cutoff_prtime,))
        rows = cursor.fetchall()
        conn.close()

        for row in rows:
            url, title, dest_uri, date_added_raw = row
            dest_str = dest_uri or ""
            filename = Path(dest_str.replace("file://", "")).name or (title or "desconocido")
            unix_ts = _firefox_time_to_unix(date_added_raw or 0)
            date_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(unix_ts)) if unix_ts > 0 else "N/A"
            url_str = url or ""

            risk_level, reasons = _classify_risk(filename, url_str)

            results.append({
                "browser_type": "Firefox",
                "archivo": filename,
                "ruta_destino": dest_str,
                "bytes": 0,
                "fecha": date_str,
                "timestamp_unix": unix_ts,
                "url_origen": url_str,
                "nivel_riesgo": risk_level,
                "motivos": reasons
            })
    except Exception:
        pass
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return results


def _history_path(profile) -> Path:
    return Path(profile.path) / "History"


def audit_chromium_history(profile, limit: int = 500) -> dict:
    db = _history_path(profile)
    result = {"navegador": profile.browser, "perfil": getattr(profile, "profile", getattr(profile, "name", "Default")),
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


def audit_recent_downloads(hours: int = 48) -> dict[str, Any]:
    """
    Descubre perfiles de navegadores y audita las descargas recientes
    en todos los perfiles disponibles (Chromium y Firefox).
    """
    profiles = discover()
    all_downloads = []

    for p in profiles:
        # Chromium family
        history_candidate = p.path / "History"
        if history_candidate.exists():
            dls = audit_chromium_downloads(history_candidate, max_age_hours=hours)
            for d in dls:
                d["navegador"] = p.browser
                d["perfil"] = p.name
            all_downloads.extend(dls)

        # Firefox family
        places_candidate = p.path / "places.sqlite"
        if places_candidate.exists():
            dls = audit_firefox_downloads(places_candidate, max_age_hours=hours)
            for d in dls:
                d["navegador"] = p.browser
                d["perfil"] = p.name
            all_downloads.extend(dls)

    risk_weights = {"CRÍTICO": 3, "ALTO": 2, "MEDIO": 1, "BAJO": 0}
    all_downloads.sort(key=lambda x: (risk_weights.get(x["nivel_riesgo"], 0), x["timestamp_unix"]), reverse=True)

    criticos = sum(1 for d in all_downloads if d["nivel_riesgo"] == "CRÍTICO")
    altos = sum(1 for d in all_downloads if d["nivel_riesgo"] == "ALTO")
    medios = sum(1 for d in all_downloads if d["nivel_riesgo"] == "MEDIO")

    return {
        "horas_auditadas": hours,
        "total_descargas_analizadas": len(all_downloads),
        "descargas_criticas": criticos,
        "descargas_altas": altos,
        "descargas_medias": medios,
        "descargas": all_downloads
    }
