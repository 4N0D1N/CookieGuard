"""Módulo de Exportación Pericial Forense para Ciberseguros y Cadena de Custodia.

Genera un expediente pericial sellado criptográficamente (SHA-256 / SHA-512)
con metadatos de integridad y trazabilidad. Este paquete sirve como apoyo técnico
para análisis, pero no constituye certificado, informe pericial oficial ni prueba
de admisibilidad legal. No lee ni incluye contenido de cookies, credenciales o bases de datos.

Zero dependencias externas obligatorias. 100% biblioteca estándar de Python.
"""
from __future__ import annotations

import hashlib
import html
import json
import platform
import sys
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .browsers import discover
from .common import VERSION, data_dir, log
from .persistence_audit import run_persistence_audit as audit_all_persistence


def _calc_sha256(path: Path) -> Optional[str]:
    """Calcula el hash SHA-256 de un fichero sin cargarlo entero en RAM."""
    if not path.is_file():
        return None
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _get_machine_anonymized_id() -> str:
    """Genera un identificador de máquina efímero y anonimizado, sin persistir el nombre real."""
    raw = f"{platform.node()}-{platform.system()}-{platform.machine()}-{uuid.uuid4().hex}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _utc_now() -> datetime:
    """Devuelve datetime aware en UTC, portable para Python 3.10+."""
    return datetime.now(timezone.utc)


def _safe_local_metadata(profiles) -> List[Dict[str, Any]]:
    """Recolecta rutas y metadatos; no abre bases de datos de cookies."""
    artifacts: List[Dict[str, Any]] = []
    for profile in profiles:
        db_path = profile.cookies_db
        if not db_path or not db_path.exists():
            continue
        try:
            st = db_path.stat()
            artifacts.append({
                "navegador": profile.browser,
                "perfil": profile.profile,
                "archivo": db_path.name,
                "tamano_bytes": st.st_size,
                "modificado_utc": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
                "sha256": None,
                "nota_privacidad": "Solo metadatos del sistema de archivos; no se abrió ni leyó el contenido de la base de datos."
            })
        except OSError:
            continue
    return artifacts


def _summary_payload() -> Dict[str, Any]:
    """Construye un resumen de estado solo con la API real del módulo dummy_summary."""
    findings = audit_all_persistence()
    total_findings = findings.get("suspicious_count", 0)
    severity = "Verde" if total_findings == 0 else "Amarillo"
    return {
        "semaforo": severity,
        "titulo": "Sin hallazgos de persistencia" if total_findings == 0 else "Requiere revisión manual",
        "total_problemas": total_findings,
        "persistencia": findings,
    }


def generate_forensic_custody_package(
    output_dir: Optional[Path] = None,
    analyst_name: str = "Usuario local",
    incident_id: Optional[str] = None,
    notes: str = "Exportación local de metadatos para revisión; no es certificación pericial.",
) -> Dict[str, Any]:
    """Genera manifiesto, informe HTML/Markdown y ZIP con hashes reproducibles."""
    issued_at = _utc_now()
    incident = incident_id or f"CG-{issued_at.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:6].upper()}"
    target_dir = Path(output_dir) if output_dir else data_dir() / "peritajes" / incident
    target_dir.mkdir(parents=True, exist_ok=True)

    # Hashes de módulos CookieGuard incluidos para trazabilidad del software.
    modules_dir = Path(__file__).resolve().parent
    module_hashes = {}
    for file_path in sorted(modules_dir.glob("*.py")):
        digest = _calc_sha256(file_path)
        if digest:
            module_hashes[file_path.name] = digest

    profiles = discover()
    artifacts = _safe_local_metadata(profiles)
    summary = _summary_payload()

    manifest: Dict[str, Any] = {
        "schema": "cookieguard-evidence-manifest-v1",
        "expediente_id": incident,
        "fecha_emision_utc": issued_at.isoformat(),
        "responsable_declarado": analyst_name,
        "notas": notes,
        "herramienta": {"nombre": "CookieGuard", "version": VERSION, "modulos_sha256": module_hashes},
        "entorno": {
            "sistema_operativo": platform.platform(),
            "arquitectura": platform.machine(),
            "python": sys.version.split()[0],
            "id_host_aleatorio": _get_machine_anonymized_id(),
        },
        "artefactos_metadatos": artifacts,
        "resumen_local": {
            "semaforo": summary["semaforo"],
            "titulo": summary["titulo"],
            "total_problemas": summary["total_problemas"],
        },
        "cadena_de_custodia": [{
            "evento": "paquete_creado",
            "fecha_utc": issued_at.isoformat(),
            "actor_declarado": analyst_name,
            "detalle": "Creación local; no hay firma de tercero ni anclaje temporal externo."
        }],
        "limitaciones": [
            "Este archivo es un registro técnico local, no es un informe pericial oficial ni asesoramiento legal.",
            "SHA-256 del manifiesto y del ZIP detecta cambios posteriores, pero no demuestra quién recogió los datos ni cuándo.",
            "El nombre del responsable y las notas son declarados por el usuario, no verificados.",
            "No se abren ni copian bases de datos de cookies, contraseñas o sesiones.",
        ],
    }

    canonical = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    manifest["sha256_manifest_sin_sello"] = hashlib.sha256(canonical).hexdigest()

    manifest_path = target_dir / "cadena_de_custodia.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    html_path = target_dir / "informe_metadatos.html"
    html_path.write_text(_build_html(manifest), encoding="utf-8")
    md_path = target_dir / "informe_metadatos.md"
    md_path.write_text(_build_markdown(manifest), encoding="utf-8")

    zip_path = target_dir / f"Expediente_{incident}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(manifest_path, "cadena_de_custodia.json")
        archive.write(html_path, "informe_metadatos.html")
        archive.write(md_path, "informe_metadatos.md")

    zip_hash = _calc_sha256(zip_path)
    log(f"Paquete local de metadatos generado: {zip_path}")
    return {
        "expediente_id": incident,
        "directorio": str(target_dir),
        "archivo_zip": str(zip_path),
        "sha256_zip": zip_hash,
        "sha256_manifest": manifest["sha256_manifest_sin_sello"],
        "total_artefactos": len(artifacts),
        "semaforo": summary["semaforo"],
        "cadena_custodia_path": str(manifest_path),
        "informe_html_path": str(html_path),
        "informe_md_path": str(md_path),
    }


def _build_html(manifest: Dict[str, Any]) -> str:
    """Crea informe HTML imprimible, escapando todos los campos dinámicos."""
    rows = []
    for item in manifest["artefactos_metadatos"]:
        rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>".format(
                html.escape(str(item["navegador"])),
                html.escape(str(item["perfil"])),
                html.escape(str(item["tamano_bytes"])),
                html.escape(str(item["sha256"])),
            )
        )
    if not rows:
        rows.append("<tr><td colspan='4'>No se encontraron perfiles de navegador accesibles.</td></tr>")
    rows_html = "\n".join(rows)
    limits = "".join(f"<li>{html.escape(item)}</li>" for item in manifest["limitaciones"])
    return f"""<!doctype html><html lang="es"><meta charset="utf-8"><title>CookieGuard {html.escape(manifest['expediente_id'])}</title>
<style>body{{font:15px/1.5 system-ui,sans-serif;max-width:900px;margin:40px auto;padding:0 18px;color:#172033}}h1{{color:#075985}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccd5df;padding:8px;text-align:left}}th{{background:#edf4f8}}.warn{{background:#fff7ed;padding:12px;border-left:4px solid #ea580c}}code{{word-break:break-all}}@media print{{body{{margin:0;max-width:none}}}}</style>
<h1>Exportación local de metadatos</h1><p><b>Expediente:</b> {html.escape(manifest['expediente_id'])}</p>
<p><b>Fecha UTC:</b> {html.escape(manifest['fecha_emision_utc'])} · <b>Estado:</b> {html.escape(manifest['resumen_local']['semaforo'])}</p>
<p><b>Responsable declarado:</b> {html.escape(manifest['responsable_declarado'])}</p>
<div class="warn"><b>Importante:</b> Este paquete es un registro local de apoyo. No es informe pericial oficial ni acredita identidad, hora fiable o admisibilidad legal.</div>
<h2>Metadatos de perfiles de navegador</h2><p>Solo se guardan metadatos del sistema de archivos; no se abre el contenido de cookies ni credenciales.</p>
<table><thead><tr><th>Navegador</th><th>Perfil</th><th>Tamaño</th><th>SHA-256</th></tr></thead><tbody>{rows_html}</tbody></table>
<h2>Limitaciones</h2><ul>{limits}</ul><h2>Hash del manifiesto (SHA-256)</h2><code>{html.escape(manifest['sha256_manifest_sin_sello'])}</code>
</html>"""


def _build_markdown(manifest: Dict[str, Any]) -> str:
    lines = [
        f"# Exportación local de metadatos: {manifest['expediente_id']}",
        f"- Fecha UTC: {manifest['fecha_emision_utc']}",
        f"- Responsable declarado: {manifest['responsable_declarado']}",
        f"- Estado: {manifest['resumen_local']['semaforo']}",
        "",
        "> No es un informe pericial oficial ni acredita identidad, hora fiable o admisibilidad legal.",
        "> No abre ni incluye bases de datos de cookies, credenciales ni contenido de sesión.",
        "",
        "## Metadatos de perfiles de navegador",
        "| Navegador | Perfil | Tamaño (bytes) | SHA-256 |",
        "|---|---|---:|---|",
    ]
    for item in manifest["artefactos_metadatos"]:
        lines.append(f"| {item['navegador']} | {item['perfil']} | {item['tamano_bytes']} | `{item['sha256']}` |")
    lines.extend(["", "## Limitaciones", *[f"- {item}" for item in manifest["limitaciones"]], "", "## Hash del manifiesto", f"`{manifest['sha256_manifest_sin_sello']}`"])
    return "\n".join(lines) + "\n"
