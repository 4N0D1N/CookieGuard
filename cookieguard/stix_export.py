"""Exporta reportes de CookieGuard como Bundle STIX 2.1 conservador.

Las alertas heurísticas se exportan como Notes enlazadas a Attack Patterns MITRE.
No se fabrican indicadores IOC ni patrones de detección sin datos concretos observados.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .common import data_dir, log
from .forensics import _sanitize_data
from .incident_report import MITRE_MAPPING

def _stix_id(kind: str, _key: str) -> str:
    # STIX 2.1 object identifiers use UUIDv4.
    return f"{kind}--{uuid.uuid4()}"



def export_stix_bundle(res: dict[str, Any], output_path: str | Path | None = None) -> dict[str, Any]:
    """Escribe un Bundle STIX 2.1; los hallazgos quedan como Notes, no IOC verificados."""
    now_iso = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    bundle_id = f"bundle--{uuid.uuid4()}"
    identity_id = _stix_id("identity", "cookieguard.sensor")
    objects: list[dict[str, Any]] = [{
        "type": "identity", "spec_version": "2.1", "id": identity_id,
        "created": now_iso, "modified": now_iso,
        "name": "CookieGuard", "identity_class": "system",
        "description": "Sensor defensivo local; los hallazgos heurísticos requieren validación humana."
    }]

    indicators = res.get("indicadores", [])
    alertas = [i for i in indicators if isinstance(i, dict) and i.get("estado") == "alerta"]
    ids_alerta = {str(i.get("id", "")) for i in alertas}
    relevant = {
        tid: info for tid, info in MITRE_MAPPING.items()
        if any(ind_id in ids_alerta for ind_id in info.get("indicadores", []))
    }

    attack_pattern_ids: dict[str, str] = {}
    for tid, info in relevant.items():
        ap_id = _stix_id("attack-pattern", tid)
        attack_pattern_ids[tid] = ap_id
        objects.append({
            "type": "attack-pattern", "spec_version": "2.1", "id": ap_id,
            "created": now_iso, "modified": now_iso,
            "name": info["nombre"], "description": info["descripcion"],
            "external_references": [{
                "source_name": "mitre-attack", "external_id": tid
            }]
        })

    for index, alert in enumerate(alertas):
        alert_id = str(alert.get("id", f"alert-{index}"))
        refs = [
            attack_pattern_ids[tid]
            for tid, info in relevant.items()
            if alert_id in info.get("indicadores", [])
        ]
        if not refs:
            # Notes need object_refs; use the CookieGuard identity as context,
            # not an assertion that a MITRE technique was confirmed.
            refs = [identity_id]
        raw_hallazgos = alert.get("hallazgos", [])
        if not isinstance(raw_hallazgos, list):
            raw_hallazgos = [raw_hallazgos]
        safe_hallazgos = [str(value)[:1000] for value in raw_hallazgos[:10]]
        content = {
            "schema": "cookieguard-heuristic-finding",
            "indicator_id": alert_id,
            "name": str(alert.get("nombre", "Alerta CookieGuard"))[:200],
            "summary": str(alert.get("resumen", ""))[:2000],
            "severity_score": alert.get("puntos", 0),
            "evidence": safe_hallazgos,
            "confidence_note": "Heurística; no equivale a un IOC verificado ni a atribución de un atacante."
        }
        content = _sanitize_data(content)
        note_id = f"note--{uuid.uuid4()}"
        objects.append({
            "type": "note", "spec_version": "2.1", "id": note_id,
            "created": now_iso, "modified": now_iso,
            "created_by_ref": identity_id,
            "content": json.dumps(content, ensure_ascii=False),
            "object_refs": refs
        })

    bundle = {"type": "bundle", "id": bundle_id, "objects": objects}
    if output_path is not None:
        dest = Path(output_path)
    else:
        target_dir = data_dir() / "stix"
        target_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        dest = target_dir / f"stix_bundle_{timestamp}.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        raise FileExistsError(f"El destino ya existe y no se sobrescribirá: {dest}")
    dest.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
    log(f"[STIX] Bundle STIX 2.1 conservador exportado en {dest}")
    return bundle
