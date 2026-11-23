"""Módulo de Canary Tokens con Callback DNS Pasivo (DNS Canary Tokens).

Permite desplegar cookies de señuelo vinculadas a subdominios DNS únicos.
Este módulo solo genera identificadores DNS para un dominio que controle el usuario y
compara una lista de consultas proporcionada localmente. No instala cookies, no registra
consultas externas y no alerta automáticamente: esas capacidades requieren DNS autoritativo
propio y un servicio de recepción/monitoreo configurado por el usuario.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from .common import data_dir, log


CANARY_STORE_FILE = "dns_canary_tokens.json"


def _get_store_path() -> Path:
    return data_dir() / CANARY_STORE_FILE


def generate_dns_canary_token(
    domain_suffix: str = "canary.cookieguard.internal",
    notes: str = "Token señuelo para detección de exfiltración"
) -> dict[str, Any]:
    """Genera un nombre DNS único; no crea registros ni lo instala en navegadores."""
    domain_suffix = domain_suffix.strip().strip(".").lower()
    if not domain_suffix or len(domain_suffix) > 240 or not re.fullmatch(
        r"(?=.{1,240}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
        domain_suffix,
        flags=re.I,
    ):
        raise ValueError("Indica un sufijo de dominio DNS válido que controles.")
    raw_token = secrets.token_hex(12)
    fqdn = f"cg-{raw_token}.{domain_suffix.strip('.')}"

    record = {
        "token_id": raw_token,
        "fqdn": fqdn,
        "dominio_base": domain_suffix,
        "notas": notes,
        "creado_utc": datetime.now().isoformat(),
        "activo": True
    }

    store_file = _get_store_path()
    store_file.parent.mkdir(parents=True, exist_ok=True)
    records = []
    if store_file.exists():
        try:
            records = json.loads(store_file.read_text(encoding="utf-8"))
        except Exception:
            records = []

    records.append(record)
    store_file.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        os.chmod(store_file, 0o600)
    except OSError:
        pass
    log(f"[DNS-Canary] Token señuelo generado: {fqdn}")
    return record


def list_dns_canary_tokens() -> list[dict[str, Any]]:
    """Lista todos los tokens DNS canary generados y almacenados."""
    store_file = _get_store_path()
    if not store_file.exists():
        return []
    try:
        return json.loads(store_file.read_text(encoding="utf-8"))
    except Exception:
        return []


def check_dns_cache_for_canaries(dns_cache_entries: list[str]) -> list[dict[str, Any]]:
    """Comprueba si alguna entrada de la caché DNS local coincide con los tokens canary registrados."""
    tokens = list_dns_canary_tokens()
    if not tokens or not dns_cache_entries:
        return []

    tokens_map = {t["fqdn"].lower(): t for t in tokens if t.get("activo")}
    alertas = []

    for entry in dns_cache_entries:
        low = entry.lower().strip()
        if low in tokens_map:
            t = tokens_map[low]
            alertas.append({
                "token_id": t["token_id"],
                "fqdn": t["fqdn"],
                "tipo": "CANARY_DNS_RESUELTO_LOCALMENTE",
                "detalle": f"El subdominio señuelo {t['fqdn']} fue resuelto por un proceso en este equipo."
            })

    return alertas
