"""Lectura de indicadores visibles de cifrado en Local State, sin descifrado."""
from __future__ import annotations

import base64
import json
from pathlib import Path


def inspect_local_state(path: str | Path) -> dict:
    out = {"archivo": Path(path).name, "legible": False,
           "marcador_app_bound": False, "marcador_dpapi_legacy": False,
           "nota": "Los marcadores no validan la protección efectiva ni permiten concluir que el perfil sea seguro o vulnerable."}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        os_crypt = data.get("os_crypt", {}) if isinstance(data, dict) else {}
        app = os_crypt.get("app_bound_encrypted_key")
        legacy = os_crypt.get("encrypted_key")
        out["legible"] = True
        out["marcador_app_bound"] = bool(app and (_prefix(app) or b"").startswith(b"APPB"))
        out["marcador_dpapi_legacy"] = bool(legacy and _prefix(legacy) == b"DPAPI")
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        pass
    return out


def _prefix(value: object) -> bytes | None:
    if not isinstance(value, str):
        return None
    try:
        return base64.b64decode(value, validate=True)[:5]
    except (ValueError, TypeError):
        return None


def audit_appbound_encryption(roots) -> dict:
    results = []
    seen = set()
    for name, root in roots:
        root = Path(root)
        try:
            key = str(root.resolve())
        except OSError:
            key = str(root)
        if key in seen:
            continue
        seen.add(key)
        path = root / "Local State"
        if path.is_file():
            item = inspect_local_state(path)
            item["navegador"] = name
            results.append(item)
    return {
        "navegadores_auditados": len(results),
        "marcadores_app_bound": sum(1 for x in results if x["marcador_app_bound"]),
        "marcadores_dpapi_legacy": sum(1 for x in results if x["marcador_dpapi_legacy"]),
        "detalles": results,
        "resumen": "Indicadores de archivos visibles; esto no comprueba la protección en ejecución ni descifra cookies.",
    }
