"""Genera un bundle de muestra y lo valida con stix2-validator (herramienta de CI)."""
from __future__ import annotations

import subprocess
import tempfile
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from cookieguard.stix_export import export_stix_bundle


def main() -> int:
    sample = {
        "indicadores": [{
            "id": "I15_procesos_infostealer",
            "nombre": "Validación CI",
            "estado": "alerta",
            "resumen": "Hallazgo heurístico sintético para validar estructura STIX.",
            "puntos": 1,
            "hallazgos": ["Dato sintético; no es un IoC real."],
        }]
    }
    with tempfile.TemporaryDirectory(prefix="cookieguard-stix-") as tmp:
        path = Path(tmp) / "bundle.json"
        export_stix_bundle(sample, path)
        return subprocess.call(["stix2_validator", "--strict", str(path)])


if __name__ == "__main__":
    raise SystemExit(main())
