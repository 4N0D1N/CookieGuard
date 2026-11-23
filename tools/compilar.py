"""Script para compilar binarios standalone de CookieGuard mediante PyInstaller.

Uso:
    python tools/compilar.py [--output-dir DIR]
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description="Compila CookieGuard como ejecutable independiente")
    parser.add_argument("--output-dir", "-o", default=str(ROOT / "dist"), help="Directorio de salida")
    parser.add_argument("--clean", action="store_true", help="Limpia artefactos previos de compilación")
    args = parser.parse_args()

    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    sep = ";" if os.name == "nt" else ":"
    entry_point = ROOT / "cookieguard" / "__main__.py"

    data_catalogo = f"{ROOT / 'catalogo'}{sep}catalogo"
    data_config = f"{ROOT / 'config'}{sep}config"

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name", "CookieGuard",
        "--add-data", data_catalogo,
        "--add-data", data_config,
        "--distpath", str(out_dir),
        "--workpath", str(ROOT / "build"),
        "--specpath", str(ROOT / "build"),
        str(entry_point)
    ]

    print("=== Compilando CookieGuard con PyInstaller ===")
    print(f"Comando: {' '.join(cmd)}")

    code = subprocess.call(cmd)
    if code != 0:
        print(f"Error al compilar (código {code})", file=sys.stderr)
        return code

    exe_name = "CookieGuard.exe" if os.name == "nt" else "CookieGuard"
    target_bin = out_dir / exe_name

    if target_bin.exists():
        size_mb = round(target_bin.stat().st_size / (1024 * 1024), 2)
        print(f"\n[OK] Binario generado con éxito: {target_bin} ({size_mb} MB)")
        return 0
    else:
        print(f"\n[!] El binario esperado no se encontró en {target_bin}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main() or 0)
