#!/usr/bin/env bash
# Inicia la interfaz gráfica o el dashboard HTML en Linux
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

if command -v python3 >/dev/null 2>&1; then
    PY="python3"
elif command -v python >/dev/null 2>&1; then
    PY="python"
else
    echo "[!] Error: Python no encontrado en el sistema."
    exit 1
fi

exec "$PY" -m cookieguard "$@"
