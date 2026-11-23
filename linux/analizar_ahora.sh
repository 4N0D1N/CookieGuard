#!/usr/bin/env bash
# Ejecuta un análisis de sesiones inmediato y abre el informe en el navegador
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

python3 -m cookieguard --analizar-ahora
