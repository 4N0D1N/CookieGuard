#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "[CookieGuard] Restaurando conexion de red normal..."
python3 -m cookieguard killswitch --desactivar
