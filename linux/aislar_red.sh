#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "[CookieGuard] Activando Killswitch de red de emergencia..."
python3 -m cookieguard killswitch --activar
