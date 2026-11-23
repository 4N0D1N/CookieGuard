#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "[CookieGuard] Sembrando cebos canary en perfiles de navegador..."
python3 -m cookieguard canary --plantar
