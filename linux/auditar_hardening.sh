#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"
echo "=== CookieGuard - Auditoria de Endurecimiento de Navegador ==="
python3 -m cookieguard hardening
