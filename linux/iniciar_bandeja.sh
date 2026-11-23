#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"
echo "Iniciando CookieGuard en bandeja / background..."
nohup python3 -m cookieguard tray > /dev/null 2>&1 &
echo "CookieGuard ejecutandose en segundo plano."
