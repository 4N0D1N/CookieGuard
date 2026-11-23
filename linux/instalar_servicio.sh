#!/usr/bin/env bash
# Instala el vigilante en segundo plano como servicio systemd de usuario (sin root)
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"
mkdir -p "$SYSTEMD_USER_DIR"

cat << 'UNIT' > "${SYSTEMD_USER_DIR}/cookieguard-watcher.service"
[Unit]
Description=CookieGuard Real-time Session Watcher
After=default.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -m cookieguard.watcher
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
UNIT

systemctl --user daemon-reload
systemctl --user enable --now cookieguard-watcher.service
echo "[✓] Servicio CookieGuard instalado e iniciado para el usuario actual."
echo "    Estado: systemctl --user status cookieguard-watcher.service"
