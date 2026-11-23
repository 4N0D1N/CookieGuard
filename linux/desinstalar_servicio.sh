#!/usr/bin/env bash
# Detiene y elimina el servicio systemd de usuario
set -euo pipefail
systemctl --user stop cookieguard-watcher.service 2>/dev/null || true
systemctl --user disable cookieguard-watcher.service 2>/dev/null || true
rm -f "${HOME}/.config/systemd/user/cookieguard-watcher.service"
systemctl --user daemon-reload
echo "[✓] Servicio de CookieGuard desinstalado con éxito."
