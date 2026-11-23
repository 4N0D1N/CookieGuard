# Registro de Progreso - CookieGuard

## Versión 1.1.0 (Actual)
- [x] **Killswitch de Red de Emergencia:** Módulo `cookieguard/killswitch.py` con bloqueo y restauración nativa en Windows (`netsh`) y Linux (`nmcli`/`iptables`). Wrappers en `actions.py` y scripts de conveniencia.
- [x] **Canary Cookies Activas:** Módulo `cookieguard/canary.py` con siembra local de cookies cebo, detección en Indicador I13 (`detections.py`) y verificación de integridad.
- [x] **Notificaciones Webhook Remotas:** Módulo `cookieguard/webhook.py` con envío seguro a ntfy.sh / Discord usando herramientas del sistema sin dependencias de terceros.
- [x] **Simulaciones Interactivas en Navegador:**
  - `docs/simulaciones/simulacion_incidente_windows.html`: Recreación interactiva de notificación Toast Windows 11, panel de triaje y Killswitch.
  - `docs/simulaciones/simulacion_incidente_linux.html`: Recreación interactiva de notificación `notify-send`, inspección `/proc` y triaje.
- [x] **Pruebas Automatizadas:** 39 tests unitarios pasando al 100% (32 de auditoría/heurística original + 7 de seguridad estricta + nuevas mejoras).

## Versión 1.0.0
- [x] Soporte multiplataforma Windows (PowerShell/CMD) y Linux (Bash/systemd).
- [x] Separación de carpetas `windows/` y `linux/` con scripts dedicados.
- [x] 12 Detectores heurísticos iniciales alineados con MITRE ATT&CK.
- [x] Generación de Dashboard HTML interactivo autónomo (44 KB).
