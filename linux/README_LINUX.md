# 🐧 CookieGuard — Guía de Uso para Linux

Esta carpeta contiene los scripts y unidades de servicio específicos para ejecutar **CookieGuard** en distribuciones **Linux** (Ubuntu, Debian, Fedora, Arch, Pop!_OS, etc.).

---

## ⚡ Inicio Rápido

CookieGuard funciona con la biblioteca estándar de Python sin requerir ningún módulo externo ni permisos de `root`.

1. **Dar permisos de ejecución a los scripts:**
   ```bash
   chmod +x linux/*.sh
   ```

2. **Abrir CookieGuard (GUI o Dashboard en Navegador):**
   ```bash
   ./linux/cookieguard.sh
   # o directamente desde la raíz:
   ./cookieguard.sh
   ```
   Si el entorno de escritorio no tiene `python3-tk` instalado, CookieGuard levantará automáticamente el **Dashboard HTML local** en tu navegador predeterminado vía `xdg-open`.

3. **Ejecutar un análisis puntual:**
   ```bash
   ./linux/analizar_ahora.sh
   # o: python3 -m cookieguard --analizar-ahora
   ```

---

## 👁️ Vigilante en Tiempo Real en Linux

El vigilante en tiempo real supervisa en segundo plano el acceso a las bases de datos de cookies de tus navegadores instalados (`~/.config/google-chrome`, `~/.config/chromium`, `~/.mozilla/firefox`, etc.).

### Instalación como servicio persistente (sin root):
Hemos preparado una unidad de **systemd de usuario** para que el vigilante arranque automáticamente con tu sesión:

```bash
# Instalar e iniciar el servicio en segundo plano:
./linux/instalar_servicio.sh

# Comprobar el estado del vigilante:
systemctl --user status cookieguard-watcher.service

# Ver logs en vivo:
journalctl --user -u cookieguard-watcher.service -f

# Desinstalar el servicio:
./linux/desinstalar_servicio.sh
```

---

## 🔍 ¿Cómo detecta infostealers en Linux sin dependencias?

1. **Inspección de `/proc/[pid]/fd` (Zero-root):**
   - El vigilante inspecciona periódicamente los descriptores de archivo abiertos en el sistema de archivos virtual `/proc`.
   - Si un binario ajeno (que no pertenezca a la lista de navegadores legítimos) abre los archivos `Cookies` de Chromium o `cookies.sqlite` de Firefox, se dispara la alerta inmediata.
2. **Detección de argumentos de evasión en `/proc/[pid]/cmdline`:**
   - Detecta navegadores clonados o ejecutados con flags de depuración remota (`--remote-debugging-port`), `--headless` o con extensiones forzadas desde rutas temporales (`/tmp`, `/dev/shm`).
3. **Notificación interactiva de escritorio:**
   - Utiliza la especificación estándar de notificaciones FreeDesktop (`notify-send` con `--action`).
   - Muestra una tarjeta en tu entorno gráfico (GNOME, KDE, XFCE) con el botón:
     `[ 🌐 Abrir análisis en navegador ]`
   - Al pulsar el botón, lanza automáticamente la pestaña de triaje de emergencia.

### Acciones de Mitigación Disponibles:
- **Terminar proceso:** Envía una señal `SIGKILL` (`kill -9 PID`) para congelar la exfiltración.
- **Revocar permisos de ejecución:** Aplica `chmod -x /ruta/al/malware` para evitar que vuelva a ser lanzado por un script padre.
- **Triaje en navegador:** Acceso inmediato a los enlaces de revocación de sesiones remotas (Google Workspace, GitHub, Microsoft 365, AWS).
