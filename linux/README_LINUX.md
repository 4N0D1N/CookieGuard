# 🐧 Guía de CookieGuard para Linux

> **Instrucciones completas para despliegue, auditoría, vigilancia y respuesta a incidentes en distribuciones Linux (Ubuntu, Debian, Fedora, Arch).**

---

## 🎮 Simulación Interactiva

Puedes probar la experiencia de respuesta a incidentes en Linux abriendo en tu navegador:
👉 **[`docs/simulaciones/simulacion_incidente_linux.html`](../docs/simulaciones/simulacion_incidente_linux.html)**
*(Simulación interactiva autónoma en HTML para visualizar la alerta `notify-send`, inspección de `/proc/[pid]/fd` y triaje).*

---

## 🚀 Scripts Rápidos Disponibles

| Script | Propósito |
| :--- | :--- |
| `abrir_cookieguard.sh` | Lanza la interfaz gráfica de triaje o el dashboard interactivo. |
| `analizar_ahora.sh` | Ejecuta un escaneo forense completo y muestra el resumen por terminal. |
| `aislar_red.sh` | **Emergencia:** Corta la conectividad mediante `nmcli` o reglas `iptables`. |
| `restaurar_red.sh` | Reactiva las interfaces de red y restablece el tráfico. |
| `sembrar_canaries.sh` | Siembra cookies cebo en los perfiles de navegador locales. |
| `instalar_vigilante.sh` | Configura e inicia el servicio en segundo plano mediante `systemd --user`. |
| `desinstalar_vigilante.sh` | Detiene y elimina el servicio de `systemd`. |

---

## ⚙️ Características Específicas de Linux

1. **Inspección de Descriptores de Ficheros (`/proc/[pid]/fd`):**
   - El vigilante detecta inmediatamente qué proceso tiene abiertos los ficheros SQLite de cookies (`Cookies`, `cookies.sqlite`).
   - Sin necesidad de privilegios `root` para procesos pertenecientes al mismo usuario.

2. **Notificaciones de Escritorio con `notify-send`:**
   - Envío de alertas con urgencia crítica (`-u critical`) y botón interactivo para abrir el navegador con `xdg-open`.

3. **Killswitch Flexible:**
   - Soporte nativo para `nmcli networking off` (entornos de escritorio NetworkManager) o reglas `iptables` de contingencia.
