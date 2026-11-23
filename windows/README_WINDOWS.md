# 🪟 Guía de CookieGuard para Windows

> **Instrucciones completas para despliegue, auditoría, vigilancia y respuesta a incidentes en entornos Windows 10 y Windows 11.**

---

## 🎮 Simulación Interactiva

Antes de probar la herramienta en producción, puedes experimentar exactamente cómo responde CookieGuard ante un ataque en:
👉 **[`docs/simulaciones/simulacion_incidente_windows.html`](../docs/simulaciones/simulacion_incidente_windows.html)**
*(Es una simulación visual en HTML para comprobar la notificación Toast nativa, el aislamiento Killswitch y la rotación de sesiones).*

---

## 🚀 Scripts Rápidos Disponibles

| Script | Propósito |
| :--- | :--- |
| `Abrir CookieGuard.cmd` | Abre la interfaz gráfica de escritorio o el Dashboard HTML interactivo. |
| `Analizar ahora.cmd` | Ejecuta una auditoría inmediata por consola y muestra el inventario de sesiones. |
| `Aislar Red Killswitch.cmd` | **Emergencia:** Bloquea todo el tráfico saliente con el Firewall de Windows (`netsh`). |
| `Restaurar Red.cmd` | Restaura las conexiones de red normales eliminando la regla de bloqueo. |
| `Sembrar Canaries.cmd` | Siembra cookies señuelo en perfiles de Chromium y Firefox para detectar robos. |
| `Instalar vigilante.cmd` | Registra el vigilante en segundo plano como Tarea Programada de Windows. |
| `Desinstalar vigilante.cmd` | Elimina la tarea programada del sistema. |

---

## ⚙️ Características Específicas de Windows

1. **Notificaciones Toast Interactivas:**
   - Si se detecta un proceso no autorizado accediendo a `User Data\Default\Network\Cookies`, Windows muestra una notificación emergente nativa.
   - Cuenta con botón para **abrir el panel de análisis directamente en el navegador predeterminado**.

2. **Detección Forense Avanzada:**
   - Inspección de eventos de auditoría de objetos (Windows Security Event 4663) y Sysmon Event ID 10 / 11 si están habilitados en la máquina.
   - Escaneo de argumentos sospechosos como `--remote-debugging-port`.

3. **Killswitch Nativo:**
   - No requiere software de terceros: invoca `netsh advfirewall firewall add rule` con nombre `CookieGuard_Killswitch_Block` para cortar conexiones hacia C2s.
