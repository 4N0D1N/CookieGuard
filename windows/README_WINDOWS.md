# 🛡️ CookieGuard — Guía de Uso para Windows

Esta carpeta contiene los scripts y configuraciones específicos para desplegar y utilizar **CookieGuard** en entornos **Microsoft Windows (10, 11 y Windows Server)**.

---

## ⚡ Inicio Rápido (1 Clic)

No requiere instalación de librerías externas (`pip install` no es necesario). Solo necesitas tener **Python 3.10+** instalado en tu sistema.

1. **Abrir la aplicación gráfica / panel interactivo:**
   - Haz doble clic en `Abrir CookieGuard.cmd` (o `windows/Abrir CookieGuard.cmd`).
   - Si tu Python incluye Tkinter, abrirá la interfaz de escritorio nativa. Si no, generará y abrirá automáticamente el **Dashboard HTML local** en tu navegador.

2. **Ejecutar un análisis puntual inmediato:**
   - Haz doble clic en `Analizar ahora.cmd`.
   - Analizará las cookies de sesión de todos tus navegadores (Chrome, Edge, Brave, Firefox, etc.) y abrirá el informe completo.

---

## 👁️ Vigilante en Tiempo Real en Windows

El vigilante en tiempo real supervisa el sistema de forma continua para detectar intentos de robo de cookies e infostealers.

### Scripts disponibles:
- **`Instalar vigilante.cmd`**: Registra una tarea programada en Windows para que el vigilante se inicie automáticamente en segundo plano al iniciar sesión, sin ventanas molestas.
- **`Desinstalar vigilante.cmd`**: Detiene y elimina la tarea programada del sistema.

### ¿Cómo detecta accesos maliciosos en Windows?
1. **Inspección de Procesos y Argumentos Peligrosos:**
   - Detecta navegadores lanzados con `--remote-debugging-port` o `--remote-allow-origins` (técnica usada por atacantes para robar cookies descifradas directamente de la memoria).
   - Detecta ejecuciones en modo `--headless` sospechosas.
2. **Auditoría de Archivos de Seguridad (Event ID 4663):**
   - Si la auditoría de accesos a archivos de Windows está habilitada, CookieGuard lee el log de seguridad de Windows para ver qué procesos abrieron las bases de datos `Cookies`, `Login Data` o `Web Data`.
3. **Integración con Sysmon (Recomendado):**
   - Incluimos una plantilla de configuración en `reglas/sysmon-cookieguard.xml` para monitorizar Event ID 10 (acceso a la memoria de procesos de navegadores) y Event ID 11 (creación/lectura de archivos sensibles).

### Respuesta ante Alerta:
Cuando se detecta un proceso sospechoso:
- Salta una **notificación Toast nativa de Windows** con sonido de alerta.
- Botón directo para **Abrir triaje en el navegador**.
- Opciones para:
  - **Suspender** o **Terminar (SIGKILL/Taskkill)** el proceso culpable.
  - **Bloquear en el Firewall de Windows** (añade una regla de bloqueo saliente para impedir que exfiltre datos).
  - Marcar como de confianza si es una herramienta conocida.

---

## 🔧 Requisitos del Sistema
- Windows 10 o Windows 11 (64 bits recomendado).
- Python 3.10 o superior (marcar la casilla *"Add Python to PATH"* durante la instalación).
- Permisos de Administrador (únicamente requeridos si deseas aplicar reglas de Firewall o instalar la auditoría Sysmon; el escaneo básico y el vigilante funcionan con usuario normal).
