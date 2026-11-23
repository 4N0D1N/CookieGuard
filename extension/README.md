# 🧩 Extensión Complementaria de Navegador: CookieGuard Session Shield

> **Supervisión ultraligera en tiempo real para Google Chrome, Microsoft Edge, Brave Browser y Mozilla Firefox.**

## 🛡️ Características Principales

1. **Privacidad Estricta Zero-Plaintext:**
   - La extensión **nunca** lee ni almacena los valores de las cookies.
   - Únicamente monitoriza metadatos mediante la API nativa `chrome.cookies.onChanged` (dominio, nombre de cookie, causa del cambio, eliminación/rotación).

2. **Detección Temprana:**
   - Detecta si las cookies de sesión crítica son borradas o sobreescritas intempestivamente (síntoma habitual de rotación forzada o hijacking).

3. **Revocación de Sesión en 1-Clic:**
   - Enlaces directos a los centros de revocación de sesiones de Google, GitHub y Microsoft 365 para expulsar sesiones clonadas inmediatamente.

---

## 🚀 Instalación en Modo Desarrollador (Unpacked)

### En Google Chrome, Microsoft Edge y Brave:
1. Abre tu navegador y navega a `chrome://extensions` (o `edge://extensions` en Edge).
2. Activa el conmutador **"Modo de desarrollador"** (Developer mode) en la esquina superior derecha.
3. Haz clic en el botón **"Cargar descomprimida"** (Load unpacked).
4. Selecciona esta carpeta `extension/` del repositorio CookieGuard.
5. ¡Listo! Verás el icono del escudo 🛡️ de CookieGuard en la barra de herramientas de tu navegador.

### En Mozilla Firefox:
1. Abre `about:debugging#/runtime/this-firefox`.
2. Haz clic en **"Cargar complemento temporal..."** (Load Temporary Add-on).
3. Selecciona el archivo `manifest.json` dentro de esta carpeta `extension/`.
