# Decisiones tomadas (sin preguntar, según tus reglas)

| # | Decisión | Por qué |
|---|---|---|
| 1 | **Python 3 (solo librería estándar)** en lugar de PowerShell 5.1 + C# `Add-Type` | Pediste **Windows y Linux**. PowerShell 5.1 no existe en Linux; sqlite3, tkinter, ctypes, winreg y zipfile vienen con Python y evitan P/Invoke a `winsqlite3.dll` y dependencias. PowerShell se sigue usando *dentro* de Windows para cosas nativas (Defender, firmas, tareas). |
| 2 | **`unittest`** en lugar de Pester | Multiplataforma, sin instalar nada (no hubo que pedirte permiso para Pester). |
| 3 | **Lista blanca de columnas** (no lista negra de `value`) | Falla cerrado: lo que no esté explícitamente permitido, no se lee. |
| 4 | Copia de BD con `CreateFileW` y compartición RWD; **VSS solo con administrador** | Tu requisito. Hallazgo: con Chrome/Edge abiertos sigue el error 32; no se usa lectura de memoria. |
| 5 | Líneas base de persistencia/red/extensiones **no avanzan solas** | Si el atacante añadiera persistencia, no debe pasar a "normal". El usuario acepta cambios a mano. Las sesiones sí se comparan con la ejecución anterior (así se piden las "nuevas"). |
| 6 | Falsos positivos corregidos tras la primera ejecución real | Apps Electron/WebView2 (Notion, etc.) guardan `Cookies`/`Login Data` en AppData: se ignoran si hay `Local State`/`Preferences` cerca. Shells que citan `--remote-debugging-port` no cuentan. |
| 7 | Notificación: toast WinRT vía PowerShell con ID de PowerShell; globo de bandeja de respaldo; `notify-send` en Linux | Sin dependencias; el botón "Abrir informe" usa activación por protocolo (`file:///`). |
| 8 | Icono de bandeja **no incluido** (stdlib no lo permite) | Ver `MEJORAS-FUTURAS.md` (pystray opcional). Se sustituyó por toast + acceso directo + vigilante con ventana de alerta. |
| 9 | Hardening: solo se "aplica" lo seguro y reversible (reglas ASR y PUA de Defender, con administrador); el resto son comprobaciones + instrucciones | Cambiar `Preferences` del navegador (borrar al cerrar, no guardar contraseñas) no es fiable: Chrome puede revertirlo/invalidar su HMAC. |
| 10 | Sysmon no se incluye ni se instala sin preguntar: se instala vía `winget` con tu aprobación en `Instalar` | Es una instalación de software en tu sistema (regla 2). |
| 11 | **No he instalado ni activado nada en tu equipo**: ni tareas, ni auditpol, ni SACL, ni Sysmon, ni reglas de firewall, ni he borrado cookies reales | Regla 2. Solo lectura de metadatos (copias temporales) y estado en carpetas temporales de pruebas. Todo el instalador se probó con `--dry-run`. |
| 12 | Cookies canary: no se escriben cookies en el navegador | Obligaría a manejar valores; el asistente guía para plantarlas tú. |
| 13 | Equipo: solo hay uno visible en la sesión | No hubo ambigüedad que preguntar. |
| 14 | Alta del indicador 5: extensión en modo desarrollador + permiso peligroso avisa aunque sea la primera ejecución | Es sospechosa por sí misma, no por ser "nueva". |
| 15 | Indicador 7 en Linux = "Sin datos" | Linux no expone caché DNS sin servicios adicionales; mejor decirlo que inventar. |
