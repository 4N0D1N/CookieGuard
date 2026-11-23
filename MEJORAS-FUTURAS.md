# Mejoras futuras (ideas grandes)

1. **Icono de bandeja** con menú (abrir, analizar ahora, último informe, salir): opcional con `pystray` + `Pillow` (no están en la librería estándar).
2. **Lectura de cookies sin bloqueo** con el navegador abierto, de forma legítima: servicio auxiliar con privilegios que use VSS bajo demanda, o extensión propia del navegador que exponga solo metadatos (nombre/dominio/caducidad vía `chrome.cookies.getAll` sin `value`).
3. **Sysmon for Linux / eBPF (Tetragon, Falco)**: sustituir `/proc` + `auditd` por eventos reales de ficheros y red; habilitar el indicador 7 en Linux.
4. **macOS** (rutas `~/Library/Application Support/...`, `launchd`, notificaciones `osascript`).
5. **Informe forense ampliado**: exportación STIX/Sigma-ready, línea de tiempo y firmas YARA de familias de stealer.
6. **Reglas Sigma propias** (carpeta `reglas/sigma/`) para tu SIEM: acceso a `Cookies`/`Login Data` por procesos no autorizados y depuración remota.
7. **Panel multi-equipo** para un CSIRT: agregación de informes JSON firmados, sin valores.
8. **Firma de código** de lanzadores y empaquetado como `.exe` (PyInstaller) / `.deb` / `.msi`; instalador sin Python.
9. **Detección de DBSC por sitio** (qué servicios ya protegen sus sesiones) y recomendaciones basadas en ello.
10. **Rotación asistida con comprobación**: verificar que la sesión antigua ya no es válida (requiere interacción con cada servicio: solo con consentimiento).
11. **Canary integrado** con webhook propio de Canarytokens y alerta en la interfaz.
12. **Telemetría opcional, local-first, a tu SIEM** (syslog/CEF) manteniendo "sin valores".
13. **Endurecimiento automático de `Preferences`** (borrar cookies al cerrar para sitios sensibles) con el navegador cerrado y copia previa.
14. Catálogo de servicios mantenido por la comunidad con verificación automática semanal de URLs.
