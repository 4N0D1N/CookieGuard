# PROGRESO

**Estado: COMPLETADO (v1.0.0) — pendiente solo de tu verificación en tu equipo (ver CHECKLIST-VERIFICACION.md).**

| Fase | Estado | Notas |
|---|---|---|
| 0 Investigación y diseño | ✅ | `docs/Investigacion.md` (fuentes ✔ verificadas / ○ por revisar), estructura, DECISIONES |
| 1 Motor e inventario | ✅ | Chromium+Firefox, Windows+Linux, catálogo ≈40 servicios, zombies, nuevas, informe HTML |
| 2 Detecciones y semáforo | ✅ | 12 indicadores, puntos en `config.json`, toast/notify-send |
| 3 Interfaz | ✅ | 8 pestañas, filtros, ordenación, exportación (HTML/CSV/JSON). Sin icono de bandeja (ver MEJORAS) |
| 4 Acciones y rotación | ✅ | URLs (147, 140 OK + 7 revisadas), borrado con copia y restauración, asistente con progreso, incidente, hardening |
| 5 Instalación/arranque | ✅ código y `--dry-run` probados · ⏳ instalación real **no ejecutada** (requiere tu OK) |
| 6 Vigilante | ✅ medido ≈1 % CPU, 26 MB; alerta de depuración remota < 2 s · ⏳ prueba con auditoría real pendiente de instalación |
| 7 Canary | ✅ asistente (opcional, desactivado) |
| 8 Pruebas | ✅ 32 tests OK · 5 simulaciones (4 OK, 1 omitida en Windows sin auditoría) · revisión de seguridad |
| 9 Documentación y entrega | ✅ README, Manual, Playbook, Limitaciones, Tecnico; `CookieGuard.zip` |

## Cómo retomar
Si se corta la sesión y dices "continúa": lee este fichero y `MEJORAS-FUTURAS.md`. Lo que queda realmente pendiente es **tuyo**:
1. Ejecutar la checklist (A→F), sobre todo C (instalación real con UAC) y la prueba del indicador 1 con auditoría.
2. Probar en una máquina Linux real (aquí solo se pudo en Windows; el código de Linux está escrito y cubierto por los tests portables).
3. Probar con usuario sin privilegios.

## ⚠️ No verificado todavía (sé honesto contigo mismo al validar)
- **Lectura de cookies con Chrome/Edge abiertos**: en mi prueba real dieron error 32 (0 cookies leídas) y la herramienta lo avisa en el semáforo ("lectura incompleta"). La lectura de Chromium/Firefox está probada con perfiles de prueba (tests), **no con tus bases reales**. Se comprueba al iniciar sesión (navegador aún cerrado), con el navegador cerrado, o con el botón *Reintentar como administrador* (VSS). Pendiente: A del checklist.
- Instalación real, auditoría 4663/SACL, Sysmon, firewall, tarea al inicio de sesión: **no ejecutados** (necesitan tu OK/UAC).
- Linux: código escrito y tests portables en verde, pero sin ejecutar en un Linux real.
- Interfaz: arranca y se cierra sin errores (prueba de humo), pero no la he visto renderizada con un clic real.

## Resultados clave de esta sesión
- Primera ejecución real: detectó Chrome y Edge, y expuso 2 falsos positivos (apps Electron/WebView2; shells que citan flags) ya corregidos con tests.
- Hallazgo: Chrome/Edge abiertos bloquean `Cookies` (error 32) → plan: ejecutar al iniciar sesión, cerrar navegador o VSS con admin.
- Análisis completo ≈ 25 s (< 60 s objetivo).
