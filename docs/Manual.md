# Manual de usuario de CookieGuard

## 1. Qué hace (y qué no)
CookieGuard te enseña **qué sesiones tienes abiertas** en tus navegadores y **busca indicios** de que alguien las haya podido copiar.
No descifra ni muestra cookies ni contraseñas, y no se conecta a internet por su cuenta.

## 2. Instalación
**Windows**: doble clic en `Instalar.cmd`. Necesitas Python 3.8+ (si falta, el instalador te dice cómo ponerlo). Te preguntará, uno a uno:
1. Copiar el programa a `%LOCALAPPDATA%\CookieGuard\app`.
2. Crear la tarea *"al iniciar sesión"* (análisis con 45 s de retraso, sin ventana).
3. Activar la **auditoría de acceso a ficheros** (`auditpol`) y las **SACL** de lectura sobre los ficheros del navegador, y una tarea que las reaplica cuando aparezcan perfiles nuevos. Pide permisos de administrador **una sola vez** (UAC).
4. (Opcional) instalar **Sysmon** con `reglas\sysmon-cookieguard.xml`.
5. Accesos directos en el menú Inicio, y primer análisis (fija la línea base).

**Linux**: `./cookieguard.sh instalar`: autoarranque en `~/.config/autostart`, entrada de menú y (con tu permiso, usando `sudo`) reglas `auditd` en `/etc/audit/rules.d/cookieguard.rules`.

Puedes probar todo sin cambiar nada: `python -m cookieguard instalar --dry-run`.

## 3. Cómo leer el semáforo
| Color | Significa | Qué hacer |
|---|---|---|
| 🟢 Verde | Sin indicios | Nada. Recuerda: no es garantía. |
| 🟡 Amarillo (≥ 15 pts) | Hay indicios a revisar | Abre **Indicadores**, lee cada hallazgo y su explicación. |
| 🔴 Rojo (≥ 40 pts) | Posible robo de sesiones | Sigue el **Playbook**: aísla el equipo y rota sesiones desde un dispositivo limpio. |
Los umbrales y los puntos por indicador se cambian en `config/config.json` o en la pestaña **Ajustes**.
Un indicador **"Sin datos"** no suma puntos: te dice qué falta (administrador, Sysmon, auditoría…).

## 4. Los 12 indicadores
| # | Indicador | Qué significa en claro | MITRE |
|---|---|---|---|
| 1 | Procesos ajenos leyendo ficheros del navegador | Un programa que no es el navegador abrió `Cookies`, `Login Data`, `cookies.sqlite`, `key4.db`… Necesita la auditoría (instalación) | T1555.003, T1539 |
| 2 | Navegador lanzado de forma peligrosa | `--remote-debugging-port`, `--headless`, `--load-extension`, perfil en carpetas temporales, padre raro (powershell/python…) | T1539, T1185 |
| 3 | Acceso a la memoria del navegador | Alguien lee la memoria de Chrome/Edge (Sysmon 10); en Linux, `ptrace_scope` | T1055, T1003 |
| 4 | Abuso del cifrado App-Bound | Servicio de elevación fuera de lugar, herramientas tipo ChromeKatz | T1555.003 |
| 5 | Extensiones peligrosas | Permisos `cookies`, `<all_urls>`, `webRequest`, `debugger`…, nuevas, fuera de tienda, en modo desarrollador o forzadas por política | T1176 |
| 6 | Copias sospechosas de bases de datos | SQLite con tablas `cookies`/`logins` en Temp/AppData…; ZIP/TXT con nombres de stealer | T1074 |
| 7 | Conexiones de exfiltración | Caché DNS/Sysmon hacia Telegram API, webhooks de Discord, transfer.sh, ngrok… | T1567 |
| 8 | Microsoft Defender | Detecciones de familias de stealer, protección desactivada, exclusiones raras | T1562.001 |
| 9 | Persistencia nueva | Run/RunOnce, Inicio, tareas, servicios, WMI (Windows); autostart, cron, rc (Linux) frente a la línea base | T1547, T1053 |
| 10 | Ejecutables recientes sin firmar | En Descargas/Temp: firma Authenticode y marca de descarga (Windows); ELF/scripts nuevos (Linux) | T1204 |
| 11 | Manipulación de la red local | Proxy, certificados raíz nuevos, `hosts`, DNS | T1557 |
| 12 | Anomalías en las cookies | Muchas cookies críticas escritas a la vez (sobre todo de madrugada) | T1539 |

**Líneas base** (9, 11 y extensiones): la primera ejecución fija "lo normal". Los cambios posteriores avisan y **no** pasan a ser lo normal
hasta que tú los aceptes (*Ajustes → Aceptar cambios pendientes*), para que un atacante no se "normalice" solo.

## 5. La interfaz
- **Resumen**: semáforo, cifras, exportar (HTML/CSV/JSON, solo metadatos), modo incidente (ZIP).
- **Sesiones activas**: tabla ordenable (clic en la cabecera) con buscador y filtros: *solo críticos, caducan en más de un año, nuevas, sin uso > 90 días, zombie*. Doble clic en un servicio → sus acciones.
- **Indicadores**: detalle y explicación de cada uno; qué te falta para ver más.
- **Extensiones**: todas las de cada perfil con permisos y marcas.
- **Acciones / Rotación**: ver 6.
- **Historial**: ejecuciones anteriores. **Ajustes**: modo silencioso, vigilante, umbrales, procesos de confianza. **Ayuda**: estos manuales.

**Estados de una sesión**: *Vigente · Caduca pronto (≤ 7 días) · Sin uso desde hace X días · Caducada · Solo hasta cerrar el navegador*.
**Zombie** = caduca dentro de más de un año **y** sin uso en más de 90 días: la candidata ideal a revocar.
**Riesgo por servicio**: Alto/Medio/Bajo según criticidad, zombie, novedad y caducidad larga.

## 6. Acciones y rotación guiada
Para cada servicio: abrir *cerrar todas las sesiones*, *cambiar contraseña*, *2FA/passkeys* e *historial de accesos* (si el servicio no está en el
catálogo se abre una **búsqueda guiada**; verifica que la página es la oficial), **borrar cookies locales** y marcar como revisado.

⚠️ **Cambiar la contraseña no siempre invalida una cookie ya robada: cierra también TODAS las sesiones.** Hazlo desde un dispositivo limpio.

**Borrado local**: pide cerrar el navegador, hace **copia de seguridad** de las bases afectadas y borra las filas del servicio (en todos los navegadores). Se deshace en *Copias de seguridad → Restaurar*.
**Cerrar navegadores y borrar todas las cookies**: doble confirmación + copia.
**Asistente de rotación**: lista ordenada por criticidad (correo → gestor de contraseñas → SSO → banca/cripto → trabajo → nube → desarrollo → redes → resto), 4 pasos por servicio, barra de progreso, estado guardado entre sesiones.
**Hardening** (pestaña *Seguridad*): versión del navegador y soporte de DBSC, contraseñas guardadas en el navegador, "continuar donde lo dejaste", perfiles separados, passkeys, y en Windows Defender (tiempo real, antialteración, reglas ASR, PUA). Los marcados con `*` tienen botón *Aplicar/Deshacer* (requieren administrador).

## 7. Vigilante en tiempo real
Actívalo en *Ajustes* o con `vigilar`. Cada pocos segundos revisa procesos nuevos (casi sin coste: ≈ 1 % de CPU, ≈ 26 MB) y, con auditoría activa, los eventos 4663/Sysmon. Si salta una alerta puedes **suspender**, **matar**, **bloquear en el Firewall** (Windows, administrador; en Linux se retira el permiso de ejecución), ver **detalles** o marcar el programa **de confianza**.

## 8. Preguntas frecuentes
- **¿Puede ver mis contraseñas?** No: el código solo pide columnas de una lista blanca de metadatos y un test lo comprueba.
- **"Cookies bloqueada (error 32)".** Chrome/Edge abiertos bloquean su base. Cierra el navegador, o *Reintentar como administrador* (copia VSS), o deja que el análisis corra al iniciar sesión.
- **¿Por qué Discord/Telegram casi no aparecen?** Guardan el token fuera de las cookies; usa las notas del servicio.
- **Verde, ¿estoy a salvo?** No: lee `Limitaciones.md`.
- **Falsos positivos**: añade el proceso a *Procesos de confianza*; las apps Electron/WebView2 legítimas ya se ignoran.
- **¿Cómo desinstalo?** `Desinstalar.cmd` / `./cookieguard.sh desinstalar`.
