# Investigación (Fase 0)

Fecha: 21-11-2026. Las fuentes marcadas ✔ se consultaron en esta sesión; las marcadas ○ son referencias conocidas del
sector que **debes revisar tú** antes de citarlas en un informe (no se abrieron en esta sesión).

## 1. Qué roban los infostealers y cómo
- **Cookies de sesión (MITRE T1539)** y **credenciales del navegador (T1555.003)**: las familias LummaC2, Vidar, StealC,
  RedLine, Rhadamanthys, Meduza, Phemedrone, WhiteSnake… leen las bases `Cookies`/`Login Data`/`Web Data`/`Local State`
  (Chromium) o `cookies.sqlite`/`logins.json`/`key4.db` (Firefox) y las envían (Telegram, webhooks, paneles C2).
- **Chrome App-Bound Encryption (ABE)** (Chrome 127+, Windows): ata la clave de cifrado al propio Chrome mediante un servicio
  de elevación. Los stealers lo han rodeado de varias formas (✔ [Elastic Security Labs](https://www.elastic.co/security-labs/katz-and-mouse-game),
  ✔ [Zscaler](https://www.zscaler.com/blogs/cybersecurity-best-practices/google-chrome-app-bound-encryption),
  ✔ [SpyCloud](https://spycloud.com/blog/infostealers-bypass-new-chrome-security-feature/),
  ✔ [Red Canary](https://redcanary.com/blog/threat-intelligence/google-chrome-app-bound-encryption/)):
  1. **Depuración remota**: lanzar Chrome con `--remote-debugging-port` y pedir las cookies ya descifradas por CDP
     (observado en Stealc y Vidar; también PHEMEDRONE). → *Indicador 2*.
  2. **Lectura de memoria (ChromeKatz)**: escanear la memoria del proceso del navegador (Stealc integró ese enfoque). → *Indicador 3*.
  3. **COM al servicio de elevación**: elevarse a SYSTEM y llamar a `DecryptData` del `GoogleChromeElevationService`. → *Indicador 4*.
  4. **Política de registro** para desactivar ABE y reiniciar el navegador. → *Indicador 4/11* (cambios de políticas).
  5. Casi todos los bypasses antiguos necesitaban administrador; hay variantes nuevas (VoidStealer, Krejsa) sin detalle verificado aquí.
- **Reutilización de la cookie** desde otra máquina = secuestro de sesión: contramedida de fondo, **DBSC**.

## 2. Contramedidas del lado del navegador/servicio
- **Google DBSC (Device Bound Session Credentials)**: ✔ [anuncio para Windows](https://developer.chrome.com/blog/dbsc-windows-announcement),
  ✔ [Google Security Blog](https://blog.google/security/protecting-cookies-with-device-bound-session-credentials/),
  ✔ [The Hacker News](https://thehackernews.com/2026/04/google-rolls-out-dbsc-in-chrome-146-to.html),
  ✔ [Workspace Updates (mayo 2026)](https://workspaceupdates.googleblog.com/2026/05/prevent-account-takeovers-with-DBSC-now-generally-available-in-the-Chrome-browser-for-Windows.html).
  Chrome 146 lo trae a Windows; la clave vive en el TPM y el servidor exige prueba de posesión, así que una cookie robada deja de servir.
  Si el equipo no tiene almacenamiento seguro de claves, vuelve al comportamiento clásico (hueco). Solo protege sitios que lo implementen (Google Workspace, etc.).
  *Uso en CookieGuard*: pestaña Acciones → Seguridad comprueba la versión de Chrome.
- ○ **Microsoft Entra Token Protection** (vincula tokens de sesión al dispositivo en Windows): mitiga el mismo problema en entornos Microsoft 365; es de administrador, no de usuario final.
- **Passkeys/FIDO2**: contra phishing; no evitan el robo de una sesión ya iniciada, pero reducen el riesgo de la reutilización.

## 3. Detección: qué se mira y de dónde sale
| Idea | Fuente | Uso en CookieGuard |
|---|---|---|
| Proceso que no es el navegador abre ficheros de credenciales del navegador (evento 4663 con SACL) | ✔ [Splunk: acceso a perfil Chrome por procesos no-Chrome](https://research.splunk.com/endpoint/81263de4-160a-11ec-944f-acde48001122) | Indicador 1 (whitelist editable) |
| Línea de comandos con `Login Data`/`Cookies`/`logins.json`/`key4.db` | ✔ [Elastic: Access of Stored Browser Credentials](https://www.elastic.co/guide/en/security/8.19/prebuilt-rule-8-4-2-access-of-stored-browser-credentials.html) (T1555/T1539) | Indicador 1 + reglas Sysmon (FileCreate) |
| Sysmon 1/3/10/11/22 con config mínima | ○ [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config), ○ [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular) | `reglas/sysmon-cookieguard.xml` |
| Reglas Sigma genéricas (T1555.003) | ○ [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) (carpeta `rules/windows`) | Referencias en `Tecnico.md` |
| Técnicas MITRE | ○ [T1539](https://attack.mitre.org/techniques/T1539/), ○ [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | Etiquetas en cada indicador |
| Cookies/tokens señuelo | ○ [Canarytokens](https://canarytokens.org) | Fase 7 (opcional) |
| ChromeKatz (lectura de cookies de memoria) | ○ [Meckazin/ChromeKatz](https://github.com/Meckazin/ChromeKatz) | Indicadores 3 y 4 (nombre de herramienta) |

Nota de honestidad: **no encontré una regla Sigma publicada** que cubra "acceso a ficheros del navegador" solo con Sysmon
(Sysmon no registra lecturas de fichero por defecto); por eso CookieGuard usa auditoría de Windows (4663+SACL) y, en Linux, `auditd`/`/proc`.

## 4. Rutas y esquemas de bases de datos de cookies (verificadas en el código y en el equipo de pruebas)
**Windows** (`%LOCALAPPDATA%` salvo Opera):
| Navegador | Ruta de la raíz | Cookies |
|---|---|---|
| Chrome / Beta / Canary | `Google\Chrome[ Beta\| SxS]\User Data` | `<perfil>\Network\Cookies` |
| Edge | `Microsoft\Edge\User Data` | `<perfil>\Network\Cookies` |
| Brave | `BraveSoftware\Brave-Browser\User Data` | idem |
| Vivaldi / Chromium / Yandex | `Vivaldi\User Data`, `Chromium\User Data`, `Yandex\YandexBrowser\User Data` | idem |
| Opera / Opera GX | `%APPDATA%\Opera Software\Opera Stable` / `Opera GX Stable` | `Network\Cookies` en la propia raíz |
| Arc | `Packages\TheBrowserCompany.Arc_*\LocalCache\Local\Arc\User Data` | idem |
| Firefox / LibreWolf / Waterfox | `%APPDATA%\Mozilla\Firefox` (+`profiles.ini`) | `<perfil>\cookies.sqlite` |

**Linux**: `~/.config/{google-chrome,chromium,microsoft-edge,BraveSoftware/Brave-Browser,vivaldi,opera,yandex-browser}`,
snap `~/snap/chromium/common/chromium`, flatpak `~/.var/app/<app>/config/...`; Firefox en `~/.mozilla/firefox`
(snap: `~/snap/firefox/common/.mozilla/firefox`, flatpak: `~/.var/app/org.mozilla.firefox/.mozilla/firefox`).
Además se busca cualquier `*/Local State` en `~/.config` y cualquier `User Data` en `%LOCALAPPDATA%` (otros Chromium).

**Esquema Chromium** (tabla `cookies`): `creation_utc, host_key, name, path, expires_utc, is_secure, is_httponly,
last_access_utc, has_expires, is_persistent, samesite, source_scheme, last_update_utc`… (+ `value`/`encrypted_value`, **que CookieGuard nunca pide**).
Fechas: microsegundos desde 1601-01-01 UTC (0 = sin caducidad/sesión).
**Esquema Firefox** (`moz_cookies`): `host, name, path, expiry` (segundos Unix; las versiones recientes pueden usar ms → se detecta),
`lastAccessed` y `creationTime` (microsegundos Unix), `isSecure, isHttpOnly, sameSite`.
**Hallazgo práctico**: con Chrome/Edge **abiertos**, `Cookies` está bloqueada (error 32 de compartición) incluso con `FileShare.ReadWrite`.
Soluciones sin tocar la memoria del navegador: ejecutar al iniciar sesión (aún no abierto), cerrar el navegador, o copiar con **Volume Shadow Copy** (`esentutl /y /vss`, requiere administrador). CookieGuard hace las tres cosas y lo indica en la interfaz.

## 5. URLs de "cerrar sesiones / cambiar contraseña / 2FA"
Están en `catalogo/servicios.json` (≈40 servicios, 147 enlaces). Se comprobaron con `tools/verificar_urls.py` el 21-11-2026:
140 respondían a la primera; de las 7 con fallo, 6 eran un problema del verificador (ING, Telegram responden con otro cliente) y 1
estaba mal (2FA de Google) y se corrigió. Los bancos y algunos servicios solo tienen enlace a la portada (no existe URL directa estable):
la nota del servicio indica la ruta del menú. Vuelve a ejecutar la herramienta de vez en cuando: **las URLs cambian**.

## 6. Ideas aprovechadas / descartadas
- ✔ Línea base + diferencias (persistencia, extensiones, red) → evita falsos positivos por "lo que siempre estuvo ahí".
- ✔ Nivel de riesgo con puntuación editable en lugar de veredicto binario.
- ✔ Solo metadatos: una herramienta de defensa no debe poder usarse como stealer (test automático).
- ✘ Descifrar cookies para "ver" qué sesiones son válidas: descartado por principio.
- ✘ Inyección/lectura de memoria del navegador para evitar el bloqueo de ficheros: descartado (es la técnica del atacante).
