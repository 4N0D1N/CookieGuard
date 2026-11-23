# Documento técnico

## Arquitectura
```
                 ┌────────────── gui.py (tkinter) ──────────────┐
 __main__.py ──► │ engine.run_analysis ──► inventory ──► sqlite_meta (copia + lista blanca de columnas)
 (CLI)           │          │                 └► classifier (catalogo/servicios.json)
                 │          ├► detections.run_all (12 indicadores, en paralelo)
                 │          ├► risk.evaluate (puntos → semáforo, config.json)
                 │          └► reports (HTML/CSV/JSON) · notify (toast/notify-send)
 watcher.py (vigilante) · actions.py (URLs, borrado+copia, rotación, incidente, hardening)
 installer.py (tarea/autostart, auditpol+SACL, auditd, Sysmon, accesos directos) · canary.py
```
Solo **librería estándar de Python** (sqlite3, tkinter, ctypes, winreg, zipfile…). Sin dependencias, sin red.

### Fuentes de datos
| Fuente | Qué | Plataforma |
|---|---|---|
| Copia temporal de `Cookies`/`cookies.sqlite` (+`-wal`/`-journal`) | metadatos | ambas |
| `Preferences`, `Extensions\*\manifest.json`, `extensions.json` | extensiones y ajustes | ambas |
| Procesos: CIM `Win32_Process` / `/proc` | flags, padre, ruta | ambas |
| Registro de eventos: Security 4663/4656/4688; Sysmon 1,3,10,11,22 (`wevtutil`) | historial | Windows |
| `ipconfig /displaydns`, registro (Run, proxy), `Get-ScheduledTask`, WMI | red y persistencia | Windows |
| `Get-MpThreatDetection`, `Get-MpComputerStatus`, `Get-MpPreference` | Defender | Windows |
| `/proc/*/fd`, `auditd` (`ausearch -k cookieguard`), `crontab`, autostart | acceso a ficheros y persistencia | Linux |

### Lectura segura (`sqlite_meta.py`)
1. **Lista blanca** `ALLOWED_COLUMNS` (solo metadatos) y `ALLOWED_TABLES`; cualquier otra columna → `ValueError`.
2. **Copia**: Windows `CreateFileW` con `FILE_SHARE_READ|WRITE|DELETE` (equivale a `FileShare.ReadWrite`); si el fichero está bloqueado (error 32) y hay admin, `esentutl /y /vss`. Linux `copyfile`. Se copian `-wal`/`-journal`/`-shm` y la carpeta temporal se borra siempre.
3. **Tests** (`tests/test_seguridad.py`): la lista blanca no contiene columnas de valor; el código no menciona `encrypted_value`/`password_value`; no hay `SELECT … value`; no se importan módulos de red; con una BD que contiene un **valor centinela** ningún informe, CSV, JSON, ZIP ni log lo contiene.

### Fechas
Chromium: µs desde 1601-01-01 UTC (`0` = sesión/sin caducidad, valores > 2⁵⁶ → "nunca"). Firefox: `expiry` en s (ms en versiones recientes: se detecta por magnitud), `lastAccessed`/`creationTime` en µs Unix. Todo se pasa a hora local.

### Puntuación (`config/config.json`)
Cada indicador devuelve una fracción 0–1 de gravedad × puntos máximos (`puntos`). Suma de indicadores en *alerta*; Amarillo ≥ `umbrales.amarillo` (15), Rojo ≥ `umbrales.rojo` (40). Los *sin_datos* no suman.

## Lógica de cada detección (con referencias)
| # | Lógica | Referencias |
|---|---|---|
| 1 | Windows: eventos 4663/4656 con `ObjectName` ∈ {Cookies, Login Data, Web Data, Local State, cookies.sqlite, logins.json, key4.db} y `ProcessName` fuera de la whitelist. Linux: `/proc/<pid>/fd` → fichero sensible; `auditd` clave `cookieguard`. | MITRE T1555.003, T1539; Splunk "non-Chrome access to Chrome profile"; Elastic "Access of Stored Browser Credentials" |
| 2 | Flags `--remote-debugging-port/pipe`, `--remote-allow-origins`, `--headless`, `--load-extension`, `--user-data-dir` a carpetas temporales; padre ∈ intérpretes. Histórico: Sysmon 1 / 4688. Se ignoran shells/`grep` que solo citan el texto. | Elastic "Katz and Mouse", Zscaler (Stealc/Vidar) |
| 3 | Sysmon 10 con `TargetImage` = navegador/`elevation_service`; Linux `ptrace_scope`. | ChromeKatz; T1055 |
| 4 | Servicio `*Elevation*` fuera de Program Files, `elevation_service.exe` fuera de ruta, nombres de herramientas (`chromekatz`, `chrome_decrypt`…), Sysmon 10 al servicio. | Red Canary, Zscaler (ABE) |
| 5 | Permisos peligrosos × (nueva / modo dev / fuera de tienda / forzada por política `ExtensionInstallForcelist` en HKLM/HKCU o `/etc/opt/chrome/policies`). | T1176 |
| 6 | Recorrido (prof. ≤ 4, ≤ 40 000 ficheros, ≤ 25 s) de Temp, AppData, ProgramData, Public, Descargas: cabecera SQLite + tablas `cookies/moz_cookies/logins/autofill/credit_cards` (solo `sqlite_master`), TXT Netscape, ZIP con nombres de stealer. Se ignoran perfiles de apps Chromium/Electron (hay `Local State`/`Preferences` cerca). | T1074 |
| 7 | Caché DNS (`ipconfig /displaydns`) y Sysmon 3/22 contra `catalogo/destinos-exfil.json`. | T1567 |
| 8 | `Get-MpThreatDetection` + `Get-MpThreat` con regex de familias; RTP/antialteración; exclusiones en rutas de usuario. | T1562.001 |
| 9 | Instantánea (Run/RunOnce, Inicio, tareas no-Microsoft, servicios fuera de Windows/Program Files, WMI | autostart, cron, rc) comparada con la línea base. | T1547, T1053, T1546.003 |
| 10 | Ejecutables ≤ 14 días en Descargas/Temp: `Get-AuthenticodeSignature` + ADS `Zone.Identifier`; Linux ELF/shebang con bit x. | T1204, T1553.005 |
| 11 | Proxy (registro/entorno), certificados raíz, `hosts` (redirecciones de servicios conocidos), DNS: diferencias con la línea base. | T1557, T1553.004 |
| 12 | ≥ 6 servicios críticos con cookies creadas/actualizadas en la misma ventana de 2 min (más puntos de madrugada). | T1539 |

Sigma/Elastic/Splunk: no se publicó una regla Sigma de "acceso a ficheros del navegador" solo con Sysmon; ver `Investigacion.md`.

## Vigilante
Bucle cada `vigilante_intervalo_s` (10 s). Windows: `CreateToolhelp32Snapshot` (nativo) y PowerShell **solo** para procesos nuevos; Security 4663 y Sysmon 10 si hay acceso. Linux: `/proc`. Alertas en `alertas.jsonl` y ventana (`python -m cookieguard.watcher --alerta <json>`). Suspender: `NtSuspendProcess`/`SIGSTOP`; matar: `taskkill`/`SIGKILL`; bloqueo: `netsh advfirewall` (nombre `CookieGuard bloqueo <exe>`, registrado en el estado para borrarlo al desinstalar). Medido en este equipo: **≈ 1 % de CPU y ≈ 26 MB**; alerta de depuración remota en **< 2 s**.

## Instalación / auditoría
- Windows: tarea `CookieGuard-InicioSesion` (ONLOGON, retraso 45 s, `pythonw`, nivel limitado); `auditpol /set /subcategory:{0CCE921D-69AE-11D9-BED3-505054503030} /success:enable` (se guarda el estado anterior); SACL `Everyone / ReadData / Success` en los ficheros sensibles (`sacl_ficheros` en el estado); tarea `CookieGuard-ReaplicarSACL` (ONLOGON, HIGHEST) que la reaplica. Desinstalar revierte todo.
- Linux: `~/.config/autostart/cookieguard.desktop`; reglas `-w <fichero> -p r -k cookieguard` en `/etc/audit/rules.d/`.
- **Firma de scripts**: no se firman (Python). Mitigación: tareas con ruta fija a la carpeta del usuario con permisos restringidos (`icacls /inheritance:r`) y lanzadores `.pyw` generados en la instalación. Opcional: firmar los `.cmd` con un certificado de código propio (`signtool`).

## Ampliar los catálogos
- **Servicios** (`catalogo/servicios.json`): añade `{id, nombre, categoria, dominios[], cookies[], urls{sesiones,password,seguridad,historial}, nota}`. Categorías y su orden de rotación: `categorias_orden`; críticas: `categorias_criticas`. Prueba con `python tools/verificar_urls.py`.
- **Destinos de exfiltración** (`catalogo/destinos-exfil.json`): `dominios[{patron,tipo,peso}]`, `archivos_stealer`, `herramientas_abe`.
- **Procesos de confianza**: pestaña Ajustes o `whitelist_procesos` en la configuración.
- **Reglas Sysmon**: `reglas/sysmon-cookieguard.xml`; actualizar con `sysmon64 -c`.
- **Nuevo indicador**: función `iNN(ctx)` en `detections.py` que devuelve el dict estándar y se añade a `INDICATORS` y a `config.json` (`puntos`).

## Pruebas
`python -m unittest discover -s tests` (32 pruebas) y `tests/simulaciones/simular.py` (5 simulaciones benignas con limpieza). Se usan `unittest` en lugar de Pester para ser multiplataforma y sin instalar nada.
