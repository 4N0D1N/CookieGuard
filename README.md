# 🛡️ CookieGuard

> **Auditor local heurístico de metadatos de sesiones de navegador, con alertas y herramientas de respuesta guiada. No descifra valores de cookies y no sustituye a un EDR o antivirus.**

![Versión](https://img.shields.io/badge/Versi%C3%B3n-1.8.0-blue)
[![CI CookieGuard](https://github.com/4N0D1N/CookieGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/4N0D1N/CookieGuard/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Plataformas](https://img.shields.io/badge/Plataformas-Windows%20%7C%20Linux-brightgreen)
![Privacidad](https://img.shields.io/badge/Privacidad-Local--first-blue)
![Dependencias](https://img.shields.io/badge/Core-Solo%20stdlib-orange)
![Licencia](https://img.shields.io/badge/Licencia-MIT-purple)

---

## 🎮 Demos y Simulaciones Interactivas en Vivo (Prueba online en tu navegador)

Puedes explorar simulaciones interactivas sin instalar nada. Son demostraciones visuales, no sensores conectados al equipo ni pruebas de detección real:

- 🌐 **[Abrir Centro de Demos en Vivo (GitHub Pages)](https://4n0d1n.github.io/CookieGuard/)**
- 🖥️ **[Lanzar Demo Windows 11 Online](https://4n0d1n.github.io/CookieGuard/docs/simulaciones/simulacion_incidente_windows.html)** *(Recrea el Toast nativo flotante de Windows 11, telemetría DPAPI, triaje forense y Killswitch de red)*
- 🐧 **[Lanzar Demo Linux Desktop Online](https://4n0d1n.github.io/CookieGuard/docs/simulaciones/simulacion_incidente_linux.html)** *(Recrea la alerta D-Bus notify-send, trazado de descriptores en /proc/[pid]/fd y aislamiento con iptables/nftables)*

*(Ambas simulaciones son interactivas en HTML5/Tailwind, ejecutables en cualquier navegador tanto online vía GitHub Pages como offline abriendo los archivos locales).*

---

## 🎯 Qué hace CookieGuard

CookieGuard inspecciona metadatos locales de perfiles de navegador y presenta señales heurísticas para ayudar a priorizar una revisión. Puede generar informes y snapshots, preparar enlaces o scripts de respuesta y ofrece demos de interfaz.

**Importante:** las alertas no confirman por sí solas un robo. La vigilancia de acceso a archivos depende de la plataforma y del método de sondeo; no hay bloqueo universal de lectura en tiempo real. Las acciones de revocación requieren que la persona use los sitios oficiales; los canary DNS requieren dominio y monitoreo propios. Los módulos marcados como experimentales o simulados no deben interpretarse como protección garantizada.

---

## 🔒 Principios de Privacidad y Seguridad (Zero-Trust)

- **Local-first:** el análisis base es local y puede ejecutarse sin red. Las funciones de actualización de IoCs y notificaciones externas usan red solo cuando se configuran o activan.
- **Solo metadatos de cookies:** el análisis no descifra ni muestra los valores de cookies ni contraseñas. Los snapshots pueden contener otros datos del sistema; revisa su contenido antes de compartirlos.
- **Dependencias:** el analizador base usa la biblioteca estándar. El cifrado AES-GCM de snapshots requiere la dependencia opcional `cryptography`; consulta `requirements-forensics.txt`.

---

> **Nota de alcance:** los apartados históricos de versiones anteriores describen funciones y prototipos de esas entregas; no constituyen una certificación independiente. Para los límites de las funciones revisadas, consulta la sección v1.6.0 y `CHECKLIST-VERIFICACION.md`.

## 🚀 Novedades de la Versión 1.1.0

- **🛡️ Killswitch de Red:**
  - Bloqueo instantáneo de tráfico saliente mediante reglas nativas de firewall de Windows (`netsh advfirewall`) o `nmcli`/`iptables` en Linux.
  - Opción de auto-activación ante detección confirmada (semáforo rojo).
- **🐤 Canary Cookies Activas (Indicador I13):**
  - Siembra de cookies trampa locales en Chromium y Firefox con nombres señuelo creíbles (`corp_vault_session`, `admin_sso_token`).
  - Detección de lectura no autorizada o borrado por parte del stealer.
- **📱 Notificaciones Webhook Seguras:**
  - Notificaciones de emergencia a ntfy.sh o Discord sin bibliotecas externas, garantizando que el payload contiene **únicamente** metadatos forenses anonimizados.
- **🖥️ Simulaciones Visuales Windows y Linux:**
  - Demos interactivas en `docs/simulaciones/` listas para abrir en cualquier navegador moderno.

---


## 🚀 Novedades de la Versión 1.8.0

- **🔐 Auditoría de certificados raíz y proxies locales (`cookieguard certs`):**
  - Detecta certificados CA de intercepción TLS (Adversary-in-the-Middle / MITM, MITRE ATT&CK T1557 / T1556) instalados en el almacén `ROOT` de Windows o en el sistema (Fiddler, Charles, Burp Suite, mitmproxy, mkcert, OWASP ZAP).
  - Identifica proxies locales (`127.0.0.1`, `localhost`) activos en variables de entorno (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) o en el registro de Windows (`HKCU\...\Internet Settings`), así como ficheros PAC automáticos no autorizados.
- **🗄️ Integridad forense de bases de datos SQLite y Time-Stomping (`cookieguard db-integrity`):**
  - Inspecciona la cabecera física (magic bytes `SQLite format 3\000`), el tamaño de página y el estado de integridad lógica (`PRAGMA quick_check`).
  - Detecta técnicas de *Time-Stomping* y manipulación: alerta si la marca de tiempo del archivo WAL/SHM está desincronizada respecto a la base de datos principal.
  - Alerta ante anomalías de *freelist* (más del 40% de páginas libres), indicio de borrado masivo de registros para eliminar huellas tras exfiltración.
- **🧩 Escáner heurístico de código de extensiones (`cookieguard scan-extensions`):**
  - Escanea scripts `.js`, `.json` y `.html` en extensiones instaladas buscando patrones de exfiltración e inyección C2:
    - Webhooks de Discord (`discord.com/api/webhooks/...`).
    - Bots de Telegram C2 (`api.telegram.org/bot.../sendMessage`).
    - Extracción masiva de cookies por API (`chrome.cookies.getAll`, `browser.cookies.getAll`, `sendBeacon`).
    - Inyección y ofuscación dinámica (`eval(atob(...))`, `debugger.attach`).
- **💻 Cobertura ampliada de aplicaciones de escritorio SaaS y Electron:**
  - Nuevos objetivos en el auditor de sesiones de escritorio (`cookieguard desktop`): **Postman Desktop** (tokens de API Bearer y variables de entorno críticas), **Slack Desktop**, **Obsidian Desktop** y **Notion Desktop**.

---

## 🚀 Novedades de la Versión 1.7.0

- **🔗 Auditoría de accesos directos e inicio (`cookieguard shortcuts`):**
  - Analiza accesos directos `.lnk` (Windows) y `.desktop` (Linux) en el Escritorio, Menú de Inicio, Barra de Tareas y carpetas de autostart.
  - Detecta técnicas de persistencia y secuestro (*Browser Shortcut Hijacking*, MITRE ATT&CK T1547 / T1059 / T1204): inyección de flags anómalos (`--load-extension`, `--proxy-server`, `--disable-web-security`, `--remote-debugging-port`), ejecutables en carpetas temporales o wrappers intermediarios (`powershell`, `cmd /c`, `mshta`, `bash`, `curl`).
  - Salida humana estructurada o en JSON con `--json`.
- **🔄 Auditoría de sincronización y cuentas de perfil (`cookieguard sync`):**
  - Inspecciona la configuración de sincronización en `Preferences` (Chromium/Edge) y `signedInUser.json` / `prefs.js` (Firefox).
  - Identifica qué cuentas están vinculadas al navegador, si la sincronización hacia la nube está activa y qué datos se replican (contraseñas, cookies, historial, extensiones).
  - Alerta ante anomalías como múltiples cuentas en un mismo perfil o perfiles sin cuenta identificable pero con sync activo.
  - Anonimización/enmascaramiento de direcciones de correo por defecto para auditorías externas (`--sin-anonimizar` para inspección forense interna).
- **📋 Playbooks interactivos de revocación y triage (`cookieguard playbook`):**
  - Catálogo integrado con más de 35 servicios críticos (Google Workspace, Microsoft 365, AWS, GitHub, Slack, Discord, Stripe, PayPal, Binance, OpenAI, etc.).
  - **Checklist HTML offline interactiva (`checklist_revocacion.html`):** Interfaz responsive auto-contenida (sin CDNs ni dependencias) con enlaces directos a consolas de "Cerrar sesión en todos los dispositivos", cambio de contraseña y permisos OAuth. Guarda el progreso en el `localStorage` del navegador.
  - **Guía de respuesta en Markdown (`PLAYBOOK_REVOCACION.md`):** Formato estructurado con tareas de contención para adjuntar a incidencias del SOC o tickets de soporte.

---

## 🛡️ Novedades de seguridad de v1.6.0

- **Snapshots con privacidad por defecto:** anonimiza usuario, hostname, emails y cadenas que parezcan credenciales. No es anonimización completa: conserva marcas de tiempo, direcciones IP y otros metadatos necesarios para el análisis; revisa el ZIP antes de compartirlo.
- **Cifrado autenticado opcional:** `cookieguard snapshot --cifrar` usa AES-256-GCM mediante `cryptography` y una derivación PBKDF2-HMAC-SHA256. Para el código fuente instala `python -m pip install -r requirements-forensics.txt`; el analizador básico no requiere esa dependencia. Descifra con `cookieguard snapshot-descifrar archivo.cgenc`. No se implementa criptografía propia.
- **Export STIX 2.1 conservador:** los hallazgos heurísticos se exportan como notas de incidente y referencias MITRE. No se fabrican indicadores de compromiso ni se presentan heurísticas como IoCs confirmados.
- **DNS canary manual:** genera un nombre único bajo un dominio que controles y compara una lista de consultas DNS local. No despliega señuelos ni recibe callbacks externos por sí solo; una alerta externa requiere DNS autoritativo y monitoreo que configures y controles.
- **Honeypot más seguro:** CookieGuard no reutiliza ni sobrescribe la carpeta señuelo si ya existe; la limpieza solo elimina artefactos intactos con marcador e hashes coincidentes. Si el señuelo fue alterado o tiene archivos adicionales, se preserva.

### Límites que deben quedar claros

El honeypot es un indicador heurístico, no un detector de lectura universal ni en tiempo real: la comprobación de descriptores abiertos existe en Linux y la detección de cambios depende del sondeo; Windows no ofrece aquí vigilancia fiable de lecturas. La auditoría de memoria/DLL es heurística y no certifica ausencia de malware. No hay driver de kernel, bloqueo activo de lectura ni callback DNS gestionado por CookieGuard. Las demos de `docs/simulaciones/` son simulaciones, no sensores reales.

## 🚀 Novedades de la Versión 1.4.0

- 🔄 **Threat Intelligence & Auto-actualización de IoCs (Indicador I16):**
  - Base de datos activa con hashes SHA-256 de stealers (LummaC2, Stealc, Vidar, RedLine, Meduza), nombres de ejecutables sospechosos y dominios/IPs de C2.
  - **Actualización automática en segundo plano:** Descarga periódica de feeds de IoCs directamente desde GitHub con verificación de integridad y control de frecuencia (TTL 24h).
  - **100% fiel a la política de privacidad:** Cero módulos de red en Python (utiliza curl nativo en Linux o PowerShell en Windows) y modo offline-first instantáneo si no hay red.
- 💬 **Auditoría de Sesiones de Apps de Escritorio y Wallets (Indicador I17):**
  - Ampliación de la cobertura más allá del navegador: detecta e inventaría sesiones activas de **Telegram Desktop, Discord** y monederos de criptomonedas (**Exodus, Electrum, Atomic Wallet, Steam**).
  - Identifica modificaciones anómalas o accesos recientes a tokens de escritorio típicamente codiciados por stealers.
- 🧩 **Auditor de Extensiones del Navegador:**
  - Inspecciona todas las extensiones instaladas en perfiles Chromium y Firefox.
  - Clasifica niveles de riesgo según permisos sensibles (all_urls, webRequest, cookies, debugger).
  - Ejecutable con `python -m cookieguard extensions`.
- 🧪 **Simulador Seguro de Ataques (Test Harness):**
  - Permite verificar el correcto funcionamiento de las alertas, notificaciones del sistema y el panel de triaje sin poner en riesgo datos reales.
  - Crea una base de datos señuelo en memoria/directorio temporal y emula una tentativa de exfiltración.
  - Ejecutable con `python -m cookieguard simular`.
- ⚙️ **Gestor de Servicio en Segundo Plano:**
  - Instalador/desinstalador automático del vigilante como Tarea Programada nativa en Windows (`schtasks`) o servicio de usuario `systemd` en Linux (`cookieguard.service`).
  - Ejecutable con `python -m cookieguard service install | status | uninstall`.
- 📊 **Emisor de Eventos SIEM y Syslog:**
  - Emite alertas estructuradas en formato JSON Lines (`data/logs/cookieguard_siem.jsonl`) y formato estándar CEF (Common Event Format) para integración con Wazuh, Splunk, Elastic y Microsoft Sentinel.

---

## 🚀 Novedades de la Versión 1.3.0

- **📦 Ejecutable Standalone "Doble Clic" (.exe Windows y binario Linux):**
  - Ya no es necesario tener Python instalado. Se compila automáticamente mediante GitHub Actions y se distribuye como `CookieGuard.exe` listo para usar.
- **🚨 Modo Rescate y Triaje Forense USB:**
  - Nuevos scripts `Rescate-USB.cmd` (Windows) y `rescate-usb.sh` (Linux) para ejecutar CookieGuard desde un pendrive en equipos sospechosos de infección.
  - **Cero huella en disco:** Todos los informes y evidencias se escriben en el propio pendrive sin tocar el disco del sistema víctima.
  - Genera automáticamente `URGENTE_ROTAR_CLAVES.txt` con un checklist claro y enlaces directos de revocación de sesiones para usar desde un móvil seguro.
- **🕵️ Process Hunter (Indicador I15 - Infostealer Hunter):**
  - Escaneo de memoria activa en tiempo real: identifica troyanos en ejecución con nombre y PID.
  - Detección de familias de malware comunes (**LummaC2, Stealc, RedLine, Vidar, Meduza**).
  - Alerta de suplantación de procesos del sistema (**Masquerading T1036** como `svchost.exe` fuera de System32).
  - Sugerencia de comando inmediato para detener el proceso malicioso (`taskkill /F /PID ...` / `kill -9 ...`).

## 📂 Estructura del Repositorio

```text
CookieGuard/
├── README.md                           # Documentación general y arquitectura
├── LICENSE                             # Licencia MIT
├── .gitignore                          # Filtros de archivos temporales
├── config/
│   └── config.json                     # Configuración de umbrales, listas blancas y módulos
├── cookieguard/                        # Núcleo Python multiplataforma
│   ├── engine.py                       # Motor de orquestación y auditoría
│   ├── watcher.py                      # Vigilante en segundo plano (Windows & Linux)
│   ├── detections.py                   # 19 Indicadores heurísticos (I01 a I19) y MITRE ATT&CK (I01 a I17)
│   ├── inventory.py                    # Inventario de sesiones por navegador
│   ├── process_hunter.py               # Cazador heurístico de procesos infostealers
│   ├── ioc_updater.py                  # Motor de Threat Intelligence y auto-actualizador de IoCs
│   ├── desktop_sessions.py             # Auditor de sesiones Telegram, Discord y Wallets (I17)
│   ├── extensions.py                   # Auditor de permisos y extensiones de navegadores
│   ├── simulator.py                    # Simulador seguro de incidentes y test harness
│   ├── service.py                      # Gestor de servicio segundo plano (Windows & systemd)
│   ├── siem.py                         # Emisor de eventos estructurados SIEM (CEF / JSON Lines)
│   ├── honeypot.py                     # Perfiles trampa señuelo contra stealers (I18)
│   ├── memory_audit.py                 # Auditoría de DLL injection y hooking (I19)
│   ├── forensics.py                    # Captura de snapshot volátil forense en ZIP
│   ├── incident_report.py              # Generador de Dossier MITRE ATT&CK (HTML/MD)
│   ├── invalidation.py                 # Generador de scripts de revocación por lotes
│   ├── triage.py                       # Generador de kit forense y checklist USB
│   ├── reports.py                      # Generador de Dashboard HTML autónomo
│   ├── gui.py                          # Interfaz gráfica de escritorio (Tkinter)
│   ├── notify.py                       # Notificaciones nativas (Toast / notify-send)
│   ├── canary.py                       # Sistema de cookies señuelo (canary tokens)
│   ├── killswitch.py                   # Aislamiento de red de emergencia
│   └── webhook.py                      # Notificaciones remotas seguras
├── docs/
│   └── simulaciones/
│       ├── simulacion_incidente_windows.html # Demo interactiva Windows 11
│       └── simulacion_incidente_linux.html   # Demo interactiva Linux
├── windows/                            # Entorno Windows
│   ├── README_WINDOWS.md               # Guía detallada de Windows, Sysmon y Firewall
│   ├── Abrir CookieGuard.cmd           # Lanzador de la GUI / Dashboard
│   ├── Analizar ahora.cmd              # Análisis rápido por consola
│   ├── Aislar Red Killswitch.cmd       # Bloqueo de red de emergencia
│   ├── Restaurar Red.cmd               # Restauración de conexión
│   ├── Sembrar Canaries.cmd            # Inserción de cookies trampa
│   ├── Instalar vigilante.cmd          # Instalador de tarea programada
│   └── Desinstalar vigilante.cmd
└── linux/                              # Entorno Linux
    ├── README_LINUX.md                 # Guía detallada de Linux y systemd
    ├── abrir_cookieguard.sh            # Lanzador de la GUI / Dashboard
    ├── analizar_ahora.sh               # Análisis rápido por terminal
    ├── aislar_red.sh                   # Bloqueo de red de emergencia
    ├── restaurar_red.sh                # Restauración de conexión
    ├── sembrar_canaries.sh             # Inserción de cookies trampa
    ├── instalar_vigilante.sh           # Servicio systemd de usuario
    └── desinstalar_vigilante.sh
```

---

## ⚡ Guía Rápida de Uso

### 🪟 En Windows
1. Haz doble clic en `windows/Analizar ahora.cmd` para ejecutar una auditoría inmediata.
2. O haz doble clic en `windows/Abrir CookieGuard.cmd` para abrir la consola visual.
3. Para activar la vigilancia en segundo plano con alertas interactivas: ejecuta `windows/Instalar vigilante.cmd`.

### 🐧 En Linux
```bash
# Análisis rápido por terminal
bash linux/analizar_ahora.sh

# Interfaz gráfica de triaje
bash linux/abrir_cookieguard.sh

# Activar vigilancia en segundo plano (systemd usuario)
bash linux/instalar_vigilante.sh
```

---

## 🧪 Pruebas y Validación de Seguridad

El proyecto incluye 84 pruebas automatizadas (77 unitarias y 7 de seguridad estricta) que garantizan el correcto funcionamiento y el cumplimiento estricto de los requisitos de privacidad:

```bash
python3 -m unittest discover -s tests -v
```

Las pruebas de seguridad (`tests/test_seguridad.py`) validan que en ningún momento se importen librerías de red directas para extraer datos sensibles ni se intente leer valores de cookies.
