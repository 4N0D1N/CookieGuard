# 🛡️ CookieGuard v2.0.0

> **Suite defensiva y auditor forense local de metadatos de sesiones de navegador, aplicaciones de escritorio y persistencia de infostealers. 100% Local-first, sin dependencias externas obligatorias y con estricta garantía de privacidad (Zero-Trust): NUNCA descifra ni expone el valor de tus cookies ni contraseñas.**

![Versión](https://img.shields.io/badge/Versi%C3%B3n-2.0.0-blue)
[![CI CookieGuard](https://github.com/4N0D1N/CookieGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/4N0D1N/CookieGuard/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Plataformas](https://img.shields.io/badge/Plataformas-Windows%2010%2F11%20%7C%20Linux-brightgreen)
![Privacidad](https://img.shields.io/badge/Privacidad-Local--first%20%26%20Zero--Telemetry-blue)
![Dependencias](https://img.shields.io/badge/Core-100%25%20Python%20stdlib-orange)
![Licencia](https://img.shields.io/badge/Licencia-MIT-purple)

---

## 📑 Tabla de Contenidos

1. [🎮 Demos y Simulaciones en Vivo](#-demos-y-simulaciones-en-vivo)
2. [🎯 ¿Qué es CookieGuard?](#-qué-es-cookieguard)
3. [🧠 Desglose Exhaustivo: Cada Característica y el Motivo de Seguridad](#-desglose-exhaustivo-cada-característica-y-el-motivo-de-seguridad-por-el-que-existe)
4. [🔒 Principios de Privacidad Zero-Trust](#-principios-de-privacidad-zero-trust)
5. [🚀 Guía Rápida en 3 Pasos (Para Dummies y Principiantes)](#-guía-rápida-en-3-pasos-para-dummies-y-principiantes)
6. [🖥️ Manual de la Interfaz Gráfica (GUI) - Explicación Botón por Botón](#️-manual-de-la-interfaz-gráfica-gui---explicación-botón-por-botón)
7. [📋 Manual del Web Dashboard y Checklist de Revocación](#-manual-del-web-dashboard-y-checklist-de-revocación)
8. [⌨️ Referencia Completa de Comandos CLI](#️-referencia-completa-de-comandos-cli)
9. [🚨 Protocolo de Respuesta a Incidentes en 5 Minutos](#-protocolo-de-respuesta-a-incidentes-en-5-minutos)
10. [🔍 Catálogo Completo de Indicadores Heurísticos (I01 a I19 + MITRE ATT&CK)](#-catálogo-completo-de-indicadores-heurísticos-i01-a-i19--mitre-attck)
11. [🧰 Modo Rescate USB (Triage Forense sin Huella)](#-modo-rescate-usb-triage-forense-sin-huella)
12. [🌐 Compatibilidad de Navegadores y Aplicaciones](#-compatibilidad-de-navegadores-y-aplicaciones)
13. [❓ Preguntas Frecuentes y Resolución de Problemas (FAQ)](#-preguntas-frecuentes-y-resolución-de-problemas-faq)
14. [🧪 Ejecución de Pruebas Automatizadas](#-ejecución-de-pruebas-automatizadas)
15. [📂 Estructura del Proyecto](#-estructura-del-proyecto)
16. [⚖️ Licencia y Descargo de Responsabilidad](#️-licencia-y-descargo-de-responsabilidad)

---

## 🎮 Demos y Simulaciones en Vivo

Puedes explorar el comportamiento de las alertas y la experiencia de respuesta a incidentes directamente en tu navegador, sin necesidad de instalar nada:

* 🌐 **[Centro de Demos en Vivo (GitHub Pages)](https://4n0d1n.github.io/CookieGuard/)**
* 🪟 **[Simulación Interactiva Windows 11](https://4n0d1n.github.io/CookieGuard/docs/simulaciones/simulacion_incidente_windows.html)**: Notificación emergente Toast de Windows 11, detección de acceso a DPAPI, triaje de sesiones y activación de Killswitch por firewall.
* 🐧 **[Simulación Interactiva Linux Desktop](https://4n0d1n.github.io/CookieGuard/docs/simulaciones/simulacion_incidente_linux.html)**: Notificación D-Bus `notify-send`, trazado de descriptores en `/proc/[pid]/fd` y aislamiento con `iptables`/`nmcli`.

*(Las simulaciones son aplicaciones interactivas en HTML5/Tailwind, seguras y autónomas, ejecutables tanto online como offline).*

---

## 🎯 ¿Qué es CookieGuard?

Los **infostealers** modernos (como *LummaC2, Stealc, RedLine, Vidar, Meduza, Rhadamanthys*) se han convertido en la principal amenaza contra la identidad digital. Estos programas maliciosos no necesitan descifrar tus contraseñas maestras ni romper el segundo factor de autenticación (2FA): simplemente localizan los archivos SQLite donde los navegadores guardan las **cookies de sesión autenticadas**, extraen la clave de descifrado del sistema (DPAPI en Windows o Secret Service en Linux) y exfiltran las cookies hacia sus servidores C2 o bots de Telegram. Con esas cookies, los atacantes clonan tu sesión y acceden directamente a tu correo, nubes de trabajo, repositorios y cuentas bancarias sin activar el 2FA.

**CookieGuard actúa como un escudo de defensa en profundidad y triaje forense local:**
1. **Audita y monitoriza** el acceso anómalo a los archivos de base de datos del navegador.
2. **Caza procesos infostealers en ejecución** y detecta técnicas de suplantación (*masquerading*).
3. **Comprueba la persistencia** en el sistema (tareas programadas, scripts de arranque, autostart).
4. **Verifica la integridad** de binarios, red local (DNS, archivo `hosts`) y extensiones del navegador.
5. **Facilita la respuesta inmediata** en caso de sospecha: corte de red instantáneo (Killswitch), instantánea forense anonimizada y playbooks con enlaces directos para revocar sesiones activas en más de 35 servicios clave.

---


---

## 🧠 Desglose Exhaustivo: Cada Característica y el Motivo de Seguridad por el que Existe

Para entender el valor de CookieGuard, es fundamental conocer **cómo operan los ciberdelincuentes** y cuál es el **fundamento defensivo específico** de cada componente del sistema:

---

### 1. 🍪 Auditoría de Metadatos de Cookies de Sesión (Inventory Engine)
* **Qué hace:** Inspecciona las bases de datos SQLite locales de todos los navegadores instalados (Chrome, Edge, Firefox, Brave, Opera, Vivaldi), inventariando dominios, nombres de cookie, rutas de almacenamiento, banderas de seguridad (`Secure`, `HttpOnly`, `SameSite`) y fechas de expiración.
* **El motivo de seguridad (Vector del atacante):** Los infostealers ya no necesitan robar contraseñas maestras ni descifrar hashes. Si clonan una cookie de sesión activa (`session_id`, `SSID`, `authToken`), el atacante puede saltarse instantáneamente el Segundo Factor de Autenticación (2FA / MFA) y suplantar la identidad del usuario en servicios críticos. Saber exactamente qué sesiones estaban abiertas en la máquina es el primer paso indispensable para responder al ataque.
* **Por qué se diseñó de esta forma:** CookieGuard **rechaza explícitamente leer la columna `encrypted_value`**. NUNCA descifra ni expone el valor de la cookie, impidiendo que la propia herramienta de seguridad pueda ser explotada por un atacante para robar credenciales.

---

### 2. 🚦 Diagnóstico Semafórico 'Modo Dummy' (`dummy` / `resumen`)
* **Qué hace:** Evalúa de forma holística todo el sistema en segundos y emite un veredicto visual directo: 🟢 **VERDE** (seguro/limpio), 🟡 **AMARILLO** (atención preventiva requerida) o 🔴 **ROJO** (compromiso activo o anomalía crítica), acompañado de los **3 pasos inmediatos a seguir en los primeros 5 minutos**.
* **El motivo de seguridad:** En situaciones de incidente o sospecha de infección, la sobrecarga de información y el pánico provocan errores graves (como apagar el ordenador sin aislar la red o perder tiempo buscando en menús confusos). Un usuario o técnico de soporte necesita saber en 3 segundos la gravedad de la situación y la prioridad operativa de respuesta.
* **Por qué se diseñó de esta forma:** Traduce heurísticas complejas (MITRE ATT&CK, llamadas DPAPI, descriptores abiertos) a un formato accesible para cualquier persona, con opción de exportar a HTML autónomo para compartir con el equipo de soporte.

---

### 3. 🕵️ Cazador de Procesos Infostealer (Process Hunter - `procesos`)
* **Qué hace:** Escanea en tiempo real la lista de procesos activos en memoria, analizando nombres de ejecutables, líneas de comandos completas, argumentos sospechosos y rutas de ejecución.
* **El motivo de seguridad (Vector del atacante):** Familias de malware como *LummaC2, Stealc, Vidar, RedLine o Meduza* operan mediante ejecutables autónomos o droppers que se ejecutan brevemente en segundo plano para recopilar las bases de datos antes de transmitirlas. Detectar el proceso mientras está activo permite identificar el PID exacto y destruirlo (`kill`) antes de que termine la exfiltración.
* **Detección de Masquerading (T1036):** Detecta troyanos que intentan camuflarse con nombres legítimos del sistema (por ejemplo, un `svchost.exe` o `csrss.exe` ejecutándose desde `%TEMP%` o la carpeta de descargas en lugar de `System32`).

---

### 4. ⚙️ Auditoría de Persistencia y Tareas Programadas (`persistence`)
* **Qué hace:** Audita todos los puntos de arranque automático del sistema operativo:
  * **Windows:** Tareas programadas (`schtasks`), carpeta `Startup` (`Inicio`), scripts de logon y claves de registro Run/RunOnce.
  * **Linux:** Ficheros `.desktop` en `~/.config/autostart` y entradas de usuario en `crontab`.
* **El motivo de seguridad (Vector del atacante):** Los stealers modernos ya no son solo de ejecución única; buscan permanecer residentes para volver a extraer credenciales cada vez que el usuario reinicia el equipo o inicia sesión en un nuevo servicio. Si limpias el navegador pero dejas viva la persistencia, el atacante volverá a robarte en el próximo reinicio.
* **Por qué se diseñó de esta forma:** Aplica heurísticas sobre parámetros ocultos (como PowerShell con `-WindowStyle Hidden` o comandos codificados en Base64 `-enc`) y rutas temporales sospechosas.

---

### 5. 🔏 Verificación de Integridad y Firmas de Binarios (`integrity`)
* **Qué hace:** Valida la legitimidad física de los ejecutables de los navegadores instalados en el sistema operativo.
  * **Windows:** Verifica criptográficamente la firma digital Authenticode del ejecutable, exigiendo certificados válidos emitidos por entidades oficiales reconocidas (*Google LLC, Microsoft Corporation, Mozilla Corporation*).
  * **Linux:** Inspecciona permisos de fichero (alertando ante banderas SUID o SGID anómalas) y verifica que los binarios residan en rutas canónicas seguras (`/usr/bin`, `/opt`, `/snap`, `/nix/store`).
* **El motivo de seguridad (Vector del atacante):** Ataques avanzados parchean o sustituyen el binario de Chrome o Edge por un ejecutable troyanizado (*Browser Hooking* / *Binary Patching*). Si el ejecutable del navegador está adulterado, cualquier cookie o contraseña que introduzcas será interceptada directamente en memoria antes de ser cifrada.

---

### 6. 🌐 Auditoría de Red Local, Archivo hosts y DNS (`network` / `hosts`)
* **Qué hace:** Analiza exhaustivamente el archivo `hosts` del sistema (`/etc/hosts` en Linux, `System32\drivers\etc\hosts` en Windows) y los servidores DNS configurados.
* **El motivo de seguridad (Vector del atacante):**
  * **Security Sinkholing:** El malware suele redirigir dominios de empresas de ciberseguridad y telemetría de antivirus (`virustotal.com`, `kaspersky.com`, `bitdefender.com`, `microsoft.com`) a `127.0.0.1` o `0.0.0.0`. De este modo, el antivirus no puede descargar firmas actualizadas y el usuario no puede subir muestras sospechosas para analizarlas.
  * **Auth Spoofing (Phishing local):** Redirección maliciosa de portales de autenticación hacia direcciones IP controladas por atacantes locales.

---

### 7. 📥 Auditoría de Metadatos de Descargas Recientes (`downloads`)
* **Qué hace:** Consulta en modo estrictamente de solo lectura el historial de descargas de perfiles Chromium (`History`), filtrando por marcas temporales recientes y clasificando archivos según su potencial peligrosidad (`.exe`, `.scr`, `.bat`, `.ps1`, `.iso`, `.zip`).
* **El motivo de seguridad (Vector del atacante):** Más del 85% de las infecciones por infostealers entran a través de descargas que el propio usuario inicia engañado: falsos instaladores de software desde anuncios de Google Ads maliciosos, cracks de programas, mods de videojuegos o adjuntos de correo electrónico. Conocer qué archivo se descargó antes del incidente permite identificar el origen de la brecha y reportar la URL maliciosa.

---

### 8. 🛡️ Auditoría de Protección App-Bound Encryption (`appbound`)
* **Qué hace:** Inspecciona el archivo `Local State` de los perfiles Chromium en Windows para verificar la presencia de los marcadores estructurales de *App-Bound Encryption*.
* **El motivo de seguridad (Vector del atacante):** Google Chrome introdujo App-Bound Encryption para vincular la clave de cifrado de cookies a un servicio privilegiado de Windows, dificultando que un proceso no privilegiado pueda descifrar la base de datos directamente con DPAPI. Sin embargo, los stealers han evolucionado para eludirlo mediante inyección en el proceso del navegador o mediante flags de depuración. Esta auditoría ayuda a evaluar el nivel de blindaje del navegador frente a ataques conocidos.

---

### 9. 🔐 Auditoría de Certificados Raíz y Proxies Locales (`certs`)
* **Qué hace:** Revisa los almacenes de certificados de confianza del sistema operativo y las configuraciones de red (variables `HTTP_PROXY`, `HTTPS_PROXY` y claves de registro de Windows).
* **El motivo de seguridad (Vector del atacante):** Ataques del tipo *Adversary-in-the-Middle (MITM, MITRE T1557)* instalan un proxy local silencioso (`127.0.0.1:8080`) acompañado de una Autoridad de Certificación (CA) falsa en el almacén raíz de Windows o Linux. Con esto, el atacante puede descifrar todo el tráfico HTTPS en tiempo real y robar cookies de sesión transparentemente conforme navegas.

---

### 10. 🗄️ Integridad Forense de Bases de Datos SQLite (`db-integrity`)
* **Qué hace:** Realiza un análisis forense de bajo nivel sobre las bases de datos de cookies: valida la cabecera física (magic bytes `SQLite format 3\000`), ejecuta `PRAGMA quick_check` y calcula el porcentaje de páginas libres (*freelist*). Además, compara las marcas de tiempo de los ficheros auxiliares WAL (*Write-Ahead Log*) y SHM (*Shared Memory*).
* **El motivo de seguridad (Vector del atacante):** Cuando un infostealer extrae datos, frecuentemente recurre a técnicas de *Time-Stomping* (alteración intencionada de marcas de tiempo del sistema de archivos) para burlar a los analistas forenses, o intenta borrar registros masivamente para no dejar rastro, lo que deja un porcentaje anómalamente alto de páginas libres en la base de datos.

---

### 11. 🧩 Auditor de Permisos y Escáner Heurístico de Extensiones (`extensions` / `scan-extensions`)
* **Qué hace:** Analiza los manifiestos de todas las extensiones instaladas para auditar permisos invasivos (`<all_urls>`, `cookies`, `webRequest`, `debugger`). Además, su escáner heurístico inspecciona el código fuente JavaScript interno buscando llamadas a webhooks de Discord, bots de Telegram C2 o llamadas a `chrome.cookies.getAll`.
* **El motivo de seguridad (Vector del atacante):** Las extensiones maliciosas del navegador son el método más sigiloso para robar cookies: no requieren ejecutar archivos `.exe` extraños y los antivirus tradicionales rara vez las inspeccionan. Una vez instalada, una extensión maliciosa puede interceptar cada cookie de sesión generada en cualquier sitio web que visites.

---

### 12. 💼 Auditoría de Sesiones de Apps de Escritorio y Wallets (`desktop-sessions`)
* **Qué hace:** Inspecciona la presencia y el estado de carpetas de sesión de aplicaciones como **Telegram Desktop** (directorio `tdata`), **Discord**, **Slack**, **Postman** (tokens de API Bearer y variables de entorno), **Notion**, **Obsidian** y billeteras de criptomonedas (**Exodus, Electrum, Atomic Wallet, MetaMask**).
* **El motivo de seguridad (Vector del atacante):** Los infostealers ya no se limitan a los navegadores web. Si un stealer roba la carpeta `tdata` de Telegram, el atacante clona tu cuenta de mensajería al instante sin necesidad de código SMS. Si roba los ficheros de Postman, obtiene las claves de acceso a los servidores de producción de tu empresa.

---

### 13. 🛑 Killswitch de Aislamiento de Red Inmediato (`killswitch`)
* **Qué hace:** Invoca las utilidades nativas de filtrado de paquetes del sistema operativo (Firewall de Windows mediante `netsh advfirewall` o `iptables`/`nmcli` en Linux) para cortar instantáneamente todo el tráfico saliente hacia Internet, manteniendo la conectividad de bucle local (`localhost`).
* **El motivo de seguridad (Contención de emergencia):** El ciclo de vida de un infostealer consta de tres fases: Infección -> Recopilación local -> Exfiltración hacia el servidor C2. Si aíslas la red durante los primeros minutos del incidente, el stealer no podrá enviar los datos recopilados, neutralizando el ataque en seco.

---

### 14. 🐤 Canary Cookies Señuelo Activas (`canary`)
* **Qué hace:** Siembra cookies ficticias con nombres muy atractivos para un atacante (`corp_vault_session`, `admin_sso_token`) en las bases de datos locales y vigila si sufren modificaciones, borrado o lecturas no autorizadas.
* **El motivo de seguridad (Alerta con 0% de falsos positivos):** Un usuario normal jamás interactúa con una cookie inventada en un dominio señuelo. Si esa cookie es manipulada o leída por un proceso ajeno al navegador, representa un indicio inequívoco de que un software automatizado está recorriendo la base de datos para robarla.

---

### 15. 🍯 Perfiles de Navegador Trampa (Honeypot - `honeypot`)
* **Qué hace:** Despliega una estructura señuelo simulando un perfil completo de navegador Chromium en ubicaciones estándar donde los stealers buscan habitualmente.
* **El motivo de seguridad (Detección temprana):** La inmensa mayoría de infostealers recorren rutas fijas por defecto. Si un proceso desconocido abre o intenta copiar los archivos de este perfil señuelo, el vigilante de CookieGuard dispara la alarma de intrusión antes de que el malware llegue a comprometer los perfiles reales del usuario.

---

### 16. 💉 Detección de Inyección de Memoria y DLL Hooking (`memory-audit`)
* **Qué hace:** Audita los módulos y librerías dinámicas (`DLL` en Windows / bibliotecas compartidas `.so` en Linux) cargados en el espacio de memoria de los procesos activos del navegador.
* **El motivo de seguridad (Vector del atacante):** Herramientas avanzadas de robo inyectan código malicioso directamente en `chrome.exe` o `firefox.exe` para capturar cookies y credenciales en texto plano antes de que el navegador las almacene o cifre. CookieGuard alerta ante módulos no firmados o cargados desde directorios temporales (`%TEMP%`, `/tmp`).

---

### 17. 📦 Instantánea Forense Volátil Anonimizada (`snapshot` y `snapshot-descifrar`)
* **Qué hace:** Captura de forma estructurada en un archivo ZIP (con opción de cifrado autenticado AES-256-GCM) el estado de procesos, conexiones de red, metadatos de perfiles y registros de eventos, anonimizando de forma automática nombres de usuario, nombres de host y correos electrónicos.
* **El motivo de seguridad:** En cuanto se reinicia o se pasa un antivirus, las evidencias volátiles del malware (procesos en ejecución, conexiones de red abiertas, ficheros temporales) se borran irremediablemente. Guardar una instantánea forense inmediata permite investigar a fondo la intrusión con posterioridad o entregarla a peritos judiciales y equipos de respuesta a incidentes (DFIR).

---

### 18. 📊 Generador de Dossier MITRE ATT&CK y STIX 2.1 (`dossier` / `stix`)
* **Qué hace:** Transforma todos los hallazgos técnicos recopilados en un informe formal de respuesta a incidentes correlacionado con las tácticas y técnicas de la matriz internacional MITRE ATT&CK, y genera paquetes de inteligencia en formato estándar OASIS STIX 2.1.
* **El motivo de seguridad:** Permite a administradores de sistemas y analistas de Centros de Operaciones de Seguridad (SOC) integrar automáticamente los datos del incidente en plataformas como Wazuh, Splunk, MISP u OpenCTI para proteger al resto de la organización.

---

### 19. 📋 Playbooks Interactivos y Checklist de Revocación (`playbook`)
* **Qué hace:** Genera guías interactivas en HTML y Markdown con enlaces directos para **cerrar sesiones activas en todos los dispositivos**, cambiar contraseñas y auditar permisos de aplicaciones OAuth en más de 35 servicios clave (Google, Microsoft 365, AWS, GitHub, Slack, Binance, Stripe, etc.).
* **El motivo de seguridad (La verdad sobre la revocación de cookies):** Borrar una cookie de tu ordenador o cambiar la contraseña local NO cierra la sesión si el atacante ya tiene la cookie en su poder. La única forma efectiva de invalidar una cookie robada es acceder a la infraestructura del proveedor y pulsar *"Cerrar sesión en todos los demás dispositivos"*, lo que destruye el token en los servidores centrales del servicio.

---

### 20. 🔔 Vigilante en Segundo Plano y Notificaciones Nativas (`service` / `watcher`)
* **Qué hace:** Se ejecuta como servicio de usuario de bajo impacto (Tarea Programada en Windows o demonio `systemd` en Linux), comprobando periódicamente el acceso a los archivos y lanzando notificaciones nativas de escritorio (Toasts de Windows o alertas D-Bus `notify-send` en Linux).
* **El motivo de seguridad:** Un usuario no puede estar ejecutando análisis manuales de forma continua. La vigilancia automatizada garantiza que, en el instante exacto en que un proceso extraño intente tocar tus perfiles de navegador, recibirás un aviso emergente en pantalla con un botón directo para abrir el panel de contención.

---

## 🔒 Principios de Privacidad Zero-Trust

CookieGuard fue diseñado desde el primer día bajo la premisa de que **una herramienta de seguridad jamás debe convertirse en un riesgo añadido**:

* **🛡️ CERO acceso a secretos:** CookieGuard **NUNCA** descifra, lee, copia ni transmite el valor en texto plano de tus cookies ni tus contraseñas. El motor lee exclusivamente metadatos estructurales (dominio, nombre de cookie, ruta, expiración, banderas `Secure` y `HttpOnly`).
* **📡 100% Local-first:** Todo el análisis se ejecuta en tu propia máquina. No hay servidores de telemetría, no hay analítica de terceros y no hay envío de datos a la nube.
* **📦 Core sin dependencias externas:** El analizador base y la interfaz funcionan al 100% con la biblioteca estándar de Python (`sqlite3`, `tkinter`, `urllib`, `subprocess`, `hashlib`). Solo las funciones forenses avanzadas de cifrado de snapshots requieren paquetes opcionales (`cryptography`).
* **🙈 Anonimización por defecto:** Los informes forenses y volcados de incidentes enmascaran automáticamente nombres de usuario, nombres de equipo y direcciones de correo electrónico.

---

## 🚀 Guía Rápida en 3 Pasos (Para Dummies y Principiantes)

Si no tienes conocimientos técnicos de ciberseguridad o sospechas que has hecho clic en un enlace o archivo malicioso, sigue estos 3 pasos:

```text
       ┌────────────────────────┐
       │   1. EJECUTAR ANÁLISIS │
       └───────────┬────────────┘
                   ▼
       ┌────────────────────────┐
       │  2. MIRAR EL SEMÁFORO  │
       │   🟢 OK | 🟡 ATENCIÓN  │
       │         🔴 PELIGRO     │
       └───────────┬────────────┘
                   ▼
       ┌────────────────────────┐
       │  3. SEGUIR 3 ACCIONES  │
       │     PRIORITARIAS       │
       └────────────────────────┘
```

### Paso 1: Ejecutar el análisis
* **En Windows:** Haz doble clic en el archivo `windows/Analizar ahora.cmd` (o abre `windows/Abrir CookieGuard.cmd`).
* **En Linux:** Abre una terminal en la carpeta y escribe:
  ```bash
  cookieguard dummy
  # o bien:
  bash linux/analizar_ahora.sh
  ```

### Paso 2: Interpretar el semáforo
El **Modo Dummy** te mostrará un diagnóstico claro e inmediato:
* 🟢 **VERDE (Sin amenazas detectadas):** No hay procesos extraños leyendo tus navegadores, la persistencia está limpia y la configuración de red es normal.
* 🟡 **AMARILLO (Atención preventiva):** Hay sesiones activas importantes que llevan mucho tiempo abiertas sin rotar, o flags de depuración que convendría cerrar.
* 🔴 **ROJO (Sospecha crítica de infección):** Se detectó un proceso conocido de infostealer, un acceso no autorizado a tus archivos de cookies o modificaciones anómalas en el archivo `hosts`/persistencia.

### Paso 3: Aplicar las 3 acciones urgentes
En caso de semáforo rojo o amarillo, CookieGuard te genera exactamente **las 3 acciones inmediatas en orden de prioridad** (por ejemplo: 1. Aislar la red con un clic, 2. Cerrar sesiones críticas desde tu teléfono, 3. Cambiar tus contraseñas principales).

---

## 🖥️ Manual de la Interfaz Gráfica (GUI) - Explicación Botón por Botón

Al iniciar la aplicación visual (`windows/Abrir CookieGuard.cmd`, `linux/abrir_cookieguard.sh` o el comando `cookieguard gui`), se abre el panel de control de escritorio. A continuación se detalla la función de cada control:

```text
┌────────────────────────────────────────────────────────────────────────┐
│  🛡️ CookieGuard - Panel de Control Forense y Vigilancia de Sesiones    │
├────────────────────────────────────────────────────────────────────────┤
│  [ Analizar ahora ]   [ 🌐 Abrir Dashboard Web ]   [ Modo Incidente ]  │
├────────────────────────────────────────────────────────────────────────┤
│  Servicios Detectados: Google, Microsoft, GitHub, AWS, Stripe...       │
│  [ Marcar como revisado ]   [ Borrar cookies de este servicio... ]     │
├────────────────────────────────────────────────────────────────────────┤
│  Ajustes de Hardening y Vigilancia:                                    │
│  [ Comprobar ]   [ Aplicar ]   [ Deshacer ]   [ Guardar ajustes ]      │
├────────────────────────────────────────────────────────────────────────┤
│  Contingencia:                                                         │
│  [ Aislar Red (Killswitch) ]   [ Restaurar Red ]   [ Probar alerta ]   │
└────────────────────────────────────────────────────────────────────────┘
```

### 🔘 Botones de Auditoría y Triaje General

| Botón | Qué hace exactamente | Cuándo usarlo |
| :--- | :--- | :--- |
| **`Analizar ahora`** | Ejecuta inmediatamente el motor de auditoría completo: escanea perfiles de navegadores Chromium y Firefox, inspecciona memoria y procesos en busca de stealers, comprueba persistencia, archivo hosts y certificados. Actualiza el semáforo y la lista de alertas en pantalla. | Al iniciar la herramienta o justo después de cerrar programas sospechosos. |
| **`🌐 Abrir Dashboard Web (HTML)`** | Genera y abre en tu navegador predeterminado un informe visual interactivo y auto-contenido (`data/reports/dashboard.html`) con tablas detalladas, deslose de sesiones por nivel de criticidad y gráficas de riesgo. | Cuando quieras revisar el informe completo con calma o exportarlo. |
| **`Modo incidente (ZIP forense)`** | Crea de inmediato un archivo comprimido forense (`data/incidentes/incidente_YYYYMMDD_HHMMSS.zip`) que recopila logs del sistema, estado de procesos, metadatos de cookies (sin valores sensibles), volcados de red y árbol de ejecución. Anonimiza datos personales por defecto. | **Urgente:** En cuanto sospeches que tu equipo ha sido infectado, para guardar la evidencia antes de formatear o apagar. |
| **`Restaurar copia de seguridad...`** | Muestra el listado de copias de seguridad de perfiles creadas por CookieGuard y permite restaurar una base de datos de cookies o configuración anterior al estado previo al incidente. | Si borraste cookies por error o una actualización dañó un perfil. |
| **`Reintentar como administrador (copia VSS)`** | Si algún navegador está abierto o bloquea el archivo `Cookies` (`sqlite3.OperationalError: database is locked`), este botón reinicia la lectura aprovechando el servicio de instantáneas de volumen (VSS en Windows) para leer el archivo sin forzar el cierre del navegador. | Cuando veas advertencias de "base de datos bloqueada" en Chrome o Edge. |

### 🔘 Botones de Gestión de Sesiones y Cookies

| Botón | Qué hace exactamente | Cuándo usarlo |
| :--- | :--- | :--- |
| **`Marcar como revisado`** | Añade una marca temporal al servicio seleccionado en la lista, indicando que ya has comprobado su seguridad, rotado credenciales o confirmado que la sesión es legítima. Se guarda en el historial local. | Conforme vas verificando una por una tus cuentas críticas. |
| **`Desmarcar paso (último)`** | Deshace la última marca de revisión realizada, devolviendo el servicio al estado pendiente. | Si marcaste un servicio por error sin haber cambiado su contraseña. |
| **`Aceptar cambios pendientes como línea base`** | Registra el estado actual de extensiones, servicios de arranque y perfiles como la "normalidad" del sistema. Las futuras ejecuciones solo alertarán si hay elementos nuevos que no estaban en esta línea base. | Tras una instalación limpia o tras auditar que el equipo está libre de malware. |
| **`Borrar cookies locales de este servicio...`** | Elimina selectivamente de la base de datos local del navegador las cookies asociadas al dominio del servicio seleccionado (por ejemplo, solo las de `google.com` o `github.com`), forzando el cierre de la sesión en este equipo. | Para cerrar una sesión comprometida sin perder las sesiones del resto de páginas. |
| **`Cerrar navegadores y borrar TODAS las cookies...`** | **Acción drástica:** Cierra los procesos de todos los navegadores abiertos y elimina íntegramente los archivos de cookies locales de todos los perfiles detectados. Cierra todas tus sesiones en este ordenador. | En caso de ataque activo confirmado donde necesites invalidar localmente todo de golpe. |

### 🔘 Botones de Hardening y Configuración

| Botón | Qué hace exactamente | Cuándo usarlo |
| :--- | :--- | :--- |
| **`Comprobar`** | Evalúa las políticas de seguridad del sistema y de los navegadores (flags de depuración remota desactivados, extensiones forzadas, protección App-Bound). Muestra en verde las correctas y en rojo las vulnerables. | Para auditar si tu navegador está configurado de forma robusta. |
| **`Aplicar seleccionado`** | Aplica la recomendación de seguridad seleccionada (por ejemplo, deshabilitar flags de depuración remota o bloquear extensiones no firmadas). | Para blindar la configuración tras la comprobación. |
| **`Deshacer seleccionado`** | Revierte el ajuste de seguridad seleccionado a los valores predeterminados del sistema. | Si un ajuste de hardening interfiere con alguna herramienta de trabajo. |
| **`Guardar ajustes`** | Guarda los umbrales de alerta, lista blanca de procesos y destinos de webhook en `config/config.json`. | Tras modificar la configuración personalizada. |
| **`Probar notificación`** | Envía una alerta de prueba al sistema operativo (Toast nativo en Windows 11 o `notify-send` en Linux) para verificar que el sistema de avisos emergentes funciona correctamente. | Durante la primera instalación para asegurar que verás las alertas. |

---

## 📋 Manual del Web Dashboard y Checklist de Revocación

Cuando abres el Dashboard Web (`data/reports/dashboard.html`) o generas el Playbook interactivo (`checklist_revocacion.html`), verás tarjetas interactivas para cada servicio afectado con tres botones principales de acción:

```text
┌──────────────────────────────────────────────────────────────┐
│  🏢 Google Workspace / Gmail                                 │
│  Criticidad: CRÍTICA | Sesiones activas detectadas: 3        │
├──────────────────────────────────────────────────────────────┤
│  [ 🚪 Cerrar Sesiones ]  [ 🔑 Cambiar Clave ]  [ 🛡️ OAuth ]   │
└──────────────────────────────────────────────────────────────┘
```

### ¿Para qué sirve cada botón y qué ocurre al pulsarlo?

1. **`🚪 Cerrar Sesiones` (Sign out of all sessions):**
   * **Propósito:** Te lleva directamente a la consola oficial del proveedor donde puedes pulsar *"Cerrar sesión en todos los demás dispositivos"* o *"Revocar tokens de sesión"*. Esto invalida de inmediato las cookies en los servidores del proveedor, dejando inservibles las cookies que el ladrón haya podido robar.
   * **Mecanismo anti-bloqueo:** Si tu navegador o el visor del sistema bloquea las ventanas emergentes (*pop-ups*), el botón **copia automáticamente el enlace oficial en tu portapapeles** y te muestra un aviso visual con la URL para que solo tengas que pegarla (`Ctrl+V`) en una pestaña limpia.

2. **`🔑 Cambiar Clave` (Password Reset):**
   * **Propósito:** Abre directamente la página oficial de cambio de contraseña de ese servicio específico. Al cambiar la contraseña en la mayoría de proveedores modernos (Google, Microsoft, GitHub, Amazon), se invalidan automáticamente todas las sesiones abiertas previas.

3. **`🛡️ Permisos OAuth` (Third-Party Apps & Integrations):**
   * **Propósito:** Abre la consola de auditoría de aplicaciones autorizadas de tu cuenta. Muchos infostealers aprovechan accesos previos para autorizar aplicaciones maliciosas que mantienen acceso permanente mediante tokens OAuth incluso si cambias la contraseña.

---

## ⌨️ Referencia Completa de Comandos CLI

Para administradores de sistemas, analistas SOC o usuarios avanzados, CookieGuard incluye una potente interfaz de línea de comandos (`CLI`) ejecutable con `python -m cookieguard <comando>` o mediante el ejecutable compilado `cookieguard <comando>`:

```text
Uso general:
  cookieguard [opciones_globales] <comando> [argumentos...]
```

### 🚦 1. Diagnóstico Rápido y Triaje Básico

#### `cookieguard dummy` / `cookieguard resumen`
Genera el diagnóstico simplificado del semáforo (Verde, Amarillo, Rojo) con las 3 acciones prioritarias recomendadas para los primeros 5 minutos.
```bash
# Salida por consola
cookieguard dummy

# Exportar a informe HTML visual para compartir
cookieguard dummy --html /tmp/diagnostico_urgente.html

# Salida estructurada JSON para integraciones
cookieguard dummy --json
```

#### `cookieguard analizar`
Ejecuta el motor de análisis completo, evaluando los 19 indicadores de seguridad, inventario de sesiones y nivel de riesgo global.
```bash
# Análisis estándar
cookieguard analizar

# Análisis detallado con volcado de todos los hallazgos
cookieguard analizar --verbose

# Exportar directamente a dashboard HTML
cookieguard analizar --html dashboard.html
```

#### `cookieguard version`
Muestra la versión actual instalada de CookieGuard y el estado del entorno de ejecución.
```bash
cookieguard version
```

---

### 🕵️ 2. Detección de Amenazas y Caza de Procesos

#### `cookieguard procesos` (Process Hunter)
Escanea la memoria y los procesos en ejecución buscando patrones de nombres y firmas asociados a infostealers conocidos (Lumma, Stealc, RedLine, Vidar, Meduza), así como técnicas de suplantación de identidad de procesos (*masquerading*).
```bash
cookieguard procesos
```

#### `cookieguard update-iocs` (Threat Intelligence)
Descarga y actualiza de forma segura la base de datos de Indicadores de Compromiso (hashes SHA-256 de stealers, IPs y dominios de C2) utilizando únicamente utilidades nativas del sistema (`curl` o `PowerShell`), respetando el modo offline-first.
```bash
cookieguard update-iocs
```

#### `cookieguard simular` (Test Harness)
Ejecuta un simulador completamente inocuo en un entorno temporal que emula la presencia de un infostealer para verificar que las alertas Toast, las notificaciones de escritorio y el motor de detección funcionan correctamente sin poner en peligro datos reales.
```bash
cookieguard simular
```

---

### ⚙️ 3. Auditoría de Sistema, Persistencia e Integridad

#### `cookieguard persistence`
Audita los mecanismos de persistencia utilizados por el malware para sobrevivir a reinicios:
* **Windows:** Tareas programadas (`schtasks`), carpeta `Startup`, claves de registro Run/RunOnce.
* **Linux:** Entradas `.desktop` en `~/.config/autostart` y tareas de usuario en `crontab`.
* **Heurísticas:** Alerta ante ejecutables alojados en carpetas temporales (`%TEMP%`, `/tmp`, `/dev/shm`), PowerShell con ventanas ocultas (`-WindowStyle Hidden`, `-enc`) o nombres engañosos como `chrome_update.exe`.
```bash
cookieguard persistence
cookieguard persistence --json
```

#### `cookieguard integrity`
Verifica la autenticidad e integridad de los ejecutables de navegadores instalados (Chrome, Edge, Firefox, Brave, etc.) para detectar si han sido parcheados o reemplazados por troyanos:
* **Windows:** Comprobación de firmas digitales Authenticode nativas (emisor legítimo como Google LLC o Microsoft Corporation).
* **Linux:** Validación de rutas canónicas (`/usr/bin`, `/opt`, `/snap`) y comprobación de permisos anómalos (banderas SUID no estándar).
```bash
cookieguard integrity
```

#### `cookieguard network` / `cookieguard hosts`
Inspecciona la configuración de red local en busca de manipulaciones:
* **Archivo `hosts`:** Detecta técnicas de *Security Sinkholing* (redirección de antivirus como `virustotal.com`, `kaspersky.com`, `microsoft.com` a `127.0.0.1` para anular sus actualizaciones) y *Auth Spoofing*.
* **DNS:** Audita los servidores DNS activos en el equipo.
```bash
cookieguard network
cookieguard hosts
```

---

### 🌐 4. Auditoría Avanzada de Navegadores y Extensiones

#### `cookieguard downloads`
Examina el historial de descargas de perfiles Chromium en modo solo lectura, marcando descargas recientes con extensiones de alto riesgo (`.exe`, `.scr`, `.bat`, `.ps1`, `.vbs`, `.iso`, `.zip`) para identificar el posible vector de entrada del malware.
```bash
cookieguard downloads
```

#### `cookieguard appbound`
Inspecciona marcadores en el archivo `Local State` de navegadores Chromium en Windows para comprobar el estado de soporte de *App-Bound Encryption* (elevación protegida por servicio de sistema).
```bash
cookieguard appbound
```

#### `cookieguard extensions` & `cookieguard scan-extensions`
* `extensions`: Inventaría todas las extensiones instaladas y clasifica su nivel de riesgo en base a los permisos solicitados en el manifiesto (`<all_urls>`, `webRequest`, `cookies`, `debugger`).
* `scan-extensions`: Escáner heurístico que analiza el código fuente (`.js`, `.json`) de las extensiones instaladas en busca de llamadas sospechosas a webhooks de Discord, bots de Telegram, `chrome.cookies.getAll` o inyecciones con `eval(atob(...))`.
```bash
cookieguard extensions
cookieguard scan-extensions
```

#### `cookieguard certs`
Audita el almacén de certificados raíz del sistema y las variables de entorno de red en busca de proxies locales (`127.0.0.1`) o certificados CA de intercepción TLS (Fiddler, Charles, Burp, mitmproxy) que puedan estar descifrando el tráfico HTTPS en tránsito.
```bash
cookieguard certs
```

#### `cookieguard db-integrity`
Inspecciona a bajo nivel los archivos SQLite de perfiles del navegador:
* Verifica el número mágico de cabecera (`SQLite format 3 `).
* Ejecuta `PRAGMA quick_check`.
* Detecta *Time-Stomping* (marcas de tiempo de ficheros WAL/SHM desincronizadas) y anomalías en la lista de páginas libres (*freelist* > 40%), indicio de borrado masivo de registros para ocultar huellas.
```bash
cookieguard db-integrity
```

---

### 💼 5. Sesiones de Aplicaciones de Escritorio

#### `cookieguard desktop-sessions`
Extiende la protección más allá de los navegadores web tradicionales, auditando sesiones activas de:
* **Mensajería y colaboración:** Telegram Desktop, Discord, Slack Desktop.
* **Herramientas de desarrollo:** Postman Desktop (tokens de API Bearer y entornos), Notion Desktop, Obsidian.
* **Billeteras de criptomonedas:** Exodus, Electrum, Atomic Wallet, extensiones MetaMask.
```bash
cookieguard desktop-sessions
```

---

### 🚨 6. Contención, Trampas y Respuesta Inmediata

#### `cookieguard killswitch`
Corta de forma instantánea todo el tráfico de red saliente hacia Internet utilizando el Firewall nativo de Windows (`netsh advfirewall`) o `iptables`/`nmcli` en Linux, impidiendo que un stealer continúe enviando datos robados a su servidor de mando (C2).
```bash
# Bloquear tráfico saliente de inmediato
cookieguard killswitch on
# o bien:
cookieguard killswitch aislar

# Restablecer la conectividad normal de red
cookieguard killswitch off
# o bien:
cookieguard killswitch restaurar
```

#### `cookieguard canary` & `cookieguard canary-trap`
* `canary`: Siembra cookies señuelo locales creíbles (`corp_vault_session`, `admin_sso_token`) en las bases de datos locales. Si un stealer vuelca la base, la lectura del señuelo dispara una alerta inmediata con 0% de falsos positivos.
* `canary-trap`: Documentación y simulación del flujo de trampa defensiva.
```bash
cookieguard canary sembrar
cookieguard canary verificar
```

#### `cookieguard honeypot`
Genera un perfil de navegador señuelo aislado con bases de datos simuladas. Si cualquier software que no sea un navegador legítimo accede a ese directorio, se registra un intento de intrusión.
```bash
cookieguard honeypot crear
cookieguard honeypot estado
cookieguard honeypot limpiar
```

---

### 📁 7. Forense, Snapshots e Informes MITRE ATT&CK

#### `cookieguard snapshot` y `cookieguard snapshot-descifrar`
Genera un volcado forense comprimido de emergencia para preservación de evidencias:
```bash
# Snapshot estándar anonimizado
cookieguard snapshot --salida /ruta/evidencia.zip

# Snapshot con cifrado militar autenticado AES-256-GCM (requiere 'cryptography')
cookieguard snapshot --cifrar --salida evidencia.cgenc

# Descifrar snapshot protegido
cookieguard snapshot-descifrar evidencia.cgenc --password "TuClaveSegura"
```

#### `cookieguard dossier` & `cookieguard stix`
* `dossier`: Genera un informe forense formal de respuesta a incidentes en HTML o Markdown, estructurado según las fases de la matriz MITRE ATT&CK.
* `stix`: Exporta los hallazgos en formato estándar STIX 2.1 para importación directa en plataformas de inteligencia de amenazas (TIP) y SIEM.
```bash
cookieguard dossier --formato html --salida informe_incidente.html
cookieguard stix --salida incident_stix.json
```

#### `cookieguard playbook`
Genera las guías y listas de verificación interactivas para revocación de sesiones:
```bash
# Genera checklist_revocacion.html con más de 35 servicios
cookieguard playbook --html checklist_revocacion.html

# Genera PLAYBOOK_REVOCACION.md para adjuntar a tickets de soporte
cookieguard playbook --markdown PLAYBOOK_REVOCACION.md
```

#### `cookieguard triage` (Modo USB)
Prepara el kit de respuesta rápida para copiar y ejecutar en un pendrive USB de rescate:
```bash
cookieguard triage --usb-dir /media/usuario/PENDRIVE
```

---

### 🕒 8. Vigilancia en Segundo Plano y Automatización

#### `cookieguard service` / `cookieguard vigilar`
Administra el servicio de monitorización continua:
* **Windows:** Instala o desinstala una Tarea Programada nativa (`schtasks`) que vigila los archivos en segundo plano con bajo consumo de CPU.
* **Linux:** Configura un servicio de usuario en `systemd` (`cookieguard.service`).
```bash
# Instalar el servicio de vigilancia
cookieguard service install

# Consultar el estado del servicio
cookieguard service status

# Desinstalar el servicio
cookieguard service uninstall

# Ejecutar el vigilante en primer plano para depuración
cookieguard vigilar --intervalo 15
```

---

## 🚨 Protocolo de Respuesta a Incidentes en 5 Minutos

Si CookieGuard detecta un infostealer en tu máquina o el semáforo está en **ROJO**, sigue este protocolo de contención cronometrado:

```text
 ⏱️ MINUTO 0 a 1: CONTENCIÓN INMEDIATA
 ├── Pulsa "Aislar Red (Killswitch)" o ejecuta: cookieguard killswitch on
 └── (Evita que el troyano termine de enviar tus archivos a su servidor C2)

 ⏱️ MINUTO 1 a 2: PRESERVACIÓN FORENSE
 ├── Genera la instantánea de evidencias: cookieguard snapshot
 └── Guarda el archivo ZIP/cgenc resultante en un pendrive externo

 ⏱️ MINUTO 2 a 3: DETENCIÓN DEL PROCESO
 ├── Localiza el proceso malicioso: cookieguard procesos
 └── Termínalo de inmediato con el comando sugerido (ej: taskkill /F /PID 1234)

 ⏱️ MINUTO 3 a 4: REVOCACIÓN REMOTA (¡DESDE OTRO EQUIPO SEGURO!)
 ├── IMPORTANTE: Utiliza tu teléfono móvil o un segundo ordenador limpio
 ├── Abre checklist_revocacion.html (o entra a las consolas oficiales)
 └── Pulsa "Cerrar sesión en todos los dispositivos" en:
     1. Cuentas de correo (Google Workspace, Microsoft 365, Outlook)
     2. Repositorios de código (GitHub, GitLab, Bitbucket)
     3. Proveedores de Cloud e infraestructura (AWS, Azure, Cloudflare)
     4. Servicios financieros y cripto (Stripe, PayPal, Exchanges)

 ⏱️ MINUTO 4 a 5: ROTACIÓN DE CONTRASEÑAS Y AUDITORÍA OAUTH
 ├── Cambia las contraseñas maestras de tus cuentas clave
 ├── Revisa aplicaciones de terceros vinculadas (OAuth) y revoca accesos desconocidos
 └── Procede a desinfectar o reinstalar limpiamente el sistema operativo
```

---

## 🔍 Catálogo Completo de Indicadores Heurísticos (I01 a I19 + MITRE ATT&CK)

CookieGuard evalúa 19 vectores de ataque complementarios para calcular la puntuación de riesgo global:

| Código | Nombre del Indicador | Técnica MITRE ATT&CK | Qué detecta | Severidad |
| :---: | :--- | :---: | :--- | :---: |
| **I01** | **Acceso no autorizado a ficheros** | `T1555.003` / `T1539` | Procesos externos (no navegadores) leyendo activamente bases SQLite de cookies o contraseñas. | 🔴 Crítica |
| **I02** | **Flags peligrosos de navegador** | `T1539` / `T1185` | Navegadores lanzados con `--remote-debugging-port`, `--headless` o `--load-extension` forzada. | 🔴 Crítica |
| **I03** | **Acceso a memoria del navegador** | `T1055` / `T1003` | Intentos de inyección o lectura de memoria en procesos de Chrome/Firefox (`OpenProcess`, ptrace). | 🔴 Crítica |
| **I04** | **Abuso de App-Bound Encryption** | `T1555.003` / `T1559` | Intentos de vulnerar el servicio de elevación DPAPI / App-Bound de Chromium en Windows. | 🔴 Crítica |
| **I05** | **Extensiones con permisos de riesgo** | `T1176` / `T1539` | Extensiones instaladas fuera de tienda, forzadas por directiva o con acceso a `cookies` y `<all_urls>`. | 🟡 Alta |
| **I06** | **Copias sospechosas de bases de datos** | `T1555.003` / `T1074` | Archivos de cookies o contraseñas copiados en `%TEMP%`, carpetas de staging o comprimidos en ZIP. | 🔴 Crítica |
| **I07** | **Conexiones a destinos de exfiltración** | `T1567` / `T1041` | Tráfico hacia webhooks de Discord, API de Telegram, servicios de túnel o servidores C2 conocidos. | 🟡 Alta |
| **I08** | **Estado de Microsoft Defender** | `T1562.001` / `T1555` | Desactivación de protección en tiempo real, exclusiones sospechosas o alertas activas de malware. | 🔴 Crítica |
| **I09** | **Persistencia nueva en el sistema** | `T1547` / `T1053` | Tareas programadas, servicios o scripts de inicio agregados recientemente que no estaban en la línea base. | 🟡 Alta |
| **I10** | **Ejecutables recientes sin firmar** | `T1204` / `T1553.005` | Binarios ejecutados desde Descargas o Temp sin firma digital válida o sin marca de zona web (MoTW). | 🟡 Alta |
| **I11** | **Manipulación de red local** | `T1557` / `T1553.004` | Modificaciones maliciosas en el archivo `hosts`, servidores DNS anómalos o instalación de CA raíz. | 🔴 Crítica |
| **I12** | **Anomalías en marcas de tiempo** | `T1539` | Creación masiva y simultánea de cookies en horas anómalas o actividad de perfiles con navegador cerrado. | 🟡 Media |
| **I13** | **Disparo de Canary Cookie (Cebo)** | `T1539` | Modificación, borrado o lectura de las cookies trampa señuelo sembradas en los perfiles. | 🔴 Crítica |
| **I14** | **Auditoría de clave maestra DPAPI** | `T1555.003` | Detección de accesos no autorizados al archivo `Local State` y llamadas a la clave de cifrado maestra. | 🔴 Crítica |
| **I15** | **Process Hunter (Infostealers)** | `T1059` / `T1036` | Procesos en ejecución que coinciden con familias conocidas de stealers o suplantan procesos de Windows. | 🔴 Crítica |
| **I16** | **Coincidencia con IoCs actualizados** | `T1071` / `T1041` | Coincidencias con la base de inteligencia de amenazas (hashes de binarios, IPs y dominios de C2). | 🔴 Crítica |
| **I17** | **Sesiones de apps de escritorio** | `T1555` / `T1539` | Modificación anómala de sesiones de Telegram Desktop, Discord, Postman o billeteras de criptomonedas. | 🟡 Alta |
| **I18** | **Perfil trampa (Honeypot)** | `T1005` / `T1555` | Acceso de cualquier proceso al directorio de perfil señuelo creado deliberadamente como trampa. | 🔴 Crítica |
| **I19** | **Inyección de DLL y Hooking** | `T1055` / `T1003` | Módulos no estándar o DLLs ubicadas en carpetas temporales inyectadas en los navegadores web. | 🔴 Crítica |

---

## 🧰 Modo Rescate USB (Triage Forense sin Huella)

En incidentes reales, es crítico **no alterar el disco del equipo investigado** para no destruir evidencias ni sobreescribir memoria volátil. CookieGuard cuenta con un modo de rescate 100% autónomo para ejecutar desde una memoria USB:

1. **Preparar el pendrive de rescate en un equipo limpio:**
   * Descarga la última versión de CookieGuard o clona el repositorio en tu memoria USB.
2. **Conectar el pendrive en el equipo sospechoso:**
   * **En Windows:** Haz doble clic en `Rescate-USB.cmd`.
   * **En Linux:** Abre una terminal en el punto de montaje del pendrive y ejecuta `bash rescate-usb.sh`.
3. **Comportamiento sin huella (Zero-Footprint):**
   * CookieGuard detecta automáticamente que se ejecuta desde un medio extraíble.
   * Todos los informes, capturas de procesos y volcados forenses se escriben **directamente en la carpeta `evidencias/` del pendrive**, sin crear temporales ni escribir un solo byte en el disco duro del sistema afectado.
   * Genera de forma automática en la raíz del USB el archivo `URGENTE_ROTAR_CLAVES.txt` con la lista de servicios comprometidos para que puedas consultarlo desde tu teléfono móvil.

---

## 🌐 Compatibilidad de Navegadores y Aplicaciones

| Categoría | Aplicaciones Soportadas | Rutas Auditadas |
| :--- | :--- | :--- |
| **Navegadores Chromium** | Google Chrome, Microsoft Edge, Brave Browser, Opera, Opera GX, Vivaldi, Chromium, Arc Browser | `%LocalAppData%` / `~/.config/` (Bases `Cookies`, `Login Data`, `Web Data`, `Local State`) |
| **Navegadores Gecko** | Mozilla Firefox, LibreWolf, Waterfox, Floorp | `%AppData%\Mozilla\Firefox` / `~/.mozilla/firefox/` (`cookies.sqlite`, `logins.json`, `key4.db`) |
| **Mensajería y Colaboración** | Telegram Desktop, Discord, Slack Desktop | Carpetas de sesión `tdata`, almacenamiento `Local Storage`, tokens cifrados |
| **Herramientas de Desarrollo** | Postman Desktop, Notion Desktop, Obsidian | Almacenes de entorno, variables globales, tokens Bearer de API |
| **Criptomonedas y Wallets** | Exodus, Electrum, Atomic Wallet, extensiones MetaMask y Phantom | Bóvedas locales cifradas, almacenamiento de perfiles de extensiones |

---

## ❓ Preguntas Frecuentes y Resolución de Problemas (FAQ)

### 1. ¿Por qué Windows Defender o mi antivirus muestra una alerta al ejecutar los scripts `.cmd`?
Los scripts `.cmd` invocan comandos de administración del sistema como `netsh` (para el firewall) o consultas WMI/CIM para listar procesos. Algunos antivirus aplican heurísticas genéricas a scripts `.cmd` que interactúan con el firewall. CookieGuard es **100% código abierto y auditable**: puedes abrir cualquier archivo `.cmd` con el Bloc de notas para comprobar que no contiene código malicioso ni descargas ocultas.

### 2. ¿Qué significa el error `sqlite3.OperationalError: database is locked`?
Este error ocurre cuando Google Chrome, Edge o Firefox están abiertos y mantienen un bloqueo exclusivo sobre el archivo de base de datos `Cookies`.
* **Solución 1:** Cierra el navegador antes de ejecutar la auditoría para permitir la lectura limpia.
* **Solución 2:** En la interfaz gráfica de CookieGuard, pulsa el botón **`Reintentar como administrador (copia VSS)`**, el cual creará una instantánea de volumen para leer el archivo sin obligarte a cerrar el navegador.

### 3. ¿CookieGuard evita al 100% que me roben las cookies en tiempo real?
**No existe ninguna herramienta en el mundo capaz de garantizar un 100% de protección en tiempo real contra todo el malware existente.** CookieGuard es una herramienta defensiva heurística de detección temprana, triaje y respuesta a incidentes. Proporciona alertas rápidas, caza procesos conocidos y te facilita la revocación urgente de sesiones en los primeros minutos críticos, pero **no sustituye a un EDR corporativo, un antivirus actualizado ni a las buenas prácticas de navegación segura**.

### 4. ¿Por qué al pulsar en "Cerrar sesiones" me copia la URL en lugar de abrir el navegador?
En entornos donde las directivas de seguridad o los visores integrados bloquean la apertura de ventanas emergentes (*pop-ups*) o navegadores externos, CookieGuard detecta el bloqueo y, como salvaguarda, **copia automáticamente la URL oficial de revocación en tu portapapeles**. Solo tienes que abrir tu navegador y presionar `Ctrl + V`.

### 5. ¿Qué pasa si no tengo Python instalado en mi equipo?
Puedes descargar directamente el ejecutable compilado autónomo (`CookieGuard.exe` para Windows o el binario standalone para Linux) desde la sección de **[Releases Oficiales en GitHub](https://github.com/4N0D1N/CookieGuard/releases)**. No requiere instalación ni configuración previa.

---

## 🧪 Ejecución de Pruebas Automatizadas

CookieGuard cuenta con una exhaustiva batería de pruebas unitarias y de integración (116 tests) ejecutadas automáticamente en entornos limpios de Windows y Ubuntu con Python 3.10, 3.11 y 3.12:

```bash
# Ejecutar toda la suite de pruebas localmente
python3 -m unittest discover -s tests -v

# Ejecutar específicamente los tests de seguridad y no-exfiltración
python3 -m unittest tests/test_seguridad.py
```

*Las pruebas de seguridad verifican estricta y formalmente que el código base no importa librerías de red para extraer secretos y que ninguna rutina extrae el campo `encrypted_value` de las bases de datos de cookies.*

---

## 📂 Estructura del Proyecto

```text
CookieGuard/
├── README.md                           # Manual de referencia completo y arquitectura
├── LICENSE                             # Licencia MIT
├── config/
│   └── config.json                     # Configuración de umbrales, listas blancas y módulos
├── cookieguard/                        # Núcleo modular en Python
│   ├── __main__.py                     # Despachador CLI con más de 40 comandos
│   ├── engine.py                       # Orquestador del análisis de auditoría
│   ├── dummy_summary.py                # Modo Dummy simplificado (semáforo y 3 acciones)
│   ├── gui.py                          # Interfaz gráfica de escritorio (Tkinter)
│   ├── detections.py                   # 19 Indicadores heurísticos (I01 a I19) y MITRE ATT&CK
│   ├── inventory.py                    # Extracción segura de metadatos de cookies
│   ├── process_hunter.py               # Cazador heurístico de procesos infostealers
│   ├── persistence_audit.py            # Auditor de persistencia y tareas programadas
│   ├── binary_integrity.py             # Verificación Authenticode y permisos de binarios
│   ├── network_audit.py                # Auditoría de archivo hosts (sinkholing) y DNS
│   ├── downloads_audit.py              # Auditor de descargas de Chromium
│   ├── appbound_audit.py               # Auditoría de marcadores App-Bound Encryption
│   ├── desktop_sessions.py             # Auditor de Telegram, Discord, Postman y Wallets
│   ├── extensions.py                   # Auditor de manifiestos y permisos de extensiones
│   ├── certs.py                        # Auditoría de certificados raíz y proxies MITM
│   ├── sqlite_meta.py                  # Integridad de bases de datos SQLite y time-stomping
│   ├── playbooks.py                    # Generador de checklist y playbooks de revocación
│   ├── killswitch.py                   # Aislamiento de red de emergencia nativo
│   ├── canary.py                       # Siembra y verificación de cookies trampa (cebo)
│   ├── honeypot.py                     # Perfiles de navegador trampa señuelo
│   ├── memory_audit.py                 # Detección de inyecciones DLL y hooking
│   ├── forensics.py                    # Generador de instantáneas forenses (ZIP / AES-GCM)
│   ├── incident_report.py              # Generador de informes MITRE ATT&CK (HTML/MD)
│   ├── ioc_updater.py                  # Threat Intelligence y actualización de IoCs
│   ├── simulator.py                    # Simulador inocuo de incidentes (Test Harness)
│   ├── service.py                      # Gestor de servicio en segundo plano (Windows / systemd)
│   ├── siem.py                         # Emisor de eventos SIEM (CEF / JSON Lines)
│   └── notify.py                       # Notificaciones nativas (Toast / notify-send)
├── docs/
│   └── simulaciones/                   # Simulaciones visuales e interactivas online/offline
│       ├── index.html                  # Portal de selección de simulaciones
│       ├── simulacion_incidente_windows.html
│       └── simulacion_incidente_linux.html
├── windows/                            # Scripts y documentación específica de Windows
│   ├── README_WINDOWS.md
│   ├── Abrir CookieGuard.cmd
│   ├── Analizar ahora.cmd
│   ├── Aislar Red Killswitch.cmd
│   ├── Restaurar Red.cmd
│   ├── Sembrar Canaries.cmd
│   ├── Instalar vigilante.cmd
│   └── Rescate-USB.cmd
└── linux/                              # Scripts y documentación específica de Linux
    ├── README_LINUX.md
    ├── abrir_cookieguard.sh
    ├── analizar_ahora.sh
    ├── aislar_red.sh
    ├── restaurar_red.sh
    ├── sembrar_canaries.sh
    ├── instalar_vigilante.sh
    └── rescate-usb.sh
```

---

## ⚖️ Licencia y Descargo de Responsabilidad

Este proyecto está publicado bajo la licencia **MIT**. Consulta el archivo [`LICENSE`](LICENSE) para más detalles.

### Descargo de Responsabilidad (Disclaimer)
CookieGuard se proporciona con fines educativos, de auditoría de seguridad preventiva y de respuesta a incidentes en sistemas propios o para los que se cuente con autorización explícita. El análisis se basa en heurísticas y metadatos locales; las alertas generadas representan indicios técnicos y no constituyen una certificación formal o pericial de compromiso. El autor no se hace responsable de daños derivados del uso inadecuado de las funciones de contención (como el corte de red o la eliminación de cookies).
