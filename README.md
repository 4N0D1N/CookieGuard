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
3. [🔒 Principios de Privacidad Zero-Trust](#-principios-de-privacidad-zero-trust)
4. [🚀 Guía Rápida en 3 Pasos (Para Dummies y Principiantes)](#-guía-rápida-en-3-pasos-para-dummies-y-principiantes)
5. [🖥️ Manual de la Interfaz Gráfica (GUI) - Explicación Botón por Botón](#️-manual-de-la-interfaz-gráfica-gui---explicación-botón-por-botón)
6. [📋 Manual del Web Dashboard y Checklist de Revocación](#-manual-del-web-dashboard-y-checklist-de-revocación)
7. [⌨️ Referencia Completa de Comandos CLI](#️-referencia-completa-de-comandos-cli)
8. [🚨 Protocolo de Respuesta a Incidentes en 5 Minutos](#-protocolo-de-respuesta-a-incidentes-en-5-minutos)
9. [🔍 Catálogo Completo de Indicadores Heurísticos (I01 a I19 + MITRE ATT&CK)](#-catálogo-completo-de-indicadores-heurísticos-i01-a-i19--mitre-attck)
10. [🧰 Modo Rescate USB (Triage Forense sin Huella)](#-modo-rescate-usb-triage-forense-sin-huella)
11. [🌐 Compatibilidad de Navegadores y Aplicaciones](#-compatibilidad-de-navegadores-y-aplicaciones)
12. [❓ Preguntas Frecuentes y Resolución de Problemas (FAQ)](#-preguntas-frecuentes-y-resolución-de-problemas-faq)
13. [🧪 Ejecución de Pruebas Automatizadas](#-ejecución-de-pruebas-automatizadas)
14. [📂 Estructura del Proyecto](#-estructura-del-proyecto)
15. [⚖️ Licencia y Descargo de Responsabilidad](#️-licencia-y-descargo-de-responsabilidad)

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
