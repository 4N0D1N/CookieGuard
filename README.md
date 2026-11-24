# 🛡️ CookieGuard v2.1.0

> **Auditor forense y escudo defensivo local contra infostealers. Monitoriza, detecta y responde al secuestro de sesiones en navegadores, aplicaciones de escritorio y portapapeles. 100% Local-first, sin telemetría y sin dependencias externas obligatorias.**

![Versión](https://img.shields.io/badge/Versi%C3%B3n-2.1.0-blue)
[![CI CookieGuard](https://github.com/4N0D1N/CookieGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/4N0D1N/CookieGuard/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Plataformas](https://img.shields.io/badge/Plataformas-Windows%2010%2F11%20%7C%20Linux-brightgreen)
![Privacidad](https://img.shields.io/badge/Privacidad-Local--first%20%26%20Zero--Telemetry-blue)
![Dependencias](https://img.shields.io/badge/Core-100%25%20Python%20stdlib-orange)
![Licencia](https://img.shields.io/badge/Licencia-MIT-purple)

---

## 🎮 Demos Interactivas en Vivo (Sin instalar nada)

Prueba la experiencia de alertas y triaje forense directamente desde tu navegador:

- 🌐 **[Centro de Demos en Vivo (GitHub Pages)](https://4n0d1n.github.io/CookieGuard/)**
- 🪟 **[Simulación Windows 11](https://4n0d1n.github.io/CookieGuard/docs/simulaciones/simulacion_incidente_windows.html)**: Notificación Toast nativa, telemetría DPAPI, triaje de sesiones y Killswitch de firewall.
- 🐧 **[Simulación Linux Desktop](https://4n0d1n.github.io/CookieGuard/docs/simulaciones/simulacion_incidente_linux.html)**: Alerta D-Bus `notify-send`, inspección de descriptores en `/proc/[pid]/fd` y aislamiento de red.

---

## 🎯 De Menos a Más: ¿Qué, Cómo y Por Qué?

CookieGuard está diseñado para que cualquier persona entienda su estado de seguridad en 10 segundos, pero ofreciendo profundidad forense para analistas de ciberseguridad.

| Pregunta | Respuesta Clara |
| :--- | :--- |
| **¿QUÉ hace?** | Monitoriza las bases de datos de sesiones de tus navegadores, caza malware en ejecución (incluyendo clippers de portapapeles), revisa la persistencia del sistema y ofrece contención inmediata (Killswitch de red) y revocación en 1 clic de sesiones comprometidas. |
| **¿CÓMO lo hace?** | De forma **100% local y pasiva**. Inspecciona marcas de tiempo, descriptores de archivo abiertos, firmas digitales de ejecutables, búfer de portapapeles y reglas de red. **NUNCA descifra ni expone el contenido de tus cookies o contraseñas**. |
| **¿POR QUÉ lo hace?** | Los **infostealers** modernos (*Lumma, Stealc, RedLine, Vidar*) ya no intentan adivinar contraseñas ni romper el 2FA: copian los archivos SQLite de cookies activas para clonar tu sesión directamente en otro ordenador. CookieGuard detecta ese acceso anómalo y te permite neutralizar el ataque antes de que sea tarde. |

---

## 🚦 Semáforo "Modo Dummy" (Diagnóstico en 10 Segundos)

Para usuarios que no quieren complicaciones técnicas, CookieGuard traduce todo el análisis a un semáforo intuitivo:

```
  🟢 VERDE     Todo en orden. Sin accesos no autorizados, procesos sospechosos ni persistencia detectada.
  🟡 AMARILLO  Advertencia preventiva. Sesiones críticas abiertas o configuraciones del sistema a revisar.
  🔴 ROJO      Alerta crítica. Posible infostealer activo, inyección de procesos o manipulación de archivos.
```

**Ejecución instantánea en terminal:**
```bash
python -m cookieguard dummy
```
*(Analiza el sistema, muestra el color correspondiente y entrega exactamente los **3 pasos prioritarios** que debes dar en los primeros 5 minutos).*

---

## ⚡ Inicio Rápido

```bash
# 1. Clonar el repositorio
git clone https://github.com/4N0D1N/CookieGuard.git
cd CookieGuard

# 2. Diagnóstico rápido (Modo Dummy)
python -m cookieguard dummy

# 3. Iniciar la Interfaz Gráfica (GUI)
python -m cookieguard.gui

# 4. Modo Simulacro (Entrenamiento interactivo de incidente sin riesgo)
python -m cookieguard drill

# 5. Abrir la Guía Interactiva de Revocación de Sesiones
# Abre docs/checklist_revocacion.html en tu navegador favorito
```

---

## 🛡️ Los 4 Pilares de CookieGuard

<details open>
<summary><b>1. 👁️ Detección y Caza de Amenazas (Watcher, Process Hunter & Clipper)</b> [Clic para colapsar/desplegar]</summary>
<br>

* **Qué hace:** Vigila accesos no autorizados a las bases de datos de cookies (`Cookies`, `cookies.sqlite`), caza procesos maliciosos en memoria y audita si malware clipper está espiando o secuestrando tokens en el portapapeles.
* **Cómo lo hace:** Compara marcas de tiempo de modificación, audita descriptores de archivos abiertos, analiza la lista de procesos buscando nombres fraudulentos (`chrome_update.exe`) y audita patrones de tokens (JWT, Bearer, AWS keys) y direcciones cripto en el portapapeles.
* **Por qué:** Los infostealers copian la base de datos de cookies mientras el usuario utiliza el equipo para saltarse los bloqueos de lectura exclusivos. Detectar este patrón detiene la exfiltración a tiempo.

</details>

<details open>
<summary><b>2. ⚙️ Integridad del Sistema y Persistencia (Firmas, Tareas, Red y Hosts)</b> [Clic para colapsar/desplegar]</summary>
<br>

* **Qué hace:** Verifica que los navegadores instalados no hayan sido parcheados, inspecciona tareas de inicio automático y comprueba el archivo `hosts` y DNS.
* **Cómo lo hace:** Valida firmas digitales Authenticode en Windows y permisos/rutas del sistema en Linux. Revisa carpetas de inicio (`Startup`, `autostart`), tareas programadas (`schtasks`, `crontab`) y detecta redirecciones de sitios de seguridad (*Sinkholing* malicioso en `hosts`).
* **Por qué:** El malware suele modificar el archivo `hosts` para impedir que descargues antivirus y crea tareas programadas para reinfectar el equipo si lo reinicias.

</details>

<details open>
<summary><b>3. 🚨 Respuesta Inmediata y Contención (Killswitch, Snapshots & Simulacro)</b> [Clic para colapsar/desplegar]</summary>
<br>

* **Qué hace:** Corta la conexión a Internet en 1 segundo ante sospecha de robo, permite simular incidentes de forma inocua para entrenar y genera informes y snapshots forenses cifrados.
* **Cómo lo hace:** Aplica reglas nativas en el firewall del sistema operativo (`netsh advfirewall` en Windows / `iptables` o `nmcli` en Linux), ofrece el comando `cookieguard drill` para simulacros controlados y empaqueta evidencias forenses en informes HTML/Markdown listos para imprimir a PDF.
* **Por qué:** Cortar la red impide que el malware envíe las cookies a su servidor C2 o canal de Telegram, ganando tiempo para rotar las credenciales.

</details>

<details open>
<summary><b>4. 🔑 Triaje y Revocación Guiada de Sesiones (Playbook Offline)</b> [Clic para colapsar/desplegar]</summary>
<br>

* **Qué hace:** Guía paso a paso para cerrar sesiones activas y cambiar contraseñas en más de 35 servicios críticos (Google, Microsoft, GitHub, AWS, Bancos, Redes Sociales).
* **Cómo lo hace:** Mediante un dashboard HTML interactivo y autónomo (`checklist_revocacion.html`) que funciona 100% offline, almacena tu progreso en `localStorage` y proporciona enlaces oficiales y botones para copiar URLs de revocación.
* **Por qué:** Cambiar la contraseña a menudo **no** invalida las cookies de sesión previamente robadas si no se fuerza el cierre explícito de sesiones en la consola de seguridad del proveedor.

</details>

---

## 📚 Documentación Técnica Detallada (Para quien quiera la opción completa)

Despliega las siguientes secciones para consultar los manuales exhaustivos, parámetros avanzados y tablas de referencia:

<details>
<summary>🎮 <b>Modo Simulacro de Incidente en Vivo (Incident Drill)</b></summary>
<br>

El **Modo Simulacro** (`python -m cookieguard drill` o `cookieguard simulacro`) permite entrenar al equipo o comprobar personalmente cómo reacciona CookieGuard ante un ataque sin peligro alguno:

1. **Entorno Aislado:** Crea un perfil temporal de pruebas y siembra una sesión señuelo (`SSO_ADMIN_SESSION`).
2. **Ataque Simulado:** Dispara un evento de lectura concurrente no autorizado sobre la base de datos de pruebas.
3. **Alerta y Semáforo:** Pasa automáticamente el semáforo a **🔴 ROJO (SIMULACRO)** y emite una notificación de escritorio real.
4. **Verificación de Contención:** Valida que el cortafuegos (Killswitch) esté listo para bloquear el tráfico.
5. **Reporte del Ejercicio:** Genera un informe HTML interactivo (`simulacro_incidente.html`) resumiendo la cronología del simulacro y los 3 pasos de respuesta rápida.

```bash
# Ejecutar simulacro interactivo
python -m cookieguard drill

# Ejecutar simulacro y guardar reporte HTML personalizado
python -m cookieguard drill --html /ruta/reporte_simulacro.html

# Ejecutar simulacro en formato JSON para integración continua o scripts
python -m cookieguard drill --json
```

</details>

<details>
<summary>📄 <b>Generador de Informe Ejecutivo Forense PDF/Markdown (Report / Dossier)</b></summary>
<br>

CookieGuard genera informes formales listos para presentar ante comités de seguridad, CISO o peritajes forenses (`python -m cookieguard report` o `cookieguard informe`):

* **Formato HTML Imprimible (PDF-Ready):** Maquetado profesional con soporte nativo de estilos `@media print` para exportar a PDF en 1 clic con diseño limpio, cabeceras oficiales y sellos de tiempo.
* **Formato Markdown:** Estructurado para adjuntar en tickets de incidentes (Jira, ServiceNow, GitHub Issues).
* **Contenido del Informe:**
  * Resumen ejecutivo y veredicto semafórico.
  * Matriz formal de alineación MITRE ATT&CK (técnicas, tácticas e indicadores detectados).
  * Inventario de perfiles y cookies de sesión clasificadas por nivel de riesgo.
  * Plan de acción y remediación en 5 minutos.

```bash
# Generar dossier HTML (por defecto, listo para Imprimir a PDF)
python -m cookieguard report

# Generar informe en formato Markdown
python -m cookieguard report --formato md --salida /ruta/informe_incidente.md
```

</details>

<details>
<summary>📋 <b>Detector Heurístico de Clipper y Auditor de Portapapeles (MITRE T1115)</b></summary>
<br>

Muchos infostealers modernos (Lumma, Stealc, RedLine) integran módulos *Clipper* para espiar el portapapeles y sustituir direcciones criptográficas o robar tokens copiados:

* **Auditoría Pasiva:** Inspecciona si el búfer de portapapeles contiene tokens JWT, cabeceras `Bearer`, claves privadas SSH/PGP, tokens de GitHub o claves de acceso AWS.
* **Detección de Objetivos Clipper:** Detecta direcciones de Bitcoin (Legacy y SegWit), Ethereum, Solana y Tron en el portapapeles para advertir al usuario antes de transacciones.
* **Purga Segura (`--limpiar` / `--clear`):** Vacía instantáneamente el portapapeles para eliminar secretos volátiles de la memoria antes de que puedan ser leídos por malware en segundo plano.

```bash
# Auditar el portapapeles actual
python -m cookieguard clipboard

# Vaciar y purgar el portapapeles inmediatamente
python -m cookieguard clipboard --limpiar
```

</details>

<details>
<summary>🖥️ <b>Manual de la Interfaz Gráfica (GUI) - Explicación de Cada Botón</b></summary>
<br>

La interfaz gráfica (`python -m cookieguard.gui`) ofrece una consola de control intuitiva para gestionar la seguridad local:

| Botón / Control | Función Exacta | Motivo de Seguridad |
| :--- | :--- | :--- |
| **🔍 Analizar Ahora** | Ejecuta un escaneo completo inmediato de todos los perfiles de navegadores detectados (Chrome, Edge, Firefox, Brave, Opera, etc.). | Permite auditar el estado del equipo bajo demanda tras sospechar de un archivo descargado o enlace dudoso. |
| **📊 Abrir Dashboard Web** | Abre el panel visual local en tu navegador con el desglose de sesiones organizadas por nivel de riesgo (Crítico, Alto, Medio). | Facilita una visión panorámica clara de qué cuentas están en riesgo sin revelar información confidencial. |
| **🚪 Cerrar Sesiones** | Abre directamente la página oficial de gestión de sesiones activas del servicio seleccionado (o copia la URL si el navegador bloquea ventanas emergentes). | Es la acción prioritaria: destruye el token de sesión en los servidores del proveedor, invalidando la cookie robada. |
| **🔑 Cambiar Clave** | Conduce a la sección de cambio de contraseña del servicio correspondiente. | Asegura que el atacante no pueda volver a iniciar sesión si también obtuvo credenciales en texto plano. |
| **🛡️ Permisos OAuth** | Abre la consola de aplicaciones y tokens de terceros conectados a tu cuenta. | Los atacantes a menudo se otorgan permisos OAuth de persistencia para mantener acceso incluso tras cambiar la clave. |
| **✅ Marcar Revisado** | Registra localmente que una sesión o alerta ha sido verificada y mitigada por el usuario. | Evita la fatiga de alertas y mantiene un control riguroso de qué cuentas faltan por sanear. |
| **📦 Generar Snapshot de Incidente** | Crea un archivo ZIP comprimido con metadatos del incidente, hashes, procesos activos y registros forenses (con cifrado AES-GCM opcional). | Preserva la evidencia inmutable para análisis forense posterior o reporte corporativo sin filtrar datos sensibles. |
| **♻️ Restaurar Estado** | Restablece las reglas de firewall y configuraciones previas aplicadas durante una contención de emergencia. | Permite reanudar la actividad normal de forma segura una vez el incidente ha sido resuelto. |
| **⚙️ Ajustes de Hardening** | Aplica medidas preventivas locales (auditoría de Defender, LSA Protection RunAsPPL en Windows, sysctl ptrace_scope y fs.protected_regular en Linux). | Reduce la superficie de ataque del sistema frente a volcados de LSASS o infecciones en directorios temporales. |
| **🧰 Pestaña: Herramientas** | Panel integrado en la GUI que reúne en 1 clic los módulos avanzados de auditoría, respuesta e incidentes. | Centraliza el acceso visual a las funciones forenses sin necesidad de abrir la terminal. |
| **🚦 Semáforo de Estado** | Diagnóstico ejecutivo inmediato con cálculo de severidad y 3 acciones urgentes guiadas. | Ofrece respuesta guiada a usuarios no técnicos en situaciones de estrés por incidente. |
| **📋 Auditar Portapapeles (Clipper)** | Inspecciona el portapapeles local en busca de tokens JWT expuestos, credenciales y criptodirecciones. | Detecta troyanos Clipper (MITRE T1115) antes de pegar direcciones financieras o credenciales. |
| **🧹 Purgar Portapapeles** | Vacía instantáneamente la memoria del portapapeles en Windows y Linux. | Evita que malware en segundo plano capture secretos copiados temporalmente. |
| **⏰ Auditar Persistencia** | Analiza claves Registry Run/RunOnce, tareas `schtasks`, systemd user units y autostart XDG. | Detecta mecanismos de arraigo de infostealers que sobreviven al reinicio del sistema. |
| **🌐 Auditar Hosts y DNS** | Comprueba redirecciones maliciosas en `hosts` y servidores DNS activos (`netsh`/resolv.conf). | Previene ataques de sinkholing y suplantación de portales de autenticación legítimos. |
| **🔏 Integridad de Binarios** | Valida firmas digitales Authenticode en Windows y permisos/rutas de sistema en Linux. | Detecta DLL hijacking, binarios suplantados o wrappers maliciosos en navegadores. |
| **🎯 Ejecutar Simulacro (Drill)** | Despliega un sandbox temporal con perfiles señuelo y prueba la cadena de detección y contención. | Permite ensayar la respuesta a incidentes de forma 100% segura y controlada. |
| **📄 Generar Dossier MITRE** | Genera un informe forense formal HTML/PDF-ready alineado con las matrices de MITRE ATT&CK. | Documenta técnicamente el incidente para auditorías, seguros cibernéticos o equipos SOC. |
| **📖 Playbook de Revocación** | Abre la checklist interactiva de revocación con enlaces oficiales directos para más de 35 servicios. | Agiliza la invalidación de sesiones y tokens OAuth en minutos tras una exfiltración. |

</details>

<details>
<summary>⌨️ <b>Referencia Completa de Comandos CLI</b></summary>
<br>

CookieGuard incluye una potente interfaz de línea de comandos para administradores, entornos headless y auditorías automatizadas:

```bash
# Diagnóstico y Análisis (Soporte comandos en Español e Inglés)
python -m cookieguard resumen                # Resumen semafórico ejecutivo en 3 pasos (alias: dummy)
python -m cookieguard analizar               # Escaneo forense de sesiones de navegador (alias: scan)
python -m cookieguard vigilar                # Monitorización continua en segundo plano (alias: watch)
python -m cookieguard gui                    # Apertura de la consola gráfica interactiva

# Caza, Portapapeles y Persistencia
python -m cookieguard clipper                # Auditoría de portapapeles y clipper malware (alias: clipboard)
python -m cookieguard clipper --limpiar      # Purga inmediata del contenido del portapapeles
python -m cookieguard persistencia           # Auditoría de tareas, Registro y autostart (alias: persistence)
python -m cookieguard integridad             # Verificación de firmas e integridad de binarios (alias: integrity)
python -m cookieguard red                    # Detección de sinkholing en archivo hosts y DNS (alias: network, hosts)

# Entrenamiento, Reportes y Contención
python -m cookieguard simulacro              # Simulacro de incidente en vivo (alias: drill)
python -m cookieguard informe --formato html # Generación de informe forense MITRE ATT&CK (alias: report, dossier)
python -m cookieguard killswitch --block     # Bloqueo inmediato de red saliente
python -m cookieguard killswitch --restore   # Restauración de conectividad de red
python -m cookieguard snapshot               # Generación de snapshot forense cifrado con AES-GCM
python -m cookieguard playbook --format html # Generación de guía de revocación offline interactiva
```

*Para ver todas las opciones disponibles en cualquier comando, utiliza el flag `--help` (ejemplo: `python -m cookieguard drill --help`).*

</details>

<details>
<summary>🪟🐧 <b>Paridad y Compatibilidad Multiplataforma (Windows y Linux)</b></summary>
<br>

CookieGuard implementa una arquitectura modular que garantiza paridad funcional entre entornos Windows y Linux, utilizando en cada uno los mecanismos nativos óptimos del sistema operativo sin dependencias externas:

| Área Funcional | Implementación en Windows | Implementación en Linux |
| :--- | :--- | :--- |
| **Auditoría de Persistencia** | Inspección de claves del Registro `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` y `RunOnce`, `HKLM`, tareas de `schtasks /query` y carpeta `Startup`. | Inspección de unidades de usuario `systemd --user` (`~/.config/systemd/user/`), entradas autostart de escritorio (`~/.config/autostart`, `/etc/xdg/autostart`) y tareas `crontab -l`. |
| **Auditoría de Red y DNS** | Análisis del archivo `%SystemRoot%\System32\drivers\etc\hosts` y resolución de servidores DNS activos vía `netsh interface ipv4 show dnsservers` con fallback a PowerShell. | Análisis del archivo `/etc/hosts` y extracción de servidores DNS configurados en `/etc/resolv.conf`. |
| **Portapapeles y Clipper** | Lectura y vaciado de portapapeles mediante llamadas directas Win32 API (`ctypes.windll.user32` `OpenClipboard`/`EmptyClipboard`) con fallback a `powershell Get-Clipboard` / `Set-Clipboard`. | Lectura y vaciado mediante herramientas estándar de entorno gráfico Wayland/X11 (`wl-paste`/`wl-copy`, `xclip`, `xsel`). En terminales headless o sin display, degrada de forma segura sin excepciones. |
| **Integridad de Binarios** | Validación de firmas digitales Authenticode mediante `Get-AuthenticodeSignature` en PowerShell, contrastando firmantes legítimos (*Google LLC, Microsoft Corporation, Mozilla Corporation*). | Inspección de permisos de archivo, comprobación de rutas canónicas de sistema (`/usr/bin`, `/bin`, `/opt`), y detección de flags o permisos SUID anómalos. |
| **Hardening y Protección del Núcleo** | Comprobación de estado de Windows Defender (Protección en tiempo real, Tamper Protection, PUA), reglas ASR y auditoría de **LSA Protection (`RunAsPPL`)** para prevenir volcados de LSASS en memoria. | Inspección de variables del kernel en `/proc/sys`: `kernel.yama.ptrace_scope` (evita inyecciones de memoria entre procesos), `fs.protected_regular` y `fs.protected_fifos` (bloquea escrituras no autorizadas en `/tmp`). |
| **Aislamiento de Emergencia (Killswitch)** | Modificación de reglas del Firewall de Windows mediante `netsh advfirewall firewall` bloqueando tráfico saliente hacia direcciones públicas con exclusión de loopback local. | Aislamiento a través de `iptables` / `ip6tables` cerrando interfaces externas o desactivación de interfaces con `nmcli networking off`. |
| **Notificaciones en Escritorio** | Notificaciones nativas interactivas en Windows mediante PowerShell Toast / Balloon notifications con botones de respuesta rápida. | Notificaciones D-Bus mediante `notify-send --action` o apertura de URL con `xdg-open`. |

</details>

<details>
<summary>🔍 <b>Catálogo Forense de Indicadores Heurísticos (I01 a I20 + MITRE ATT&CK)</b></summary>
<br>

CookieGuard evalúa el sistema frente a un catálogo formal de 20 indicadores mapeados contra el marco global MITRE ATT&CK:

| ID | Indicador | Técnica MITRE | Severidad | Descripción y Criterio de Detección |
| :---: | :--- | :---: | :---: | :--- |
| **I01** | *SQLite Lock Contention* | T1539 | 🟡 Media | Apertura forzada de la base de datos de cookies por un proceso externo con el navegador abierto. |
| **I02** | *Anomalía de Timestamp WAL* | T1070.006 | 🟠 Alta | Desincronización temporal entre el archivo SQLite principal y el diario Write-Ahead Log (*Time-Stomping*). |
| **I03** | *Lectura Masiva de Cookies* | T1539 | 🔴 Crítica | Acceso secuencial rápido a múltiples entradas de sesión en menos de 2 segundos. |
| **I04** | *Consulta de Clave DPAPI/Secret Service* | T1555.003 | 🔴 Crítica | Proceso no firmado o no autorizado solicitando acceso a las claves maestras de cifrado del navegador. |
| **I05** | *Proceso Sospechoso en Memoria* | T1057 / T1059 | 🔴 Crítica | Ejecutable no firmado corriendo desde directorios temporales (`%TEMP%`, `/dev/shm`, `/tmp`). |
| **I06** | *Suplantación de Nombre (Masquerading)* | T1036.005 | 🔴 Crítica | Proceso con nombre engañoso (`chrome_updater.exe`, `svchost.exe` fuera de System32). |
| **I07** | *Persistencia en Tareas / Crontab* | T1053 | 🟠 Alta | Tarea programada oculta o con flags sospechosos (`-WindowStyle Hidden`, scripts en base64). |
| **I08** | *Manipulación de Archivo Hosts* | T1565.001 | 🔴 Crítica | Dominios de antivirus o actualización redirigidos a `127.0.0.1` (*Security Sinkholing*). |
| **I09** | *Certificado Raíz MITM No Oficial* | T1557 / T1556 | 🔴 Crítica | Presencia de CA raíz asociada a herramientas de intercepción TLS (mitmproxy, Burp Suite, Fiddler). |
| **I10** | *Proxy Local No Autorizado* | T1090.001 | 🟠 Alta | Tráfico redirigido a `localhost` mediante variables de entorno o scripts PAC sospechosos. |
| **I11** | *Extensión con Patrón Exfiltrador* | T1176 | 🔴 Crítica | Código JavaScript en extensiones con llamadas a webhooks de Discord, bots de Telegram o `cookies.getAll`. |
| **I12** | *Descarga de Binario de Alto Riesgo* | T1204.002 | 🟡 Media | Registro reciente de descargas de extensiones ejecutables (`.exe`, `.scr`, `.bat`) desde sitios dudosos. |
| **I13** | *Canary Cookie Alterada* | T1539 | 🔴 Crítica | Lectura o eliminación del token trampa señuelo sembrado en el perfil del navegador. |
| **I14** | *Binario de Navegador Modificado* | T1574 | 🔴 Crítica | Ejecutable principal de Chrome, Edge o Firefox con firma digital inválida o bandera SUID anómala. |
| **I15** | *Manipulación de Acceso Directo (.lnk)* | T1547.009 | 🟠 Alta | Acceso directo del navegador modificado para inyectar flags de proxy, depuración o ejecución maliciosa. |
| **I16** | *Desincronización de Perfiles Cloud* | T1539 | 🟡 Media | Detección de perfil local activo desconectado o sincronizando con cuentas ajenas. |
| **I17** | *Anomalía de Freelist SQLite* | T1070 | 🟠 Alta | Base de datos con más del 40% de páginas libres, indicio de borrado masivo de registros para ocultar huellas. |
| **I18** | *Objetivo de Escritorio Comprometido* | T1555 | 🟠 Alta | Extracción de metadatos o tokens en aplicaciones como Slack, Postman, Obsidian o Notion Desktop. |
| **I19** | *Tráfico Anómalo / C2 Heurístico* | T1071.001 | 🔴 Crítica | Conexión saliente rápida tras evento de lectura de base de datos hacia servidores desconocidos. |
| **I20** | *Exposición / Secuestro de Portapapeles* | T1115 | 🔴 Crítica | Tokens activos (JWT, API Keys) o criptodirecciones expuestas en portapapeles sujetas a malware clipper. |

</details>

<details>
<summary>🧰 <b>Modo Rescate USB (Triage Forense sin Huella)</b></summary>
<br>

Puedes copiar CookieGuard en una memoria USB formateada y ejecutarlo en cualquier ordenador afectado sin instalar Python ni escribir en el disco del sistema:

1. **Preparación del USB:**
   Copia el directorio de CookieGuard o el ejecutable compilado en el pendrive.
2. **Ejecución en Solo Lectura:**
   ```bash
   # En Windows
   E:\CookieGuard\cookieguard.exe dummy --no-write
   
   # En Linux
   /media/usb/CookieGuard/cookieguard dummy --no-write
   ```
3. **Extracción Segura de Evidencia:**
   Los informes generados se guardan directamente en el pendrive para no alterar las marcas de tiempo (`MACB`) del disco de la víctima.

</details>

<details>
<summary>🚨 <b>Protocolo de Respuesta ante Incidente Confirmado (5 Minutos)</b></summary>
<br>

Si el semáforo se sitúa en **🔴 ROJO** o confirmas un acceso no autorizado:

1. **Aislar de Inmediato:**
   Ejecuta `python -m cookieguard killswitch --activar` o desconecta físicamente el cable de red / Wi-Fi.
2. **Revocar Sesiones Críticas (Desde otro dispositivo limpio o tras cortar la red):**
   Abre `checklist_revocacion.html` y pulsa **Cerrar Sesiones** en:
   - Proveedores de identidad (Google, Microsoft, Apple).
   - Gestores de repositorios y nube (GitHub, GitLab, AWS, Azure).
   - Correo electrónico principal y servicios financieros.
3. **Generar Evidencia:**
   Genera un informe formal o snapshot forense con `python -m cookieguard report` y `python -m cookieguard snapshot`.
4. **Desinfectar y Restaurar:**
   Revisa los procesos y tareas detectadas con `process-hunter`, `clipboard --limpiar` y `persistence`, elimina la amenaza y restablece la red con `killswitch --desactivar`.

</details>

<details>
<summary>🌐 <b>Matriz de Compatibilidad (Navegadores y Aplicaciones de Escritorio)</b></summary>
<br>

* **Navegadores Basados en Chromium:** Google Chrome, Microsoft Edge, Brave, Opera, Vivaldi, Arc.
* **Navegadores Basados en Gecko:** Mozilla Firefox, Floorp, LibreWolf, Waterfox.
* **Aplicaciones de Escritorio (SaaS & Electron):** Slack Desktop, Postman Desktop, Discord, Notion Desktop, Obsidian Desktop.
* **Sistemas Operativos:**
  * Windows 10 (21H2+) y Windows 11 (x64 / ARM64).
  * Distribuciones Linux modernas (Ubuntu 20.04+, Debian 11+, Fedora 38+, Arch Linux, Pop!_OS).

</details>

<details>
<summary>❓ <b>Preguntas Frecuentes (FAQ)</b></summary>
<br>

* **¿CookieGuard sustituye a mi antivirus o EDR?**  
  No. CookieGuard es una capa de defensa especializada en sesiones y robo de identidad (*Identity Threat Detection & Response - ITDR*). Se complementa perfectamente con cualquier solución antivirus o EDR existente.
* **¿CookieGuard lee mis contraseñas o mis mensajes?**  
  Absolutamente no. Funciona bajo estrictos principios Zero-Trust: únicamente audita metadatos de archivos (tamaño, fechas de modificación, bloqueos de lectura) y procesos del sistema.
* **¿Por qué no descifra las cookies para verificar si están activas?**  
  Por diseño ético y seguridad. Descifrar cookies expondría tus credenciales en memoria, convirtiendo a la herramienta en un objetivo para otros atacantes. CookieGuard prefiere protegerte sin asumir jamás la posesión de tus secretos.
* **¿Requiere permisos de Administrador / Root?**  
  Para la auditoría básica de cookies y semáforo dummy **no** requiere privilegios elevados. Para la activación del Killswitch de firewall o ciertas comprobaciones de tareas de sistema sí requerirá elevación de privilegios.

</details>

---

## 🔒 Privacidad y Compromiso Zero-Trust

* **Sin Conexión a Servidores Externos:** No existe telemetría, analíticas de uso ni comunicación con servidores propios.
* **Código 100% Auditable:** Sin binarios opacos ni ofuscados. Todo el código fuente está disponible y estructurado en módulos legibles de Python estándar.
* **Sin Dependencias Obligatorias:** El núcleo completo funciona exclusivamente con la biblioteca estándar de Python (`sqlite3`, `ctypes`, `subprocess`, `urllib`, `hashlib`, `tkinter`).

---

## ⚖️ Licencia y Descargo Legal

Distribuido bajo la licencia **MIT**. Consulta el archivo `LICENSE` para más información.

*Descargo de responsabilidad: CookieGuard es una herramienta defensiva y de concienciación de seguridad. Los indicadores heurísticos son señales de alerta preventiva y no constituyen una certificación pericial infalible ni garantía de invulnerabilidad. El usuario es el único responsable de las acciones de revocación y administración de sus cuentas.*
