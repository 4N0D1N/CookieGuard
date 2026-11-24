# 🛡️ CookieGuard v2.0.0

> **Auditor forense y escudo defensivo local contra infostealers. Monitoriza, detecta y responde al secuestro de sesiones en navegadores y aplicaciones de escritorio. 100% Local-first, sin telemetría y sin dependencias externas obligatorias.**

![Versión](https://img.shields.io/badge/Versi%C3%B3n-2.0.0-blue)
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
| **¿QUÉ hace?** | Monitoriza las bases de datos de sesiones de tus navegadores, caza malware de robo de credenciales en ejecución, revisa la persistencia del sistema y ofrece botones inmediatos para aislar la red y revocar sesiones comprometidas. |
| **¿CÓMO lo hace?** | De forma **100% local y pasiva**. Inspecciona marcas de tiempo, descriptores de archivo abiertos, firmas digitales de ejecutables y reglas de red. **NUNCA descifra ni expone el contenido de tus cookies o contraseñas**. |
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

# 4. Abrir la Guía Interactiva de Revocación de Sesiones
# Abre docs/checklist_revocacion.html en tu navegador favorito
```

---

## 🛡️ Los 4 Pilares de CookieGuard

<details open>
<summary><b>1. 👁️ Detección y Caza de Amenazas (Watcher & Process Hunter)</b> [Clic para colapsar/desplegar]</summary>
<br>

* **Qué hace:** Vigila accesos no autorizados a las bases de datos de cookies (`Cookies`, `cookies.sqlite`) y caza procesos maliciosos en memoria.
* **Cómo lo hace:** Compara marcas de tiempo de modificación, audita descriptores de archivos abiertos y analiza la lista de procesos buscando nombres fraudulentos (`chrome_update.exe`), rutas en `%TEMP%`/`/dev/shm` o inyecciones de código.
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
<summary><b>3. 🚨 Respuesta Inmediata y Contención (Killswitch y Forense)</b> [Clic para colapsar/desplegar]</summary>
<br>

* **Qué hace:** Corta la conexión a Internet en 1 segundo ante sospecha de robo y genera una instantánea forense cifrada para análisis.
* **Cómo lo hace:** Aplica reglas nativas en el firewall del sistema operativo (`netsh advfirewall` en Windows / `iptables` o `nmcli` en Linux) y empaqueta metadatos y registros en un archivo ZIP con cifrado AES-GCM opcional.
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
| **⚙️ Ajustes de Hardening** | Aplica medidas preventivas locales (como habilitar auditoría de procesos o configurar límites de retención de cookies). | Reduce la superficie de ataque del sistema frente a futuras infecciones. |

</details>

<details>
<summary>⌨️ <b>Referencia Completa de Comandos CLI</b></summary>
<br>

CookieGuard incluye una potente interfaz de línea de comandos para administradores, entornos headless y auditorías automatizadas:

```bash
# Diagnóstico y Análisis
python -m cookieguard dummy                  # Resumen semafórico ejecutivo en 3 pasos
python -m cookieguard scan                   # Escaneo forense de sesiones de navegador
python -m cookieguard watch                  # Monitorización continua en segundo plano

# Caza y Persistencia
python -m cookieguard process-hunter         # Escaneo de procesos sospechosos e inyecciones
python -m cookieguard persistence            # Auditoría de tareas programadas y autostart
python -m cookieguard integrity              # Verificación de firmas y permisos de navegadores

# Red y Configuración
python -m cookieguard network                # Detección de sinkholing en archivo hosts y DNS
python -m cookieguard certs                  # Detección de certificados CA MITM y proxies locales
python -m cookieguard scan-extensions        # Escaneo heurístico de scripts de extensiones

# Contención y Respuesta
python -m cookieguard killswitch --block     # Bloqueo inmediato de red saliente
python -m cookieguard killswitch --restore   # Restauración de conectividad de red
python -m cookieguard snapshot --output /ruta # Generación de snapshot forense
python -m cookieguard playbook --format html # Generación de guía de revocación offline
```

*Para ver todas las opciones disponibles en cualquier comando, utiliza el flag `--help` (ejemplo: `python -m cookieguard persistence --help`).*

</details>

<details>
<summary>🔍 <b>Catálogo Forense de Indicadores Heurísticos (I01 a I19 + MITRE ATT&CK)</b></summary>
<br>

CookieGuard evalúa el sistema frente a un catálogo formal de indicadores mapeados contra el marco global MITRE ATT&CK:

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
   Ejecuta `python -m cookieguard killswitch --block` o desconecta físicamente el cable de red / Wi-Fi.
2. **Revocar Sesiones Críticas (Desde otro dispositivo limpio o tras cortar la red):**
   Abre `checklist_revocacion.html` y pulsa **Cerrar Sesiones** en:
   - Proveedores de identidad (Google, Microsoft, Apple).
   - Gestores de repositorios y nube (GitHub, GitLab, AWS, Azure).
   - Correo electrónico principal y servicios financieros.
3. **Generar Evidencia:**
   Genera un snapshot forense con `python -m cookieguard snapshot`.
4. **Desinfectar y Restaurar:**
   Revisa los procesos y tareas detectadas con `process-hunter` y `persistence`, elimina la amenaza y restablece la red con `killswitch --restore`.

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
