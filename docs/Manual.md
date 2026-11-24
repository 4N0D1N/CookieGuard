# 📖 Manual Completo de Uso de CookieGuard (Windows y Linux)

> **Guía integral y unificada de operación, auditoría, vigilancia y respuesta a incidentes con CookieGuard v2.4.0.**  
> *Diseñado para usuarios particulares, administradores de sistemas y equipos de respuesta a incidentes (DFIR).*

---

## 📑 Índice General

1. [Filosofía, Privacidad y Arquitectura](#1-filosofía-privacidad-y-arquitectura)
2. [Instalación y Puesta en Marcha](#2-instalación-y-puesta-en-marcha)
   - [Guía Rápida para Windows 10 / 11](#guía-rápida-para-windows-10--11)
   - [Guía Rápida para Linux (Ubuntu, Debian, Fedora, Arch)](#guía-rápida-para-linux-ubuntu-debian-fedora-arch)
3. [El Semáforo "Modo Dummy" (Diagnóstico en 10 Segundos)](#3-el-semáforo-modo-dummy-diagnóstico-en-10-segundos)
4. [Escenarios Prácticos de Uso Paso a Paso](#4-escenarios-prácticos-de-uso-paso-a-paso)
   - [Escenario A: "Creo que me han infectado o robado las cookies" (Asistente de Rescate)](#escenario-a-creo-que-me-han-infectado-o-robado-las-cookies)
   - [Escenario B: "¿Qué archivo o descarga introdujo el malware?" (Auditor de Descargas)](#escenario-b-qué-archivo-o-descarga-introdujo-el-malware)
   - [Escenario C: "Dejar un señuelo para cazar infostealers antes de que roben" (Trampa Activa)](#escenario-c-dejar-un-señuelo-para-cazar-infostealers-antes-de-que-roben)
   - [Escenario D: "Aislamiento de Emergencia" (Killswitch de Red)](#escenario-d-aislamiento-de-emergencia-killswitch-de-red)
   - [Escenario E: "Rotación Segura de Contraseñas y Sesiones" (Playbook Offline)](#escenario-e-rotación-segura-de-contraseñas-y-sesiones)
   - [Escenario F: "Chequeo Médico Integral del Equipo" (Doctor de Sensores)](#escenario-f-chequeo-médico-integral-del-equipo)
5. [Guía de la Interfaz Gráfica (GUI) y Todos sus Botones](#5-guía-de-la-interfaz-gráfica-gui-y-todos-sus-botones)
6. [Referencia Completa de Comandos CLI (Windows y Linux)](#6-referencia-completa-de-comandos-cli-windows-y-linux)
7. [Diferencias Técnicas por Plataforma](#7-diferencias-técnicas-por-plataforma)
8. [Preguntas Frecuentes y Resolución de Problemas](#8-preguntas-frecuentes-y-resolución-de-problemas)

---

## 1. Filosofía, Privacidad y Arquitectura

CookieGuard fue creado para resolver una amenaza crítica: **los infostealers modernos (Lumma, Stealc, RedLine, Vidar, Meduza)** no rompen contraseñas mediante fuerza bruta ni eluden el segundo factor (2FA). Su técnica consiste en leer directamente los archivos SQLite de cookies y credenciales del navegador (`Cookies`, `cookies.sqlite`, `Login Data`), empaquetarlos en un archivo ZIP y exfiltrarlos hacia canales de mando y control (C2) en Telegram, Discord o servidores web maliciosos.

### Principios Fundamentales
* **100% Local-first y Cero Telemetría:** CookieGuard no envía ningún dato a internet. No hay servidores de recopilación, no hay Google Analytics ni identificadores personales.
* **Privacidad Estricta de Credenciales:** CookieGuard **NUNCA** descifra, lee ni muestra los valores secretos de tus cookies o contraseñas. Solo audita metadatos: fechas de creación, caducidad, nombres de dominio, atributos de seguridad (`Secure`, `HttpOnly`, `SameSite`) y qué procesos acceden a los archivos en disco.
* **Cero Dependencias Externas Obligatorias:** Todo el motor nuclear funciona exclusivamente con la biblioteca estándar de Python 3.10+ (`sqlite3`, `hashlib`, `tkinter`, `urllib`).

---

## 2. Instalación y Puesta en Marcha

### Guía Rápida para Windows 10 / 11

#### Opción 1: Ejecutable Autónomo (Sin necesidad de instalar Python)
1. Descarga el paquete `CookieGuard-Windows-x64.zip` desde la sección de **Releases** de GitHub.
2. Descomprímelo en cualquier carpeta (por ejemplo, `C:\Herramientas\CookieGuard` o en un pendrive USB).
3. Haz doble clic en `CookieGuard.exe` o en `Abrir CookieGuard.cmd`.

#### Opción 2: Usando Python (Recomendado para desarrolladores y administradores)
1. Asegúrate de tener Python 3.10 o superior instalado con la opción *"Add Python to PATH"* marcada.
2. Abre una ventana de **PowerShell** o **CMD**:
   ```powershell
   git clone https://github.com/4N0D1N/CookieGuard.git
   cd CookieGuard
   ```
3. Ejecución inmediata del diagnóstico semáforo:
   ```powershell
   python -m cookieguard dummy
   ```
4. Para abrir la consola visual de escritorio:
   ```powershell
   python -m cookieguard gui
   ```
5. *(Opcional)* Registrar la vigilancia automática en segundo plano al iniciar sesión:
   ```powershell
   .\windows\Instalar_vigilante.cmd
   ```

---

### Guía Rápida para Linux (Ubuntu, Debian, Fedora, Arch)

#### Opción 1: Ejecutable Autónomo Linux
1. Descarga `CookieGuard-Linux-x64.tar.gz` desde GitHub Releases.
2. Extrae y ejecuta:
   ```bash
   tar -xzf CookieGuard-Linux-x64.tar.gz
   cd CookieGuard
   ./CookieGuard
   ```

#### Opción 2: Usando Python
1. Comprueba tu versión de Python (`python3 --version` ≥ 3.10). En Debian/Ubuntu, instala el soporte de interfaz gráfica si vas a usar la GUI:
   ```bash
   sudo apt update && sudo apt install python3-tk
   ```
2. Clona y accede al repositorio:
   ```bash
   git clone https://github.com/4N0D1N/CookieGuard.git
   cd CookieGuard
   ```
3. Ejecuta el diagnóstico rápido en la terminal:
   ```bash
   python3 -m cookieguard dummy
   ```
4. Abre la interfaz gráfica nativa:
   ```bash
   python3 -m cookieguard gui
   ```
5. *(Opcional)* Activar el servicio en segundo plano con `systemd`:
   ```bash
   ./linux/instalar_vigilante.sh
   # O mediante el comando interno:
   python3 -m cookieguard service install
   ```

---

## 3. El Semáforo "Modo Dummy" (Diagnóstico en 10 Segundos)

El comando `dummy` (o su alias en español `resumen`) está pensado para que cualquier persona, sin importar sus conocimientos técnicos, sepa exactamente cómo está su equipo:

```bash
# Windows
python -m cookieguard dummy

# Linux
python3 -m cookieguard dummy
```

### Significado de los Colores

| Color | Estado | Significado Técnico | Acción Inmediata |
| :---: | :---: | :--- | :--- |
| 🟢 | **VERDE** | Sistema limpio. Sin accesos anómalos a bases de datos, sin malware en memoria, ni alteraciones en hosts/DNS. | No tienes que hacer nada. Tu equipo está en orden. |
| 🟡 | **AMARILLO** | Advertencia. Hay sesiones críticas activas en servicios sensibles, tareas sospechosas o directivas débiles. | Revisa las sesiones abiertas y cierra las que no utilices. |
| 🔴 | **ROJO** | **ALERTA CRÍTICA**. Posible infostealer en ejecución, trampa canary activada, secuestro de red o exfiltración. | **Activa el Protocolo de Rescate (`rescue`)** y aísla la red. |

---

## 4. Escenarios Prácticos de Uso Paso a Paso

### Escenario A: "Creo que me han infectado o robado las cookies"
**El peligro:** Si abres el navegador en un equipo infectado para cambiar las contraseñas, el infostealer volverá a capturar las nuevas credenciales.
**La solución con CookieGuard:** El **Asistente de Rescate Cero-Confianza (`rescue`)**.

#### En Windows:
```powershell
python -m cookieguard rescue --auto
```
#### En Linux:
```bash
python3 -m cookieguard rescue --auto
```

**Qué hace automáticamente:**
1. Congela y cierra de forma segura los procesos de navegadores abiertos para evitar que sigan escribiendo cookies en memoria.
2. Genera un informe interactivo HTML (`reporte_rescate_*.html`) con el **orden táctico de rotación de contraseñas**:
   * **Fase 1 (Crítico):** Correo electrónico principal (Gmail, Outlook) y Gestores de contraseñas (Bitwarden, 1Password).
   * **Fase 2 (Crítico):** Cuentas corporativas y repositorios de código (Google Workspace, Microsoft 365, GitHub, GitLab).
   * **Fase 3 (Alto):** Banca, pasarelas de pago y cripto (PayPal, Stripe, Binance).
   * **Fase 4 (Medio):** Redes sociales y comunicación (LinkedIn, Twitter/X, Discord, Slack).
   * **Fase 5 (Medio):** Comercio electrónico y suscripciones (Amazon, Netflix).
3. ⚠️ **Regla de Oro:** CookieGuard te recuerda cambiar estas contraseñas desde otro dispositivo limpio (móvil, otra máquina) o tras aislar el equipo.

---

### Escenario B: "¿Qué archivo o descarga introdujo el malware?"
**El problema:** El 95% de las infecciones entran por descargas en navegadores (falsos cracks, PDFs con doble extensión `.pdf.exe`, instaladores en CDNs de Discord/Telegram).
**La solución:** El **Auditor de Descargas Recientes (`downloads` / `descargas`)**.

```bash
# Auditar descargas de las últimas 48 horas (por defecto):
python -m cookieguard descargas

# Auditar las últimas 72 horas con salida detallada:
python -m cookieguard descargas --hours 72
```

**Qué detecta:**
* Archivos con doble extensión maliciosa (ej. `factura_abril.pdf.exe`).
* Descargas procedentes de CDNs abusadas por actores maliciosos (`cdn.discordapp.com`, `t.me/`, servidores temporales de compartición).
* Ejecutables no firmados o scripts (`.scr`, `.vbs`, `.iso`, `.bat`, `.ps1`).

---

### Escenario C: "Dejar un señuelo para cazar infostealers antes de que roben"
**El problema:** Los infostealers hacen un barrido masivo de carpetas de usuario buscando bases de datos SQLite en milisegundos.
**La solución:** La **Trampa Activa Canary (`trap` / `trampa`)**.

```bash
# 1. Armar y desplegar trampas señuelo en perfiles de usuario:
python -m cookieguard trap --deploy

# 2. Comprobar si alguna trampa ha sido leída o alterada:
python -m cookieguard trap --check

# 3. Monitor continuo en segundo plano (aviso inmediato si alguien toca el cebo):
python -m cookieguard trap --watch --interval 3

# 4. Cuando desees retirar las trampas señuelo:
python -m cookieguard trap --cleanup
```

**Cómo funciona:**
Crea un archivo SQLite señuelo (`CookieGuard_Canary_Vault.db`) con firmas de seguridad. Si cualquier proceso no autorizado abre, modifica o lee el archivo cebo, CookieGuard dispara una alerta roja instantánea antes de que el atacante pueda procesar tus cookies reales.

---

### Escenario D: "Aislamiento de Emergencia" (Killswitch de Red)
Si confirmas un infostealer activo y necesitas cortar la exfiltración de inmediato:

#### En Windows (Usa el Firewall nativo de Windows):
```powershell
# Activar aislamiento (corta conexiones salientes hacia servidores C2)
python -m cookieguard killswitch --activar

# Ver el estado actual
python -m cookieguard killswitch --estado

# Restaurar la red una vez neutralizada la amenaza
python -m cookieguard killswitch --desactivar
```

#### En Linux (Usa NetworkManager o iptables):
```bash
python3 -m cookieguard killswitch --activar
python3 -m cookieguard killswitch --desactivar
```

---

### Escenario E: "Rotación Segura de Contraseñas y Sesiones"
Genera una checklist interactiva para más de 35 servicios web principales con enlaces directos a sus portales oficiales de seguridad:

```bash
python -m cookieguard playbook --formato ambos
```
Genera:
* `checklist_revocacion.html`: Panel web visual para marcar progresos localmente.
* `PLAYBOOK_REVOCACION.md`: Guía en Markdown para incluir en reportes técnicos.

---

### Escenario F: "Chequeo Médico Integral del Equipo"
Comprueba el estado de salud de todos los sensores locales de CookieGuard en 2 segundos:

```bash
python -m cookieguard doctor
```
Verifica compatibilidad de DPAPI/App-Bound, estado de permisos de lectura, soporte de DBSC en navegadores, registro de persistencia y estado del firewall.

---

## 5. Guía de la Interfaz Gráfica (GUI) y Todos sus Botones

Al iniciar `python -m cookieguard gui`, se abre la ventana principal con pestañas temáticas:

### 1. Pestaña Principal (Dashboard)
* **Analizar Ahora:** Ejecuta un escaneo forense completo de todas las cookies y perfiles instalados.
* **Abrir Dashboard Web:** Abre el informe visual completo en el navegador predeterminado.
* **Marcar Revisado:** Restablece las alertas pendientes una vez que has inspeccionado el sistema.
* **Crear ZIP de Incidente:** Empaqueta un archivo `.zip` con todos los metadatos forenses anonimizados para compartir con un perito o soporte técnico (sin incluir contraseñas ni valores de cookies).

### 2. Pestaña "Herramientas" (La Navaja Suiza Defensiva)

| Botón en la GUI | Qué hace exactamente |
| :--- | :--- |
| **Resumen para Dummies** | Ejecuta el análisis semáforo y muestra los 3 pasos prioritarios en lenguaje sencillo. |
| **Auditar Portapapeles (Clipper)** | Escanea el portapapeles buscando si algún troyano Clipper está reemplazando direcciones de criptomonedas o URLs. |
| **Limpiar Portapapeles** | Sobrescribe y vacía de forma segura el contenido del búfer del portapapeles. |
| **Auditar Persistencia** | Inspecciona tareas programadas (`schtasks`, `cron`), carpetas de autoarranque y claves del registro (`Run`/`RunOnce`). |
| **Auditar Red / Hosts** | Comprueba si el archivo `hosts` o la configuración DNS han sido alterados para secuestrar dominios bancarios o de login. |
| **Integridad de Binarios** | Verifica las firmas digitales Authenticode (Windows) o permisos SUID/integridad (Linux) de los ejecutables de navegadores. |
| **Modo Simulacro** | Ejecuta un simulacro de ataque sintético 100% inocuo para entrenar tus reflejos de respuesta. |
| **Generar Dossier MITRE** | Genera un informe pericial formal alineado con la matriz MITRE ATT&CK (técnicas T1539, T1555, T1055, T1115). |
| **Generar Playbook Offline** | Crea la guía interactiva offline para revocar sesiones en más de 35 servicios clave. |
| **Extensiones Locales / Dev** | Detecta extensiones cargadas en modo desarrollador (unpacked/sideloaded) que eluden los controles de las tiendas oficiales. |
| **Guardián: Comprobar Ahora** | Ejecuta una ronda de comprobación silenciosa del motor guardián de ultra bajo consumo. |
| **Exportar Metadatos / Custodia** | Genera un expediente pericial sellado con hashes criptográficos SHA-256 para aseguradoras o peritajes legales. |
| **Crear Guías de Revocación** | Genera scripts ejecutables `.ps1` (PowerShell) o `.sh` (Bash) para abrir rápidamente los portales oficiales de cambio de clave. |
| **Depuración Remota (CDP)** | Detecta si algún navegador fue lanzado con el puerto `--remote-debugging-port` activado para extraer cookies en vivo. |
| **Políticas Hardening** | Audita y genera plantillas de directivas de grupo / JSON para bloquear extensiones fraudulentas y aislar procesos. |
| **🛟 Asistente de Rescate** | Activa el protocolo de recuperación cero-confianza, congela navegadores y entrega la guía de rotación por criticidad. |
| **📥 Descargas Sospechosas** | Audita el historial de descargas de las últimas 48 horas en busca de la vía de entrada del malware. |
| **🚨 Trampa Canary Activa** | Despliega y revisa trampas señuelo SQLite con supervisión de integridad en tiempo real. |
| **🩺 Doctor / Salud de Sensores** | Ejecuta el diagnóstico de salud integral de los sensores y subsistemas de la máquina. |

---

## 6. Referencia Completa de Comandos CLI (Windows y Linux)

Todos los comandos admiten `--json` para integraciones SIEM o automatizaciones.

```bash
# Diagnóstico y Estado
python -m cookieguard dummy               # Resumen semáforo para dummies
python -m cookieguard doctor              # Diagnóstico de salud de sensores
python -m cookieguard analizar            # Análisis forense completo por terminal
python -m cookieguard version             # Imprime la versión actual (2.4.0)

# Protocolos Nuevos v2.4.0
python -m cookieguard rescue --auto       # Asistente de rescate rápido cero-confianza
python -m cookieguard descargas --hours 48 # Auditor de descargas recientes
python -m cookieguard trap --deploy       # Desplegar trampas señuelo
python -m cookieguard trap --check        # Comprobar integridad de trampas
python -m cookieguard trap --watch        # Monitor en bucle continuo de trampas
python -m cookieguard trap --cleanup      # Retirar archivos trampa

# Contención y Defensa Activa
python -m cookieguard killswitch --activar    # Aislar tráfico de red saliente
python -m cookieguard killswitch --desactivar # Restaurar red normal
python -m cookieguard clipboard --limpiar     # Purgar búfer de portapapeles

# Auditorías Específicas
python -m cookieguard persistence         # Auditar tareas programadas y autoarranque
python -m cookieguard network             # Auditar archivo hosts y configuración DNS
python -m cookieguard integrity           # Verificar firmas de binarios de navegadores
python -m cookieguard remote-debug        # Auditar puertos de depuración remota (CDP)
python -m cookieguard unpacked            # Auditar extensiones en modo desarrollador
python -m cookieguard certs               # Auditar certificados raíz y proxies MITM
python -m cookieguard db-integrity        # Auditar integridad física de SQLite
python -m cookieguard desktop-sessions    # Auditar sesiones de Discord, Telegram, Wallets
python -m cookieguard sync                # Auditar sincronización de perfiles en la nube

# Informes y Entregables
python -m cookieguard playbook            # Generar checklist de revocación HTML/MD
python -m cookieguard dossier             # Generar informe formal de incidente MITRE
python -m cookieguard custodia            # Generar expediente con cadena de custodia
python -m cookieguard stix                # Exportar alertas a formato STIX 2.1
python -m cookieguard drill               # Ejecutar simulacro seguro de incidente
```

---

## 7. Diferencias Técnicas por Plataforma

| Característica | Comportamiento en Windows | Comportamiento en Linux |
| :--- | :--- | :--- |
| **Notificaciones** | Notificaciones Toast interactivas nativas de Windows con botones de acción. | Notificaciones de escritorio mediante el estándar D-Bus / `notify-send`. |
| **Killswitch de Red** | Regla de bloqueo saliente en Firewall de Windows (`netsh advfirewall`). | Control mediante `nmcli networking off` o reglas de filtrado `iptables`. |
| **Inspección de Procesos** | Consulta a APIs de Windows y verificación Authenticode mediante `powershell Get-AuthenticodeSignature`. | Inspección nativa del pseudo-sistema `/proc/[pid]/fd`, `maps` y permisos POSIX. |
| **Servicio de Fondo** | Tarea programada en el Programador de Tareas de Windows (`schtasks`). | Servicio de usuario mediante `systemd --user` o entrada `autostart` XDG. |
| **Protección de Claves** | Detección de marcadores DPAPI y elevación App-Bound en `Local State`. | Detección de sockets de Secret Service / GNOME Keyring / KWallet. |

---

## 8. Preguntas Frecuentes y Resolución de Problemas

#### ¿CookieGuard necesita permisos de Administrador / root?
No para su uso habitual. Tanto el análisis de cookies, la inspección de descargas, el semáforo y las trampas canary funcionan con los permisos de tu usuario estándar. Solo se requieren permisos elevados si deseas activar el Killswitch de red (para modificar reglas del cortafuegos) o instalar tareas programadas de sistema.

#### ¿Al ejecutar el Asistente de Rescate se borran mis favoritos o contraseñas?
No. El asistente de rescate únicamente detiene los procesos del navegador para evitar que el malware continúe operando y genera tu plan de rotación. **No borra tus archivos personales**.

#### ¿Qué hago si el semáforo se pone en ROJO?
1. Ejecuta de inmediato: `python -m cookieguard rescue --auto`.
2. Si sospechas exfiltración activa, activa el corte de red: `python -m cookieguard killswitch --activar`.
3. Desde tu teléfono móvil o un equipo limpio, accede a tu correo principal y cambia la contraseña de inmediato revocando todas las sesiones existentes.
4. Sigue la checklist interactiva de revocación generada por CookieGuard.
