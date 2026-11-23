# 🛡️ CookieGuard

> **Monitor local de integridad para cookies de sesión de navegadores (Chrome, Firefox, Edge, Brave). Detección de accesos no autorizados, Killswitch de red y respuesta rápida ante exfiltración de infostealers.**

![Versión](https://img.shields.io/badge/Versi%C3%B3n-1.2.0-blue)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Plataformas](https://img.shields.io/badge/Plataformas-Windows%20%7C%20Linux-brightgreen)
![Privacidad](https://img.shields.io/badge/Privacidad-100%25%20Offline-red)
![Dependencias](https://img.shields.io/badge/Dependencias-Zero%20(Solo%20Stdlib)-orange)
![Licencia](https://img.shields.io/badge/Licencia-MIT-purple)

---

## 🎮 Demos y Simulaciones Interactivas en Vivo (Prueba online en tu navegador)

Puedes probar de forma interactiva e inmediata cómo responde CookieGuard ante un incidente real sin instalar nada:

- 🌐 **[Abrir Centro de Demos en Vivo (GitHub Pages)](https://4n0d1n.github.io/CookieGuard/)**
- 🖥️ **[Lanzar Demo Windows 11 Online](https://4n0d1n.github.io/CookieGuard/docs/simulaciones/simulacion_incidente_windows.html)** *(Recrea el Toast nativo flotante de Windows 11, telemetría DPAPI, triaje forense y Killswitch de red)*
- 🐧 **[Lanzar Demo Linux Desktop Online](https://4n0d1n.github.io/CookieGuard/docs/simulaciones/simulacion_incidente_linux.html)** *(Recrea la alerta D-Bus notify-send, trazado de descriptores en /proc/[pid]/fd y aislamiento con iptables/nftables)*

*(Ambas simulaciones son interactivas en HTML5/Tailwind, ejecutables en cualquier navegador tanto online vía GitHub Pages como offline abriendo los archivos locales).*

---

## 🎯 ¿Qué problema resuelve CookieGuard?

Los **infostealers modernos** (Lumma, Redline, Stealc, Vidar, Rhadamanthys) no buscan contraseñas almacenadas: su botín principal son las **cookies de sesión activas** almacenadas en las bases de datos SQLite de tus navegadores.

Con estas cookies, un ciberdelincuente puede:
- Clonar tu sesión autenticada en su propio equipo.
- **Evadir completamente el factor de doble autenticación (2FA / MFA).**
- Tomar control inmediato de cuentas de Google Workspace, GitHub, Microsoft 365, AWS o portales financieros sin disparar avisos de cambio de contraseña.

**CookieGuard actúa como un radar y escudo local:**
1. **Inventaría:** Identifica qué sesiones críticas tienes abiertas en tus navegadores.
2. **Vigila en tiempo real:** Detecta si procesos desconocidos intentan leer tus bases de cookies.
3. **Alerta y responde:** Te avisa con un popup interactivo en tu sistema y abre un panel en tu navegador con enlaces directos en 1-clic para revocar las sesiones comprometidas.
4. **Aisla la red (Killswitch):** Corta el tráfico saliente para evitar que el stealer suba las cookies a sus servidores de mando y control (C2).
5. **Cebos Canary:** Planta cookies trampa cuya lectura delata inequívocamente al atacante.
6. **Alertas móviles (Webhook):** Notifica de inmediato a tu móvil mediante ntfy.sh o Discord ante incidentes críticos.

---

## 🔒 Principios de Privacidad y Seguridad (Zero-Trust)

- **100% Offline:** CookieGuard **NUNCA** envía tus datos ni credenciales fuera de tu equipo.
- **Solo Metadatos:** **NUNCA** descifra ni almacena los valores de tus cookies o contraseñas. Solo lee metadatos (nombre de cookie, dominio, fecha de expiración).
- **Cero Dependencias Externas:** Funciona exclusivamente con la biblioteca estándar de Python y herramientas nativas del sistema operativo (`netsh`, `iptables`, `curl`, PowerShell). Sin paquetes `pip` de terceros que puedan ser comprometidos en la cadena de suministro.

---

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
│   ├── detections.py                   # 13 Indicadores heurísticos y MITRE ATT&CK
│   ├── inventory.py                    # Inventario de sesiones por navegador
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

El proyecto incluye 39 pruebas unitarias automatizadas que garantizan el correcto funcionamiento y el cumplimiento estricto de los requisitos de privacidad:

```bash
python3 -m unittest discover -s tests -v
```

Las pruebas de seguridad (`tests/test_seguridad.py`) validan que en ningún momento se importen librerías de red directas para extraer datos sensibles ni se intente leer valores de cookies.
