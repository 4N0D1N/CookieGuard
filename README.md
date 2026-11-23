# 🛡️ CookieGuard

> **Monitor local de integridad para cookies de sesión de navegadores (Chrome, Firefox, Edge, Brave). Detección de accesos no autorizados y respuesta rápida ante exfiltración de infostealers.**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Plataformas](https://img.shields.io/badge/Plataformas-Windows%20%7C%20Linux-brightgreen)
![Privacidad](https://img.shields.io/badge/Privacidad-100%25%20Offline-red)
![Dependencias](https://img.shields.io/badge/Dependencias-Zero%20(Solo%20Stdlib)-orange)
![Licencia](https://img.shields.io/badge/Licencia-MIT-purple)

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
3. **Alerta y responde:** Te avisa con un popup interactivo y abre un panel en tu navegador con enlaces directos en 1-clic para revocar las sesiones robadas antes de que las utilicen.

---

## 🔒 Principios de Privacidad y Seguridad (Zero-Trust)

- **100% Offline:** CookieGuard **NUNCA** envía datos fuera de tu equipo. No hay telemetría ni servidores remotos.
- **Solo Metadatos:** **NUNCA** descifra ni almacena los valores de tus cookies o contraseñas. Solo lee metadatos (nombre de cookie, dominio, fecha de expiración).
- **Cero Dependencias Externas:** Funciona exclusivamente con la biblioteca estándar de Python y herramientas nativas del sistema operativo. Sin paquetes de terceros que puedan ser comprometidos en la cadena de suministro.

---

## 📂 Estructura del Repositorio

El proyecto está organizado de forma modular, con guías y lanzadores específicos para cada sistema operativo:

```text
CookieGuard/
├── README.md                  # Documentación general y arquitectura
├── LICENSE                    # Licencia MIT
├── .gitignore                 # Filtros de archivos temporales
├── cookieguard/               # Núcleo Python multiplataforma
│   ├── engine.py              # Motor de orquestación y auditoría
│   ├── watcher.py             # Vigilante en segundo plano (Windows & Linux)
│   ├── detections.py          # Indicadores heurísticos y MITRE ATT&CK
│   ├── inventory.py           # Inventario de sesiones por navegador
│   ├── reports.py             # Generador de Dashboard HTML autónomo
│   ├── gui.py                 # Interfaz gráfica de escritorio (Tkinter)
│   ├── notify.py              # Sistema de notificaciones nativas (Toast / notify-send)
│   └── canary.py              # Sistema de cookies señuelo (canary tokens)
├── windows/                   # Entorno Windows
│   ├── README_WINDOWS.md      # Guía detallada de Windows, Sysmon y Firewall
│   ├── Abrir CookieGuard.cmd  # Lanzador de la GUI / Dashboard
│   ├── Analizar ahora.cmd     # Análisis rápido por consola
│   ├── Instalar vigilante.cmd # Instalador de tarea programada
│   └── Desinstalar vigilante.cmd
├── linux/                     # Entorno Linux
│   ├── README_LINUX.md        # Guía detallada de Linux, /proc y systemd
│   ├── cookieguard.sh         # Lanzador universal para Linux
│   ├── analizar_ahora.sh      # Análisis rápido inmediato
│   ├── instalar_servicio.sh   # Instalador de servicio systemd de usuario
│   ├── desinstalar_servicio.sh
│   └── cookieguard-watcher.service
├── catalogo/                  # Firmas de servicios web y destinos de exfiltración
├── docs/                      # Manuales técnicos, análisis forense y playbook
└── tests/                     # Batería de 32 tests automatizados y pruebas de seguridad
```

---

## 🚀 Puesta en Marcha

### En Windows
1. Descarga o clona el repositorio:
   ```cmd
   git clone https://github.com/4N0D1N/CookieGuard.git
   cd CookieGuard
   ```
2. Ejecuta `Abrir CookieGuard.cmd` o consulta la [Guía completa para Windows](windows/README_WINDOWS.md).

### En Linux
1. Descarga o clona el repositorio:
   ```bash
   git clone https://github.com/4N0D1N/CookieGuard.git
   cd CookieGuard
   chmod +x linux/*.sh
   ```
2. Ejecuta `./linux/cookieguard.sh` o consulta la [Guía completa para Linux](linux/README_LINUX.md).

---

## 📊 Navegadores Soportados

| Navegador | Motor | Windows | Linux | Detección SQLite |
| :--- | :--- | :---: | :---: | :---: |
| **Google Chrome** | Chromium | ✅ | ✅ | `Cookies` / `Network/Cookies` |
| **Microsoft Edge** | Chromium | ✅ | ✅ | `Cookies` |
| **Brave Browser** | Chromium | ✅ | ✅ | `Cookies` |
| **Mozilla Firefox** | Gecko | ✅ | ✅ | `cookies.sqlite` |
| **Opera / Opera GX** | Chromium | ✅ | ✅ | `Cookies` |
| **Vivaldi** | Chromium | ✅ | ✅ | `Cookies` |
| **LibreWolf / Waterfox** | Gecko | ✅ | ✅ | `cookies.sqlite` |

---

## 🛡️ Técnicas MITRE ATT&CK Monitorizadas

| ID Técnica | Nombre MITRE | Mecanismo de Detección en CookieGuard |
| :--- | :--- | :--- |
| **T1539** | Steal Web Session Cookie | Vigilancia de lectura en SQLite vía `/proc` y Event ID 4663 |
| **T1005** | Data from Local System | Detección de copias temporales de bases de datos en `/tmp` |
| **T1059** | Command and Scripting Interpreter | Detección de scripts padres (PowerShell, cURL, Bash, WScript) |
| **T1115** | Clipboard Data | Alertas de acceso a portapapeles tras llamadas de navegador |
| **T1057** | Process Discovery | Detección de enumeración de perfiles de navegación |

---

## 🧪 Pruebas y Calidad de Código

El proyecto cuenta con una suite completa de pruebas unitarias y de seguridad:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

Resultados: **32 tests ejecutados y pasando** (100% de éxito en inventario, cifrado, falsos positivos y aislamiento de red).

---

## 📄 Licencia

Este proyecto está bajo la Licencia **MIT**. Consulta el archivo [LICENSE](LICENSE) para más detalles.

Desarrollado y mantenido por [4N0D1N](https://github.com/4N0D1N).
