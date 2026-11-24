# 🐧 Guía Oficial de CookieGuard para Linux

> **Instrucciones completas para despliegue, auditoría, vigilancia y respuesta a incidentes en distribuciones Linux (Ubuntu, Debian, Fedora, Arch, RHEL).**  
> *100% Local-first, sin telemetría y sin dependencias externas.*

---

## 🚀 Inicio Rápido con Scripts de Bash (.sh)

En esta carpeta dispones de scripts listos para ejecutar directamente desde la terminal:

| Script | Acción que Realiza |
| :--- | :--- |
| **`cookieguard.sh`** | Lanzador principal de la interfaz gráfica y análisis forense. |
| **`analizar_ahora.sh`** | Ejecuta un escaneo forense completo y muestra el semáforo en terminal. |
| **`asistente_rescate.sh`** | **EMERGENCIA:** Detiene navegadores y genera el plan táctico de rotación de claves. |
| **`auditar_descargas.sh`** | Audita las descargas recientes de Chromium y Firefox buscando malware. |
| **`trampa_canary.sh`** | Despliega y verifica trampas cebo SQLite en carpetas de perfiles locales. |
| **`aislar_red.sh`** | **CONTENCIÓN:** Corta la conectividad mediante `nmcli` o reglas `iptables`. |
| **`restaurar_red.sh`** | Reactiva las interfaces de red y restablece el tráfico saliente. |
| **`instalar_servicio.sh`** | Configura e inicia el servicio en segundo plano mediante `systemd --user`. |
| **`desinstalar_servicio.sh`**| Detiene y elimina el servicio de `systemd`. |
| **`rescate-usb.sh`** | Modo pendrive USB: genera informe interactivo sin escribir en disco infectado. |

---

## 💻 Ejemplos de Uso en Terminal (Bash / Zsh)

Abre tu terminal en la raíz del proyecto:

### 1. Diagnóstico Semáforo en 10 Segundos
```bash
python3 -m cookieguard dummy
```

### 2. Protocolo de Rescate en Caso de Robo Confirmado
```bash
python3 -m cookieguard rescue --auto
```
*Detiene los navegadores de forma segura y genera un informe interactivo HTML con el orden de rotación táctica de tus cuentas principales.*

### 3. Cazar la Descarga Maliciosa que Originó la Infección
```bash
python3 -m cookieguard descargas --hours 48
```
*Examina las bases de datos de descargas (`History` y `places.sqlite`) buscando ejecutables con doble extensión, scripts maliciosos o archivos procedentes de canales sospechosos de Discord o Telegram.*

### 4. Vigilancia Activa con Trampa Cebo (Canary Trap)
```bash
# Desplegar trampas señuelo en perfiles de navegador:
python3 -m cookieguard trap --deploy

# Comprobar si algún proceso ajeno ha leído o tocado el archivo señuelo:
python3 -m cookieguard trap --check

# Monitor continuo en bucle:
python3 -m cookieguard trap --watch --interval 5
```

### 5. Cortafuegos de Emergencia (Killswitch)
```bash
# Aislar tráfico de red (contención):
python3 -m cookieguard killswitch --activar

# Restaurar la conexión normal:
python3 -m cookieguard killswitch --desactivar
```

---

## 🛡️ Características Específicas de Linux

1. **Inspección de Descriptores en `/proc/[pid]/fd`:**  
   Detecta qué procesos no autorizados tienen abiertos los ficheros SQLite de cookies (`Cookies`, `cookies.sqlite`) sin necesidad de permisos de superusuario (`root`) para procesos de tu mismo usuario.
2. **Notificaciones de Escritorio con `notify-send`:**  
   Emite alertas nativas vía D-Bus con nivel de urgencia crítico (`-u critical`) y apertura directa con `xdg-open`.
3. **Servicio Nativo `systemd --user`:**  
   Permite ejecución continua y arranque automático sin tocar carpetas del sistema operativo.
