# 🪟 Guía Oficial de CookieGuard para Windows 10 y 11

> **Manual de despliegue, auditoría, vigilancia y respuesta a incidentes en entornos Microsoft Windows.**  
> *100% Local-first, sin telemetría y sin dependencias externas.*

---

## 🚀 Inicio Rápido con Scripts por Lotes (.cmd)

En esta carpeta dispones de scripts directos listos para ejecutar con doble clic:

| Script | Acción que Realiza |
| :--- | :--- |
| **`Abrir CookieGuard.cmd`** | Abre la interfaz gráfica nativa de escritorio o el dashboard interactivo. |
| **`Analizar ahora.cmd`** | Ejecuta un escaneo forense completo inmediato y muestra el semáforo en consola. |
| **`Asistente_de_Rescate.cmd`** | **EMERGENCIA:** Congela navegadores y entrega el plan táctico de rotación de claves. |
| **`Auditar_Descargas_Recientes.cmd`** | Audita las descargas de las últimas 48 horas en busca de la vía de entrada del malware. |
| **`Armar_Trampa_Canary.cmd`** | Despliega y verifica trampas cebo SQLite en carpetas de perfiles de usuario. |
| **`Aislar Red Killswitch.cmd`** | **CONTENCIÓN:** Corta todo el tráfico saliente mediante el Firewall de Windows (`netsh`). |
| **`Restaurar Red.cmd`** | Elimina la regla del cortafuegos y restablece la conexión a internet. |
| **`Instalar vigilante.cmd`** | Registra el vigilante en segundo plano en el Programador de Tareas de Windows. |
| **`Desinstalar vigilante.cmd`** | Elimina la tarea programada del sistema. |
| **`Rescate-USB.cmd`** | Modo pendrive USB: genera informe interactivo sin escribir en disco infectado. |

---

## 💻 Ejemplos de Uso desde PowerShell o CMD

Abre una terminal en la raíz del proyecto:

### 1. Diagnóstico Semáforo en 10 Segundos
```powershell
python -m cookieguard dummy
```

### 2. Protocolo de Rescate en Caso de Robo Confirmado
```powershell
python -m cookieguard rescue --auto
```
*Detiene los navegadores para evitar fugas continuas y genera un reporte HTML interactivo con las prioridades de rotación de cuentas.*

### 3. Cazar la Descarga Maliciosa que Originó la Infección
```powershell
python -m cookieguard descargas --hours 48
```
*Examina el historial de descargas de Chromium y Firefox buscando ejecutables camuflados (`.pdf.exe`), enlaces de Discord CDN o scripts `.vbs`.*

### 4. Vigilancia Activa con Trampa Cebo (Canary Trap)
```powershell
# Desplegar trampas señuelo en tus perfiles:
python -m cookieguard trap --deploy

# Comprobar si algún proceso ha leído o alterado el señuelo:
python -m cookieguard trap --check

# Dejar un monitor en bucle continuo:
python -m cookieguard trap --watch --interval 5
```

### 5. Cortafuegos de Emergencia (Killswitch)
```powershell
# Bloquear tráfico saliente hacia servidores C2:
python -m cookieguard killswitch --activar

# Reactivar la red tras desinfectar:
python -m cookieguard killswitch --desactivar
```

---

## 🛡️ Características Específicas de Windows

1. **Notificaciones Toast Nativas de Windows:**  
   Si el vigilante detecta un acceso no autorizado a los archivos SQLite de cookies (`Cookies`, `cookies.sqlite`), Windows emite una alerta Toast con sonido y botón para abrir directamente la investigación.
2. **Auditoría de Políticas de Navegadores:**  
   Genera plantillas de directivas de grupo para Chrome y Edge (`Software\Policies\Google\Chrome`) que bloquean extensiones no autorizadas y depuración remota.
3. **Verificación de Firmas Authenticode:**  
   Inspecciona las firmas digitales de los ejecutables de navegadores para detectar troyanos o binarios manipulados.
