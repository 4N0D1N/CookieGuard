# 🪟 Sensor en Tiempo Real para Windows (FileSystemWatcher & Sysmon)

> **Monitoreo proactivo de eventos de archivo sobre almacenes de cookies y claves maestras en Windows.**

## 🎯 ¿Qué hace este sensor?

Monitorea los directorios de datos de usuario de Chrome, Edge, Brave y Firefox en `%LOCALAPPDATA%` y `%APPDATA%`.
Ante cualquier acceso o copia de:
- `Network\Cookies`
- `Local State` (Clave de cifrado DPAPI)
- `cookies.sqlite`

Emite una alerta visual destacada en consola y un pitido sonoro del sistema para advertir de exfiltración en progreso.

## 🚀 Uso Inmediato

```powershell
# Ejecutar desde PowerShell (sin necesidad de instalar software adicional):
powershell -ExecutionPolicy Bypass -File .\cookieguard_etw.ps1
```

*(Adicionalmente, se incluye en `reglas/sysmon-cookieguard.xml` la configuración oficial de Sysmon para integración a nivel de driver en Windows).*
