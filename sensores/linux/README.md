# 🐧 Sensor de Kernel eBPF para Linux (`bpftrace`)

> **Detección proactiva a nivel de microsegundo mediante ganchos en el kernel Linux sin sondeo periódico.**

## 🎯 ¿Cómo funciona?

Este sensor utiliza **eBPF (Extended Berkeley Packet Filter)** mediante la herramienta estándar `bpftrace`.
Se engancha al punto de rastreo del kernel `tracepoint:syscalls:sys_enter_openat`.

Cada vez que cualquier proceso del sistema intenta abrir un descriptor de archivo apuntando a:
- Archivos `Cookies` de Chromium / Chrome / Brave / Edge.
- Bases `cookies.sqlite` de Firefox.
- Archivo de clave maestra `Local State` (DPAPI/AES).
- Base de claves `key4.db` de Firefox.

Si el proceso invocador **no** es el binario oficial del navegador (p.ej. un binario sospechoso en `/tmp/`, script Python, curl, nc o malware en memoria), el kernel emite una alerta instantánea en tiempo real.

## 🚀 Requisitos y Uso

```bash
# 1. Instalar bpftrace (disponible en todas las distribuciones modernas)
sudo apt install bpftrace  # Debian/Ubuntu
sudo dnf install bpftrace  # Fedora/RHEL
sudo pacman -S bpftrace    # Arch Linux

# 2. Ejecutar la sonda con privilegios de root
sudo bpftrace cookieguard_sensor.bt
```
