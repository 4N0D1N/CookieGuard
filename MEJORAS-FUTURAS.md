# Historial de Mejoras y Estado del Proyecto (v1.2.0)

Todas las mejoras prioritarias y técnicas identificadas para la defensa integral contra infostealers han sido implementadas y verificadas:

## ✅ Implementadas en v1.0.0, v1.1.0 y v1.2.0

1. **14 Indicadores de Detección MITRE ATT&CK (I01 - I14):**
   - I01 a I12: Procesos ajenos, flags sospechosos de depuración (`--remote-debugging-port`), inyección en memoria, copias temporales SQLite, tráfico de exfiltración, tampering de Defender/antivirus, persistencia y anomalías de expiración.
   - I13: Canary Cookies locales activas (cebos en perfiles de navegador con 0% de falsos positivos).
   - I14: Auditoría de acceso a clave maestra (`Local State` en Chromium con DPAPI y `key4.db` en Firefox). Monitoreo de descriptores en `/proc/[pid]/fd` y detección de herramientas de volcado de DPAPI.
2. **Contención Inmediata con Killswitch de Red:**
   - Windows: Corte de tráfico saliente mediante `netsh advfirewall` preservando loopback y DNS esencial.
   - Linux: Reglas automáticas en `iptables` / `nftables` de aislamiento con whitelist.
   - Modo simulación / dry-run y restauración garantizada en 1 clic.
3. **Cebos Canary Activos Integrados:**
   - Siembra automatizada de cookies trampa con prefijo `__Host-` y atributos de máxima seguridad en perfiles Chromium y Firefox.
   - Soporte opcional para Canarytokens HTTP remotos.
4. **Alertas Remotas por Webhook:**
   - Soporte para ntfy.sh, Discord, Telegram o endpoints corporativos para alertar al móvil sin exponer credenciales.
5. **Demos y Simulaciones Interactivas en Vivo:**
   - Desplegadas en GitHub Pages (`https://4n0d1n.github.io/CookieGuard/`).
   - Simulación nativa Windows 11 (Toast flotante, triaje forense, telemetría DPAPI).
   - Simulación nativa Linux Desktop (alerta D-Bus notify-send, `/proc` fd tracing, iptables isolation).
6. **Reglas Sigma Nativas para SIEM (`reglas/sigma/`):**
   - Cuatro reglas listas para producción: acceso a cookies, robo de clave `Local State`, flags de depuración remota y extensiones desempaquetadas.
7. **Auditoría y Endurecimiento de Navegadores (`cookieguard hardening`):**
   - Análisis de `Preferences` y `Secure Preferences`, detección de extensiones en modo desarrollador o sin firma, y copias de seguridad automáticas antes de cambios.
8. **Compatibilidad y Verificación DBSC (`cookieguard dbsc`):**
   - Comprobación de soporte de Device Bound Session Credentials por hardware (TPM) para Google, Microsoft y Okta.
9. **Icono en Bandeja del Sistema (System Tray) / Daemon Silencioso (`cookieguard tray`):**
   - Soporte para icono de bandeja interactivo (`pystray`) y fallback robusto a servicio en segundo plano con notificaciones nativas del sistema operativo.
10. **Zero Dependencias Externas Obligatorias:**
    - 100% Python puro con librería estándar, compatible con entornos offline y restringidos.

---

## 🔮 Futuras Exploraciones Opcionales (Próximos horizontes)

- **Sensor eBPF nativo para Linux (Tetragon / Falco):** Sustituir el sondeo periódico de `/proc` por ganchos en el kernel (kprobes/tracepoints) para intercepción a nivel de milisegundo en kernels Linux 5.15+.
- **Driver Minifilter para Windows:** Driver de sistema de archivos para bloqueo proactivo antes de que el stealer pueda completar la lectura de `Cookies`.
- **Extensión complementaria de navegador:** Extensión opcional para monitorizar rotación de sesiones mediante `chrome.cookies.onChanged` exponiendo únicamente metadatos sin valores.
