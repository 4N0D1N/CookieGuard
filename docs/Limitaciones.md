# Limitaciones (con honestidad)

CookieGuard **no es un antivirus ni un EDR**. Trabaja con **indicios y niveles de riesgo**. Un Verde significa *"no he visto nada"*, no *"estás a salvo"*.

## Lo que NO puede detectar, y por qué
| Caso | Por qué |
|---|---|
| **Malware sofisticado ya instalado** (rootkit, kernel, malware que se esconde de herramientas de usuario) | CookieGuard corre como un programa normal: si el atacante controla el sistema, puede ocultarle procesos, ficheros y eventos. |
| **Phishing AiTM (Evilginx, Modlishka…)** | La cookie se roba en el servidor del atacante mientras inicias sesión en una página falsa. **No pasa nada en tu equipo**, así que no hay rastro local. Defensa real: passkeys/FIDO2, DBSC/Token Protection, no iniciar sesión desde enlaces. |
| **Robo puntual y limpio** (el stealer ya se fue y no dejó restos) | Sin persistencia ni ficheros residuales y sin auditoría en el momento, solo quedan indicios débiles (p. ej. cookies escritas a la vez). |
| **Accesos de lectura al fichero sin auditoría activa** | En Windows, el indicador 1 necesita la auditoría 4663+SACL (se activa en la instalación). Antes de eso dice "Sin datos". Sysmon no registra lecturas de fichero por defecto. |
| **Quién se conectó a dónde** (indicador 7) sin Sysmon | La caché DNS solo dice *qué dominio se resolvió*, no *qué proceso*; además se vacía. En Linux no se expone esa caché. |
| **Tokens fuera de las cookies** (Discord, Telegram/WhatsApp Web, apps Electron) | Los guardan en almacenamiento local/IndexedDB, no en cookies; CookieGuard no los lee (ni debe). |
| **Lectura de la memoria del navegador sin Sysmon** | Windows no avisa de ello sin telemetría adicional (Sysmon 10). |
| **Cookies de sesión del propio servidor** (sesión válida en el servidor aunque borres la local) | Borrar cookies locales no revoca la sesión en el servidor: hay que **cerrar sesiones** en el servicio. |

## Limitaciones técnicas
- **Chrome/Edge abiertos bloquean la base `Cookies`**: se lee al iniciar sesión, con el navegador cerrado, o con copia VSS (administrador). No se usa ninguna técnica de lectura de memoria para evitarlo (es la del atacante).
- **Falsos positivos**: herramientas legítimas (backup, indexadores, EDR, depuración de desarrolladores) pueden aparecer; usa *Procesos de confianza*. Se ignoran las apps Electron/WebView2 evidentes.
- **Falsos negativos** si el atacante usa un proceso de la lista de confianza (p. ej. se inyecta en `chrome.exe`).
- **El catálogo envejece**: las URLs de seguridad de los servicios cambian; `tools/verificar_urls.py` las revisa.
- **Linux**: sin Defender/Sysmon equivalentes integrados; el indicador 1 usa `/proc` (instante actual) y `auditd`; el 3 mira `ptrace_scope`; el 7 no tiene datos. DBSC y App-Bound Encryption son funciones de Chrome en Windows.
- **Elevación**: las tareas de auditoría y el firewall requieren administrador; sin él esos indicadores dicen qué falta en lugar de fallar.
- **Seguridad del propio programa**: se instala en una carpeta del usuario; si un atacante ya es ese usuario, puede modificarlo. Mitigación: permisos de carpeta restringidos, tareas con ruta fija y (opcional) firma de scripts (ver `Tecnico.md`).
