# Checklist de verificación (hazlo tú en tu equipo)

Marca cada punto. Todo lo que cambia el sistema te lo pide el programa antes.

## A. Sin instalar nada
- [ ] `python -m unittest discover -s tests` → **OK** (32 pruebas, 1 omitida en Windows de permisos POSIX).
- [ ] `python tests/simulaciones/simular.py todas` → todas **OK** (la de "acceso_fichero" sale OMITIDA en Windows hasta que haya auditoría; ver C).
- [ ] `Analizar ahora.cmd` (o `./cookieguard.sh analizar`): lista tus navegadores y se abre el informe. Si un navegador está abierto verás "bloqueada (error 32)": ciérralo y repite (o *Reintentar como administrador*).
- [ ] Compara 3 servicios del informe con lo que ves en el navegador (`chrome://settings/cookies/detail?site=...`): dominio, caducidad y navegador coinciden.
- [ ] Confirma que las bases originales siguen intactas (el navegador abre y mantiene tus sesiones).
- [ ] `Abrir CookieGuard.cmd` abre la interfaz **sin consola**; todas las pestañas tienen datos; ordena por columna, prueba los 5 filtros, exporta HTML/CSV/JSON y ábrelos: **ninguno contiene valores de cookies** (solo dominio, nombre, fechas, flags).
- [ ] `python -m cookieguard instalar --dry-run` → lista los pasos sin cambiar nada.
- [ ] Notificación de prueba: pestaña Ajustes → *Probar notificación* (aparece un toast / aviso).

## B. Acciones
- [ ] En *Por servicio* abre las 4 URLs de 3 servicios (p. ej. Google, GitHub, uno de tus bancos): cada una abre la página correcta.
- [ ] Un dominio fuera del catálogo abre una **búsqueda guiada**.
- [ ] **Borrado local** de un servicio sin importancia: pide cerrar el navegador, crea copia en *Copias de seguridad* y al abrir el navegador esa sesión ha desaparecido. **Restaura** la copia y comprueba que vuelve.
- [ ] *Asistente de rotación*: marca 2 pasos, cierra y reabre CookieGuard: el progreso se mantiene.
- [ ] *Modo incidente*: abre el ZIP: sin valores de cookies.

## C. Instalación (te pedirá permisos; hazlo cuando estés conforme)
- [ ] `Instalar.cmd`: acepta uno a uno los pasos. UAC aparece **una vez**.
- [ ] Cierra sesión y vuelve a entrar → a los ~45 s aparece la notificación con el semáforo y el botón *Abrir informe*.
- [ ] Verifica lo creado:
  - `schtasks /Query /TN CookieGuard-InicioSesion` y `CookieGuard-ReaplicarSACL`
  - `auditpol /get /subcategory:"File System"` → *Success*
  - (PowerShell) `(Get-Acl "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies" -Audit).Audit`
- [ ] **Simulación 1 con auditoría activa**: desde PowerShell abre el fichero de cookies de un navegador **cerrado** con un proceso ajeno (`[IO.File]::OpenRead(...)`) y vuelve a analizar → indicador 1 en alerta (evento 4663).
- [ ] **Vigilante**: Ajustes → activar; ejecuta `python tests/simulaciones/simular.py debug_flag crear` → salta la ventana de alerta en segundos; prueba *Suspender*, *Detalles* y *Bloquear* (admin); limpia con `... debug_flag limpiar`. Consumo: `%LOCALAPPDATA%\CookieGuard\vigilante_estado.json` (CPU % y MB).
- [ ] **Extensión de prueba**: en un perfil de pruebas de Chrome, *Cargar descomprimida* una extensión con permiso `cookies` y `<all_urls>` → indicador 5 en Amarillo.
- [ ] (Opcional) Sysmon: tras instalarlo, `Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5` muestra eventos; el indicador 3 deja de decir "Sin datos".

## D. Usuario sin privilegios
- [ ] Con una cuenta estándar: `Analizar ahora.cmd` funciona; los indicadores que necesitan administrador dicen **qué falta** en lugar de fallar; no se puede escribir en `%LOCALAPPDATA%\CookieGuard` desde otra cuenta.

## E. Desinstalación (sistema limpio)
- [ ] `Desinstalar.cmd` → conserva informes si lo eliges.
- [ ] `schtasks /Query /TN CookieGuard-InicioSesion` → no existe; igual `CookieGuard-ReaplicarSACL`.
- [ ] `auditpol /get /subcategory:"File System"` → como estaba antes (anótalo antes de instalar).
- [ ] `(Get-Acl <fichero> -Audit).Audit` → sin reglas de CookieGuard; `netsh advfirewall firewall show rule name=all | findstr CookieGuard` → vacío.
- [ ] Menú Inicio sin la carpeta *CookieGuard*.

## F. Linux
- [ ] `./cookieguard.sh analizar` y `./cookieguard.sh` (interfaz). `./cookieguard.sh instalar` crea `~/.config/autostart/cookieguard.desktop`; tras reiniciar sesión llega un aviso (`notify-send`).
- [ ] `sudo auditctl -l | grep cookieguard` (si activaste auditd) y `./cookieguard.sh desinstalar` lo deja limpio.
