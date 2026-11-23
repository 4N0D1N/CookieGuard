# Playbook: "creo que me han robado las cookies"

Úsalo con semáforo **Rojo**, o **Amarillo** con hallazgos de los indicadores 1, 2, 3, 6 u 8, o si ves accesos que no reconoces.
Regla de oro: **todo lo que cambies, hazlo desde un dispositivo limpio** (otro móvil u ordenador), no desde el equipo sospechoso.

## 0. Antes de nada (5 minutos)
1. **No apagues** el equipo todavía si quieres análisis forense. **Desconéctalo de la red** (cable/Wi-Fi). Sigue encendido.
2. En CookieGuard: **Modo incidente** → ZIP con indicadores, hashes y hallazgos (sin valores de cookies). Cópialo a un USB.
3. Anota la hora, qué hacías, qué descargaste o instalaste últimamente.

## 1. Aislar
- Desconecta el equipo de la red y de la VPN. Cierra sesión de la nube corporativa desde otro dispositivo (paso 2).
- Si es un equipo de trabajo: **avisa a tu CSIRT/SOC ya**; ellos pueden revocar sesiones centralmente.
- Desde el vigilante o el administrador de tareas: suspende/mata el proceso sospechoso y bloquéalo en el Firewall (no lo borres aún: guarda su ruta y SHA-256).

## 2. Desde un dispositivo limpio: cerrar sesiones y rotar, por orden de criticidad
Para **cada** servicio: **(a) cerrar todas las sesiones/dispositivos → (b) cambiar contraseña → (c) revisar 2FA/passkeys y métodos de recuperación → (d) revisar actividad reciente.**
El orden importa; usa el **Asistente de rotación** de CookieGuard (guarda el progreso) o esta lista:
1. **Correo principal** (da acceso al "olvidé mi contraseña" de todo lo demás).
2. **Gestor de contraseñas** (cierra sesiones, cambia la maestra, revisa dispositivos).
3. **SSO/identidad**: Microsoft/Entra, Google, Apple, Okta.
4. **Banca y cripto**: bloquea tarjetas/operativa si ves movimientos raros; llama al banco. Retira fondos a una cartera nueva si es cripto.
5. **Trabajo**: Slack, Atlassian, GitHub/GitLab (revoca también tokens personales y claves SSH), AWS/Cloudflare, Zoom, Notion.
6. **Redes sociales y mensajería**: Meta, X, LinkedIn, Discord, Telegram, WhatsApp.
7. El resto de servicios (CookieGuard los lista en el asistente).

⚠️ **Cambiar la contraseña no basta**: una cookie robada puede seguir funcionando. **Cierra todas las sesiones** y, si el servicio lo permite, revoca tokens/aplicaciones.

## 3. Revisar 2FA y recuperación
- Quita **métodos de 2FA que no reconozcas** (teléfonos, apps, llaves) y **códigos de recuperación** antiguos; genera nuevos.
- Revisa **correo y teléfono de recuperación**.
- Pasa a **passkeys / llaves FIDO2** en correo, banca y cripto cuando sea posible.

## 4. Persistencia que deja el atacante en las cuentas
- **Reglas de reenvío y filtros del correo** (Gmail: Configuración → Reenvío y filtros; Outlook: Reglas y Reenvío). Un atacante crea reglas para ver tu correo aunque cambies la contraseña.
- **Aplicaciones OAuth autorizadas**: Google (Seguridad → Acceso de terceros), Microsoft (Aplicaciones y servicios), GitHub (Applications), X, Meta… Revoca las que no reconozcas.
- **Claves de API, tokens personales, claves SSH, webhooks** y contraseñas de aplicación.
- **Dispositivos de confianza** y *"recordar este navegador"*.

## 5. Buscar inicios de sesión raros
Revisa el historial de acceso de cada servicio crítico (CookieGuard abre la página): IPs/países, horas, dispositivos, y acciones sensibles (cambio de correo, descargas masivas, envíos de dinero). Anota IPs y hora UTC para el informe.

## 6. El equipo
Si se confirma un **infostealer** (Defender lo detecta, hay copias de bases de datos, procesos con depuración remota, ejecutables desconocidos, persistencia nueva):
- **Reinstala Windows/Linux** (formateo completo). Un stealer suele ir acompañado de otras puertas traseras y no puedes garantizar la limpieza con un antivirus.
- Cuándo **no** hace falta: falso positivo claro (p. ej. una extensión conocida, una herramienta de desarrollo tuya con depuración remota) y sin otros indicios.
- Restaura solo **datos** (no ejecutables) y desde copias anteriores al incidente. Cambia de nuevo las contraseñas desde el equipo limpio.
- Después: navegador actualizado (DBSC en Chrome 146+), Defender con protección antialteración, perfiles separados para banca, sin contraseñas en el navegador.

## 7. Cierre
Documenta línea de tiempo, indicadores, servicios rotados y lecciones. Si hay datos personales/corporativos afectados, valora la **notificación** (RGPD, 72 h) con tu DPO/legal.
