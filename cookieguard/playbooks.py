"""Módulo de Playbooks interactivos de revocación y respuesta a incidentes de cookies.

Genera listas de comprobación y guías paso a paso offline (HTML interactivo y Markdown)
con enlaces directos a las consolas de revocación de sesiones, rotación de contraseñas
y auditoría de persistencia para más de 35 servicios críticos.
"""
from __future__ import annotations

import html
import os
import time
from pathlib import Path
from typing import Any

from .common import data_dir, log


PLAYBOOK_CATALOG: list[dict[str, Any]] = [
    {
        "id": "google",
        "nombre": "Google / Gmail / Workspace",
        "categoria": "Identidad y Correo",
        "criticidad": "Crítica",
        "dominios": ["google.com", "accounts.google.com", "mail.google.com"],
        "url_sesiones": "https://myaccount.google.com/device-activity",
        "url_password": "https://myaccount.google.com/signinoptions/password",
        "url_oauth": "https://myaccount.google.com/permissions",
        "pasos": [
            "Haz clic en 'Cerrar sesión' en todos los dispositivos desconocidos o en el equipo comprometido.",
            "Cambia la contraseña maestra de la cuenta inmediatamente.",
            "Revisa en Gmail > Configuración > Reenvío y correo POP/IMAP que no existan reglas de reenvío silencioso.",
            "Revisa 'Acceso de aplicaciones de terceros' y revoca las apps sospechosas."
        ]
    },
    {
        "id": "microsoft",
        "nombre": "Microsoft 365 / Outlook / Azure",
        "categoria": "Identidad y Correo",
        "criticidad": "Crítica",
        "dominios": ["microsoft.com", "live.com", "office.com", "login.microsoftonline.com"],
        "url_sesiones": "https://account.microsoft.com/devices",
        "url_password": "https://account.live.com/password/change",
        "url_oauth": "https://account.live.com/consent/Manage",
        "pasos": [
            "Pulsa en 'Cerrar sesión en todas partes' (Sign out everywhere) en Seguridad avanzada.",
            "Cambia tu contraseña y regenera las claves de recuperación de MFA.",
            "En Outlook Web, revisa Reglas de la bandeja de entrada para descartar reenvíos ocultos.",
            "En Azure / Entra ID, revoca tokens de actualización (Revoke-AzureADUserAllRefreshToken)."
        ]
    },
    {
        "id": "github",
        "nombre": "GitHub",
        "categoria": "Desarrollo y Código",
        "criticidad": "Crítica",
        "dominios": ["github.com", "api.github.com"],
        "url_sesiones": "https://github.com/settings/sessions",
        "url_password": "https://github.com/settings/security",
        "url_oauth": "https://github.com/settings/applications",
        "pasos": [
            "Pulsa 'Revoke all other web sessions' para cerrar sesiones activas de navegador.",
            "Revisa y revoca Personal Access Tokens (PATs) en Developer Settings > Personal access tokens.",
            "Inspecciona tus SSH Keys en Settings > SSH and GPG keys y elimina claves no autorizadas.",
            "Revisa Authorized OAuth Apps y GitHub Apps autorizadas."
        ]
    },
    {
        "id": "aws",
        "nombre": "Amazon Web Services (AWS)",
        "categoria": "Infraestructura Cloud",
        "criticidad": "Crítica",
        "dominios": ["aws.amazon.com", "console.aws.amazon.com"],
        "url_sesiones": "https://us-east-1.console.aws.amazon.com/iam/home#/security_credentials",
        "url_password": "https://us-east-1.console.aws.amazon.com/iam/home#/security_credentials",
        "url_oauth": "https://us-east-1.console.aws.amazon.com/iam/home#/users",
        "pasos": [
            "Invalida las credenciales temporales generadas con STS.",
            "Rota inmediatamente las Access Keys (Access Key ID y Secret Access Key).",
            "Fuerza el cierre de sesiones en la consola de IAM y cambia la contraseña de usuario/consola.",
            "Verifica la política IAM adjunta para detectar roles creados recientemente."
        ]
    },
    {
        "id": "gitlab",
        "nombre": "GitLab",
        "categoria": "Desarrollo y Código",
        "criticidad": "Alta",
        "dominios": ["gitlab.com"],
        "url_sesiones": "https://gitlab.com/-/profile/active_sessions",
        "url_password": "https://gitlab.com/-/profile/password/edit",
        "url_oauth": "https://gitlab.com/-/profile/applications",
        "pasos": [
            "Revoca todas las sesiones activas en la pestaña Active Sessions.",
            "Revoca Personal Access Tokens y Deploy Tokens de repositorios clave.",
            "Cambia contraseña y regenera 2FA."
        ]
    },
    {
        "id": "slack",
        "nombre": "Slack",
        "categoria": "Comunicación y Equipos",
        "criticidad": "Alta",
        "dominios": ["slack.com", "app.slack.com"],
        "url_sesiones": "https://my.slack.com/account/settings#sessions",
        "url_password": "https://my.slack.com/account/settings#password",
        "url_oauth": "https://my.slack.com/apps/manage",
        "pasos": [
            "Pulsa 'Sign out of all other sessions'.",
            "Cambia tu contraseña de cuenta o solicita al administrador del Workspace que invalide tu sesión.",
            "Revisa integraciones o bots vinculados a tu cuenta."
        ]
    },
    {
        "id": "discord",
        "nombre": "Discord",
        "categoria": "Comunicación y Equipos",
        "criticidad": "Alta",
        "dominios": ["discord.com"],
        "url_sesiones": "https://discord.com/channels/@me",
        "url_password": "https://discord.com/channels/@me",
        "url_oauth": "https://discord.com/channels/@me",
        "pasos": [
            "En Ajustes de Usuario > Dispositivos, desconecta todas las sesiones activas.",
            "Al cambiar la contraseña en Ajustes > Mi cuenta, Discord invalida automáticamente el token actual.",
            "Revisa Aplicaciones autorizadas y revoca accesos de bots desconocidos."
        ]
    },
    {
        "id": "telegram",
        "nombre": "Telegram Web",
        "categoria": "Comunicación y Equipos",
        "criticidad": "Alta",
        "dominios": ["telegram.org", "web.telegram.org"],
        "url_sesiones": "https://web.telegram.org/a/#?settings=devices",
        "url_password": "https://web.telegram.org/a/#?settings=privacy",
        "url_oauth": "https://web.telegram.org/a/#?settings=privacy",
        "pasos": [
            "En Ajustes > Dispositivos, pulsa 'Cerrar todas las demás sesiones'.",
            "Activa la Verificación en dos pasos (contraseña en la nube) si no estuviera activa."
        ]
    },
    {
        "id": "binance",
        "nombre": "Binance",
        "categoria": "Finanzas y Cripto",
        "criticidad": "Crítica",
        "dominios": ["binance.com"],
        "url_sesiones": "https://www.binance.com/es/my/security/device-management",
        "url_password": "https://www.binance.com/es/my/security",
        "url_oauth": "https://www.binance.com/es/my/security",
        "pasos": [
            "En 'Gestión de dispositivos', elimina inmediatamente todos los dispositivos desconocidos.",
            "Cambia la contraseña (esto bloquea retiros temporalmente por protección durante 24-48h).",
            "Desactiva o regenera las claves API de trading.",
            "Verifica la lista blanca de direcciones de retiro."
        ]
    },
    {
        "id": "coinbase",
        "nombre": "Coinbase",
        "categoria": "Finanzas y Cripto",
        "criticidad": "Crítica",
        "dominios": ["coinbase.com"],
        "url_sesiones": "https://www.coinbase.com/settings/activity",
        "url_password": "https://www.coinbase.com/settings/security_settings",
        "url_oauth": "https://www.coinbase.com/settings/api",
        "pasos": [
            "Revisa 'Dispositivos activos' y finaliza todas las sesiones ajenas.",
            "Cambia la contraseña y activa confirmación por hardware de seguridad.",
            "Revoca claves API en la pestaña API."
        ]
    },
    {
        "id": "paypal",
        "nombre": "PayPal",
        "categoria": "Finanzas y Cripto",
        "criticidad": "Crítica",
        "dominios": ["paypal.com"],
        "url_sesiones": "https://www.paypal.com/myaccount/security",
        "url_password": "https://www.paypal.com/myaccount/security/password",
        "url_oauth": "https://www.paypal.com/myaccount/security/permissions",
        "pasos": [
            "Cambia la contraseña de acceso.",
            "Revisa 'Dispositivos de confianza' y elimina los no reconocidos.",
            "En 'Permisos concedidos', elimina pagos automáticos y comercios no autorizados."
        ]
    },
    {
        "id": "stripe",
        "nombre": "Stripe Dashboard",
        "categoria": "Finanzas y Cripto",
        "criticidad": "Crítica",
        "dominios": ["stripe.com", "dashboard.stripe.com"],
        "url_sesiones": "https://dashboard.stripe.com/settings/user",
        "url_password": "https://dashboard.stripe.com/settings/user",
        "url_oauth": "https://dashboard.stripe.com/apikeys",
        "pasos": [
            "Cierra todas las sesiones en Ajustes de usuario.",
            "Rota inmediatamente las API Secret Keys y Restricted Keys.",
            "Revisa usuarios invitados y permisos del equipo."
        ]
    },
    {
        "id": "cloudflare",
        "nombre": "Cloudflare",
        "categoria": "Infraestructura Cloud",
        "criticidad": "Alta",
        "dominios": ["cloudflare.com", "dash.cloudflare.com"],
        "url_sesiones": "https://dash.cloudflare.com/profile/sessions",
        "url_password": "https://dash.cloudflare.com/profile/authentication",
        "url_oauth": "https://dash.cloudflare.com/profile/api-tokens",
        "pasos": [
            "Cierra sesiones activas en Perfil > Sesiones.",
            "Revoca y regenera API Tokens y Global API Key.",
            "Revisa registros de auditoría (Audit Logs) para descartar cambios en registros DNS."
        ]
    },
    {
        "id": "openai",
        "nombre": "OpenAI / ChatGPT",
        "categoria": "IA y Productividad",
        "criticidad": "Media",
        "dominios": ["openai.com", "chatgpt.com", "platform.openai.com"],
        "url_sesiones": "https://platform.openai.com/account/sessions",
        "url_password": "https://chatgpt.com/#settings/Security",
        "url_oauth": "https://platform.openai.com/api-keys",
        "pasos": [
            "En Configuración > Seguridad, pulsa 'Cerrar sesión en todos los dispositivos'.",
            "En la plataforma de desarrolladores, revoca las API Keys activas.",
            "Cambia la contraseña de acceso."
        ]
    },
    {
        "id": "twitter",
        "nombre": "X (Twitter)",
        "categoria": "Redes Sociales",
        "criticidad": "Media",
        "dominios": ["twitter.com", "x.com"],
        "url_sesiones": "https://twitter.com/settings/sessions",
        "url_password": "https://twitter.com/settings/password",
        "url_oauth": "https://twitter.com/settings/connected_apps",
        "pasos": [
            "Pulsa 'Cerrar todas las demás sesiones'.",
            "Cambia la contraseña.",
            "Revoca aplicaciones conectadas sospechosas."
        ]
    },
    {
        "id": "linkedin",
        "nombre": "LinkedIn",
        "categoria": "Redes Sociales",
        "criticidad": "Media",
        "dominios": ["linkedin.com"],
        "url_sesiones": "https://www.linkedin.com/psettings/sessions",
        "url_password": "https://www.linkedin.com/psettings/change-password",
        "url_oauth": "https://www.linkedin.com/psettings/permitted-services",
        "pasos": [
            "Cierra sesiones activas desde 'Dónde has iniciado sesión'.",
            "Cambia la contraseña de la cuenta.",
            "Revisa los servicios vinculados permitidos."
        ]
    },
    {
        "id": "meta",
        "nombre": "Meta (Facebook / Instagram)",
        "categoria": "Redes Sociales",
        "criticidad": "Media",
        "dominios": ["facebook.com", "instagram.com"],
        "url_sesiones": "https://accountscenter.facebook.com/password_and_security",
        "url_password": "https://accountscenter.facebook.com/password_and_security",
        "url_oauth": "https://www.facebook.com/settings?tab=applications",
        "pasos": [
            "En Centro de Cuentas > Dónde has iniciado sesión, selecciona 'Cerrar sesión en todos los dispositivos'.",
            "Cambia la contraseña de acceso.",
            "Revisa apps y sitios web autorizados vinculados a tu cuenta."
        ]
    },
    {
        "id": "apple",
        "nombre": "Apple ID / iCloud",
        "categoria": "Identidad y Correo",
        "criticidad": "Crítica",
        "dominios": ["apple.com", "icloud.com"],
        "url_sesiones": "https://appleid.apple.com/account/manage",
        "url_password": "https://appleid.apple.com/account/manage",
        "url_oauth": "https://appleid.apple.com/account/manage",
        "pasos": [
            "En la sección Dispositivos, elimina cualquier equipo ajeno.",
            "Cambia la contraseña de tu ID de Apple.",
            "Revisa y revoca 'Iniciar sesión con Apple' en servicios externos."
        ]
    }
]


def match_services_for_cookies(grupos_sesiones: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Empareja las sesiones detectadas en el equipo con el catálogo de playbooks."""
    detected: list[dict[str, Any]] = []
    seen = set()

    for g in grupos_sesiones:
        nom = (g.get("nombre") or "").lower()
        dom = (g.get("dominio") or "").lower()

        matched = False
        for entry in PLAYBOOK_CATALOG:
            if entry["id"] in seen:
                continue
            # Comprobar dominios
            if any(d in dom or dom in d for d in entry["dominios"]) or entry["id"] in nom:
                seen.add(entry["id"])
                item = dict(entry)
                item["sesion_detectada"] = True
                item["cookies_count"] = g.get("total_cookies", 1)
                detected.append(item)
                matched = True
                break

    # Si hay servicios del catálogo que no tenían cookies activas pero son críticos, se pueden añadir opcionalmente
    for entry in PLAYBOOK_CATALOG:
        if entry["id"] not in seen and entry["criticidad"] == "Crítica":
            seen.add(entry["id"])
            item = dict(entry)
            item["sesion_detectada"] = False
            detected.append(item)

    return detected


def generate_playbook_html(services: list[dict[str, Any]] | None = None, output_path: Path | None = None) -> Path:
    """Genera una checklist HTML interactiva y estilizada que guarda el progreso en localStorage."""
    items = services if services is not None else PLAYBOOK_CATALOG
    if output_path is None:
        target_dir = data_dir() / "informes"
        target_dir.mkdir(parents=True, exist_ok=True)
        dest = target_dir / "checklist_revocacion.html"
    else:
        dest = Path(output_path)
        dest.parent.mkdir(parents=True, exist_ok=True)

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    cards_html = []
    for s in items:
        sid = html.escape(s["id"])
        nombre = html.escape(s["nombre"])
        cat = html.escape(s.get("categoria", "General"))
        crit = s.get("criticidad", "Media")
        badge_class = "crit-alta" if crit == "Crítica" else ("crit-media" if crit == "Alta" else "crit-baja")

        pasos_lis = "".join(f"<li>{html.escape(p)}</li>" for p in s.get("pasos", []))

        url_ses = html.escape(s.get("url_sesiones", "#"))
        url_pass = html.escape(s.get("url_password", "#"))
        url_oauth = html.escape(s.get("url_oauth", "#"))

        card = f"""
        <div class="card" data-service="{sid}" data-crit="{crit.lower()}">
            <div class="card-header">
                <div class="title-row">
                    <label class="check-container">
                        <input type="checkbox" id="chk_{sid}" onchange="toggleTask('{sid}')">
                        <span class="checkmark"></span>
                    </label>
                    <div>
                        <h3>{nombre}</h3>
                        <span class="category">{cat}</span>
                    </div>
                </div>
                <span class="badge {badge_class}">{crit}</span>
            </div>
            <div class="card-body">
                <p class="subtitle">Pasos recomendados para contención:</p>
                <ol class="step-list">
                    {pasos_lis}
                </ol>
                <div class="action-buttons">
                    <a href="{url_ses}" target="_blank" rel="noopener noreferrer" class="btn btn-primary">🔗 Cerrar Sesiones</a>
                    <a href="{url_pass}" target="_blank" rel="noopener noreferrer" class="btn btn-secondary">🔑 Cambiar Clave</a>
                    <a href="{url_oauth}" target="_blank" rel="noopener noreferrer" class="btn btn-tertiary">🛡️ Permisos OAuth</a>
                </div>
            </div>
        </div>
        """
        cards_html.append(card)

    cards_joined = "\n".join(cards_html)

    full_html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CookieGuard - Playbook de Revocación de Sesiones</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --surface-hover: #293548;
            --text: #f8fafc;
            --muted: #94a3b8;
            --border: #334155;
            --primary: #3b82f6;
            --primary-hover: #2563eb;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.5;
            padding: 24px;
        }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        header {{
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border);
        }}
        h1 {{ font-size: 26px; font-weight: 700; color: #fff; margin-bottom: 8px; display: flex; align-items: center; gap: 8px; }}
        .header-meta {{ color: var(--muted); font-size: 14px; }}
        .progress-box {{
            background: var(--surface);
            padding: 16px;
            border-radius: 8px;
            border: 1px solid var(--border);
            margin-bottom: 24px;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}
        .progress-labels {{ display: flex; justify-content: space-between; font-weight: 600; font-size: 14px; }}
        .progress-bar-bg {{ background: var(--border); height: 10px; border-radius: 5px; overflow: hidden; }}
        .progress-bar-fill {{ background: var(--success); height: 100%; width: 0%; transition: width 0.3s ease; }}
        .filter-bar {{ display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }}
        .filter-btn {{
            background: var(--surface);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 6px 14px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
        }}
        .filter-btn.active {{ background: var(--primary); border-color: var(--primary); }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 16px;
            overflow: hidden;
            transition: border-color 0.2s;
        }}
        .card.completed {{ border-color: var(--success); opacity: 0.75; }}
        .card.completed h3 {{ text-decoration: line-through; color: var(--muted); }}
        .card-header {{
            padding: 14px 18px;
            background: rgba(255,255,255,0.02);
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
        }}
        .title-row {{ display: flex; align-items: center; gap: 14px; }}
        h3 {{ font-size: 17px; font-weight: 600; }}
        .category {{ font-size: 12px; color: var(--muted); }}
        .badge {{
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .crit-alta {{ background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid var(--danger); }}
        .crit-media {{ background: rgba(245, 158, 11, 0.2); color: #fde68a; border: 1px solid var(--warning); }}
        .crit-baja {{ background: rgba(59, 130, 246, 0.2); color: #bfdbfe; border: 1px solid var(--primary); }}
        .card-body {{ padding: 18px; }}
        .subtitle {{ font-size: 13px; font-weight: 600; color: var(--muted); margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }}
        .step-list {{ margin-left: 20px; font-size: 14px; margin-bottom: 16px; color: #cbd5e1; }}
        .step-list li {{ margin-bottom: 4px; }}
        .action-buttons {{ display: flex; gap: 8px; flex-wrap: wrap; }}
        .btn {{
            text-decoration: none;
            padding: 7px 12px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 500;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }}
        .btn-primary {{ background: var(--primary); color: #fff; }}
        .btn-primary:hover {{ background: var(--primary-hover); }}
        .btn-secondary {{ background: var(--border); color: #fff; }}
        .btn-secondary:hover {{ background: #475569; }}
        .btn-tertiary {{ background: rgba(255,255,255,0.06); color: var(--muted); border: 1px solid var(--border); }}
        .btn-tertiary:hover {{ background: rgba(255,255,255,0.1); color: #fff; }}
        .check-container {{ position: relative; cursor: pointer; user-select: none; width: 22px; height: 22px; }}
        .check-container input {{ position: absolute; opacity: 0; cursor: pointer; height: 0; width: 0; }}
        .checkmark {{
            position: absolute; top: 0; left: 0; height: 22px; width: 22px;
            background-color: var(--border); border-radius: 5px;
        }}
        .check-container:hover input ~ .checkmark {{ background-color: #475569; }}
        .check-container input:checked ~ .checkmark {{ background-color: var(--success); }}
        .checkmark:after {{ content: ""; position: absolute; display: none; }}
        .check-container input:checked ~ .checkmark:after {{ display: block; }}
        .check-container .checkmark:after {{
            left: 7px; top: 3px; width: 6px; height: 11px;
            border: solid white; border-width: 0 2px 2px 0;
            transform: rotate(45deg);
        }}
        footer {{ text-align: center; margin-top: 32px; color: var(--muted); font-size: 13px; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🚨 CookieGuard: Playbook de Revocación de Sesiones</h1>
            <div class="header-meta">Generado el {timestamp} | Guía paso a paso para neutralizar cookies robadas</div>
        </header>

        <div class="progress-box">
            <div class="progress-labels">
                <span>Progreso de contención</span>
                <span id="progress-text">0 / {len(items)} completados (0%)</span>
            </div>
            <div class="progress-bar-bg">
                <div class="progress-bar-fill" id="progress-fill"></div>
            </div>
        </div>

        <div class="filter-bar">
            <button class="filter-btn active" onclick="filterCards('all')">Todos ({len(items)})</button>
            <button class="filter-btn" onclick="filterCards('crítica')">Críticos</button>
            <button class="filter-btn" onclick="filterCards('alta')">Altos</button>
            <button class="filter-btn" onclick="filterCards('media')">Medios</button>
            <button class="filter-btn" onclick="resetProgress()" style="margin-left: auto; color: var(--danger);">Reiniciar checklist</button>
        </div>

        <div class="card-list">
            {cards_joined}
        </div>

        <footer>
            CookieGuard Incident Response | Los cambios de estado se guardan localmente en tu navegador.
        </footer>
    </div>

    <script>
        const STORAGE_KEY = 'cookieguard_playbook_state';

        function loadState() {{
            try {{
                return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{{}}');
            }} catch(e) {{
                return {{}};
            }}
        }}

        function saveState(state) {{
            localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
        }}

        function updateProgress() {{
            const cards = document.querySelectorAll('.card');
            const total = cards.length;
            let completed = 0;
            cards.forEach(c => {{
                const id = c.getAttribute('data-service');
                const chk = document.getElementById('chk_' + id);
                if (chk && chk.checked) {{
                    completed++;
                    c.classList.add('completed');
                }} else {{
                    c.classList.remove('completed');
                }}
            }});
            const pct = total > 0 ? Math.round((completed / total) * 100) : 0;
            document.getElementById('progress-text').innerText = `${{completed}} / ${{total}} completados (${{pct}}%)`;
            document.getElementById('progress-fill').style.width = pct + '%';
        }}

        function toggleTask(id) {{
            const chk = document.getElementById('chk_' + id);
            const state = loadState();
            state[id] = chk.checked;
            saveState(state);
            updateProgress();
        }}

        function resetProgress() {{
            if (confirm('¿Deseas restablecer todos los elementos de la checklist?')) {{
                localStorage.removeItem(STORAGE_KEY);
                document.querySelectorAll('.card input[type="checkbox"]').forEach(c => c.checked = false);
                updateProgress();
            }}
        }}

        function filterCards(crit) {{
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');
            document.querySelectorAll('.card').forEach(c => {{
                if (crit === 'all' || c.getAttribute('data-crit') === crit.toLowerCase()) {{
                    c.style.display = 'block';
                }} else {{
                    c.style.display = 'none';
                }}
            }});
        }}

        // Inicializar estado guardado
        window.addEventListener('DOMContentLoaded', () => {{
            const state = loadState();
            for (const [id, val] of Object.entries(state)) {{
                const chk = document.getElementById('chk_' + id);
                if (chk) chk.checked = !!val;
            }}
            updateProgress();
        }});
    </script>
<div id="cg-toast" style="position:fixed;left:50%;bottom:20px;transform:translateX(-50%);background:#111;color:#fff;padding:12px 16px;border-radius:10px;max-width:90%;font:14px sans-serif;display:none;z-index:99;word-break:break-all"></div>
<script>
document.addEventListener('click', function (ev) {{
  var a = ev.target.closest && ev.target.closest('a.btn[href^="https://"]');
  if (!a) return;
  ev.preventDefault();
  var url = a.href, w = null;
  try {{ w = window.open(url, '_blank', 'noopener'); }} catch (e) {{}}
  if (w) return;
  var t = document.getElementById('cg-toast');
  var done = function (m) {{ t.textContent = m + ' ' + url; t.style.display = 'block'; setTimeout(function () {{ t.style.display = 'none'; }}, 9000); }};
  if (navigator.clipboard && navigator.clipboard.writeText) {{
    navigator.clipboard.writeText(url).then(function () {{ done('El visor bloquea ventanas nuevas. Enlace copiado, pégalo en tu navegador:'); }}, function () {{ done('El visor bloquea ventanas nuevas. Copia este enlace:'); }});
  }} else {{ done('El visor bloquea ventanas nuevas. Copia este enlace:'); }}
}});
</script>
</body>
</html>
"""
    dest.write_text(full_html, encoding="utf-8")
    log(f"[Playbooks] Checklist interactiva generada en: {dest}")
    return dest


def generate_playbook_markdown(services: list[dict[str, Any]] | None = None, output_path: Path | None = None) -> Path:
    """Genera una guía de revocación estructurada en formato Markdown."""
    items = services if services is not None else PLAYBOOK_CATALOG
    if output_path is None:
        target_dir = data_dir() / "informes"
        target_dir.mkdir(parents=True, exist_ok=True)
        dest = target_dir / "PLAYBOOK_REVOCACION.md"
    else:
        dest = Path(output_path)
        dest.parent.mkdir(parents=True, exist_ok=True)

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "# 🚨 CookieGuard: Playbook de Respuesta y Revocación de Sesiones",
        f"*Generado el: {timestamp}*",
        "",
        "Este documento contiene las acciones inmediatas para mitigar la exfiltración o robo de cookies de sesión.",
        "Sigue el orden de criticidad indicado a continuación.",
        "",
        "---",
        ""
    ]

    for s in items:
        crit = s.get("criticidad", "Media")
        lines.append(f"## [{crit}] {s['nombre']}")
        lines.append(f"- **Categoría**: {s.get('categoria', 'General')}")
        lines.append(f"- **Consola de Sesiones Activas**: [{s.get('url_sesiones')}]({s.get('url_sesiones')})")
        lines.append(f"- **Cambio de Contraseña**: [{s.get('url_password')}]({s.get('url_password')})")
        lines.append(f"- **Permisos OAuth**: [{s.get('url_oauth')}]({s.get('url_oauth')})")
        lines.append("")
        lines.append("### Tareas de Contención:")
        for p in s.get("pasos", []):
            lines.append(f"- [ ] {p}")
        lines.append("")
        lines.append("---")
        lines.append("")

    dest.write_text("\n".join(lines), encoding="utf-8")
    log(f"[Playbooks] Guía Markdown generada en: {dest}")
    return dest
