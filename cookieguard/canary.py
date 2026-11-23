"""Cookies canary (opcional, desactivado por defecto).

Idea: una sesion SENUELO en un sitio que controlas (o un Canarytoken). Si un stealer roba esa cookie y alguien la
reutiliza desde fuera, el servidor del senuelo te avisa. CookieGuard NO escribe cookies en tu navegador (eso
exigiria manejar valores): te guia para plantarlas tu mismo y registra la URL para abrirla cuando quieras.
La unica salida a red es abrir esa URL en tu navegador cuando pulsas el boton.
"""
from __future__ import annotations

import webbrowser
from urllib.parse import urlparse

from .common import load_config, save_user_config

PASOS = """\
ASISTENTE DE COOKIES CANARY
===========================
Opcion A - Canarytokens (sin servidor propio)
  1. Entra en https://canarytokens.org y elige un token de tipo 'Web bug / URL' o 'Fake app / Cloned website'.
  2. Pon tu correo (o webhook) para recibir el aviso y copia la URL del token.
  3. Registra esa URL aqui (opcion 1). Ábrela desde cada navegador/perfil que quieras 'sembrar':
     el sitio del token registra quien entra.
  4. Aviso: Canarytokens avisa cuando ALGUIEN abre la URL; si un stealer extrae el historial/sesion y la reutiliza,
     te llega la alerta con IP y navegador.

Opcion B - Dominio propio (mas realista)
  1. En un subdominio tuyo (p. ej. intranet.midominio.es) publica una pagina de 'login' falsa.
  2. Al iniciar sesion con credenciales falsas, el servidor pone una cookie de sesion HttpOnly con un valor aleatorio.
  3. Si ese valor se presenta desde otra IP, el servidor te envia un aviso (correo/Telegram/webhook).
  4. Registra la URL del login aqui para abrirla y 'sembrar' la sesion en el navegador.

Limites: es opcional, no sustituye al resto de indicadores, y un atacante cuidadoso puede ignorar la cookie canary.
"""


def valid_url(url: str) -> bool:
    u = urlparse(url)
    return u.scheme == "https" and bool(u.netloc)


def set_canary(url: str, activo: bool = True) -> bool:
    if activo and not valid_url(url):
        return False
    save_user_config({"canary_url": url if activo else "", "canary_activo": bool(activo)})
    return True


def open_canary() -> bool:
    cfg = load_config()
    if not cfg.get("canary_activo") or not valid_url(cfg.get("canary_url", "")):
        return False
    return webbrowser.open(cfg["canary_url"])


def wizard_cli() -> int:
    print(PASOS)
    cfg = load_config()
    print(f"Estado: {'ACTIVO' if cfg.get('canary_activo') else 'desactivado'}  URL: {cfg.get('canary_url') or '-'}")
    op = input("1) Registrar/activar URL  2) Abrir ahora  3) Desactivar  (otra tecla: salir): ").strip()
    if op == "1":
        url = input("URL https del canary: ").strip()
        print("Guardado." if set_canary(url) else "URL no valida (debe empezar por https://).")
    elif op == "2":
        print("Abierta." if open_canary() else "Canary no activo o URL no valida.")
    elif op == "3":
        set_canary("", False)
        print("Desactivado.")
    return 0
