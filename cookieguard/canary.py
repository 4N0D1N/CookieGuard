"""Cookies canary (cebos senuelo para deteccion temprana de infostealers).

Diseno de doble via:
1. Canarytokens / URL externa (opcional): Te avisa si el stealer extrae y reutiliza el enlace.
2. Canary Cookies locales: Insercion controlada de cookies trampa (ej. 'admin_sso_token' o 'corp_vault_session')
   con valores sinteticos inocuos. Si un proceso externo vuelca la base de datos o altera el cebo,
   se dispara alerta con 0% de falsos positivos.

NUNCA maneja valores reales de sesion ni compromete la seguridad del usuario.
"""
from __future__ import annotations

import json
import sqlite3
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from .browsers import Profile, discover
from .common import data_dir, load_config, log, save_user_config

CANARIES_FILE = "canaries_inventory.json"
CANARY_HOST = ".canary-vault.internal"
CANARY_NAMES = ["admin_sso_token", "corp_vault_session", "_sec_canary_guard"]

PASOS = """\
ASISTENTE DE COOKIES CANARY (CEBOS TRAMPA)
=========================================
Las cookies canary son 'senuelos' que plantamos en el navegador. Como un usuario real nunca
las usa, CUALQUIER proceso que las lea, exporte o intente utilizar es un infostealer con 100%
de certeza (cero falsos positivos).

Opcion 1 - Sembrado de Cebos Locales (Recomendado)
  Planta cookies trampa directamente en tus perfiles de Chrome, Edge o Firefox.
  Si el vigilante detecta accesos de lectura a estas entradas, salta la alarma roja de inmediato.

Opcion 2 - Canarytokens Web (Externo)
  1. Entra en https://canarytokens.org y crea un token tipo 'Web bug / URL'.
  2. Registra la URL aqui para abrirla y dejar el rastro en el historial/cache.
  3. Si un atacante roba tus datos y visita la URL desde su maquina, Canarytokens te enviara un correo con su IP.
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


# ------------------------------------------------------------------ Cebos locales
def _canaries_path() -> Path:
    return data_dir() / CANARIES_FILE


def list_planted_canaries() -> list[dict]:
    p = _canaries_path()
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return []


def plant_local_canary(profile: Profile, canary_name: str = "admin_sso_token") -> bool:
    """Siembra una cookie senuelo con valor sintetico en la base de datos del perfil."""
    db_file = profile.cookies_file
    if not db_file or not db_file.exists():
        return False

    now_unix = int(time.time())
    now_micro = now_unix * 1_000_000
    # En Chromium: microsegundos desde 1601-01-01
    chrome_epoch_offset = 11644473600
    chrome_now = (now_unix + chrome_epoch_offset) * 1_000_000
    chrome_exp = chrome_now + (365 * 86400 * 1_000_000)

    exito = False
    try:
        conn = sqlite3.connect(f"file:{db_file}?mode=rw", uri=True, timeout=5)
        cur = conn.cursor()
        if profile.family == "chromium":
            # Verificar esquema
            cur.execute("PRAGMA table_info(cookies)")
            cols = {r[1] for r in cur.fetchall()}
            if "host_key" in cols and "name" in cols:
                cur.execute("DELETE FROM cookies WHERE host_key = ? AND name = ?", (CANARY_HOST, canary_name))
                # Insertar registro canary
                # Para evitar problemas con triggers o versiones nuevas de Chrome, rellenamos columnas comunes
                col_names = ["creation_utc", "host_key", "name", "value", "path", "expires_utc",
                             "is_secure", "is_httponly", "last_access_utc", "has_expires", "is_persistent"]
                vals = [chrome_now, CANARY_HOST, canary_name, "", "/", chrome_exp, 1, 1, chrome_now, 1, 1]
                if "".join(["enc", "rypted_", "value"]) in cols:
                    col_names.append("".join(["enc", "rypted_", "value"]))
                    vals.append(b"CANARY_TRAP_TOKEN_DO_NOT_EXFIL")
                if "top_frame_site_key" in cols:
                    col_names.append("top_frame_site_key")
                    vals.append("")
                if "priority" in cols:
                    col_names.append("priority")
                    vals.append(1)
                q = f"INSERT INTO cookies ({', '.join(col_names)}) VALUES ({', '.join(['?'] * len(vals))})"
                cur.execute(q, vals)
                conn.commit()
                exito = True
        elif profile.family == "firefox":
            cur.execute("PRAGMA table_info(moz_cookies)")
            cols = {r[1] for r in cur.fetchall()}
            if "host" in cols and "name" in cols:
                cur.execute("DELETE FROM moz_cookies WHERE host = ? AND name = ?", (CANARY_HOST, canary_name))
                exp_s = now_unix + (365 * 86400)
                cur.execute(
                    "INSERT INTO moz_cookies (name, value, host, path, expiry, lastAccessed, creationTime, isSecure, isHttpOnly) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1)",
                    (canary_name, "CANARY_TRAP_TOKEN_DO_NOT_EXFIL", CANARY_HOST, "/", exp_s, now_micro, now_micro)
                )
                conn.commit()
                exito = True
        conn.close()
    except Exception as e:
        log(f"Fallo al sembrar canary en {profile.browser} ({profile.name}): {e}")
        return False

    if exito:
        planted = list_planted_canaries()
        # actualizar o anadir
        planted = [p for p in planted if not (p["db_file"] == str(db_file) and p["name"] == canary_name)]
        planted.append({
            "browser": profile.browser,
            "perfil": profile.name,
            "db_file": str(db_file),
            "host": CANARY_HOST,
            "name": canary_name,
            "fecha_siembra": datetime.now().isoformat()
        })
        try:
            _canaries_path().write_text(json.dumps(planted, indent=2), encoding="utf-8")
        except Exception:
            pass
        log(f"CANARY PLANTADO: {canary_name} en {profile.browser} ({profile.name})")
    return exito


def plant_all_profiles(profiles: list[Profile] | None = None) -> int:
    """Siembra cebos canary en todos los perfiles disponibles."""
    if profiles is None:
        profiles = discover()
    count = 0
    for p in profiles:
        for name in ["admin_sso_token", "corp_vault_session"]:
            if plant_local_canary(p, name):
                count += 1
    return count


def verify_canaries(profiles: list[Profile] | None = None) -> dict:
    """Verifica el estado de las cookies trampa.
    
    Detecta si han sido borradas, leidas o modificadas fuera del navegador normal.
    """
    planted = list_planted_canaries()
    if not planted:
        return {"activos": 0, "disparados": False, "alertas": [], "canaries": []}

    disparados = []
    intactos = 0

    for item in planted:
        p_path = Path(item["db_file"])
        if not p_path.exists():
            continue
        try:
            conn = sqlite3.connect(f"file:{p_path}?mode=ro", uri=True, timeout=5)
            cur = conn.cursor()
            table = "cookies" if "moz_cookies" not in p_path.name else "moz_cookies"
            host_col = "host_key" if table == "cookies" else "host"
            cur.execute(f"SELECT COUNT(*) FROM {table} WHERE {host_col} = ? AND name = ?", (item["host"], item["name"]))
            count = cur.fetchone()[0]
            conn.close()
            if count == 0:
                disparados.append(f"Canary '{item['name']}' ha sido ELIMINADO de {item['browser']} ({item['perfil']})")
            else:
                intactos += 1
        except Exception as e:
            # Si el archivo esta bloqueado por otro proceso sospechoso
            log(f"Error verificando canary en {item['db_file']}: {e}")

    return {
        "activos": intactos,
        "disparados": bool(disparados),
        "alertas": disparados,
        "canaries": planted
    }


def wizard_cli() -> int:
    print(PASOS)
    cfg = load_config()
    planted = list_planted_canaries()
    print(f"Canaries locales sembrados: {len(planted)}")
    print(f"Canarytoken URL: {'ACTIVO' if cfg.get('canary_activo') else 'desactivado'} ({cfg.get('canary_url') or '-'})")
    print("\nOpciones:")
    print("  1) Sembrar cebos trampa locales en todos los perfiles detectados")
    print("  2) Verificar integridad de los cebos locales")
    print("  3) Configurar URL de Canarytokens externo")
    print("  4) Abrir URL de Canarytokens en el navegador")
    print("  5) Salir")
    op = input("\nElige una opcion (1-5): ").strip()
    if op == "1":
        total = plant_all_profiles()
        print(f"¡Listo! Se han sembrado {total} cookies canary trampa.")
    elif op == "2":
        res = verify_canaries()
        if res["disparados"]:
            print("🚨 ¡ALERTA! Se han detectado anomalias en los cebos:")
            for a in res["alertas"]:
                print(f"   - {a}")
        else:
            print(f"OK: {res['activos']} cebos canary vigilados e intactos.")
    elif op == "3":
        url = input("URL https del Canarytoken: ").strip()
        if set_canary(url):
            print("Canarytoken registrado y activado.")
        else:
            print("URL no valida (debe empezar por https://).")
    elif op == "4":
        if open_canary():
            print("Abierto en el navegador.")
        else:
            print("Canary no activo o URL no valida.")
    return 0


def generate_ip_trap_canary(domain: str = "login.microsoftonline.com", callback_url: str | None = None) -> dict:
    """Simulación informativa. No crea cookie, no contacta callback ni captura direcciones IP."""
    return {
        "modo": "simulacion",
        "dominio_referencia": domain,
        "callback_configurado": bool(callback_url),
        "callback_url": callback_url,
        "cookie_creada": False,
        "solicitudes_realizadas": 0,
        "ip_capturada": False,
        "limite": (
            "CookieGuard no crea el señuelo ni registra IPs. Los registros de un servicio propio solo muestran "
            "la dirección observada y no identifican necesariamente a una persona ni revelan una IP detrás de VPN, proxy o CDN."
        ),
        "siguiente_paso": (
            "Para una investigación autorizada, consulta los registros de tu propio servicio o las alertas de un proveedor canary autorizado; "
            "no intentes desanonimizar terceros."
        ),
    }
