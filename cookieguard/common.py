"""Utilidades comunes de CookieGuard (Windows y Linux, solo libreria estandar)."""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

IS_WIN = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")
if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    APP_ROOT = Path(sys._MEIPASS)
else:
    APP_ROOT = Path(__file__).resolve().parent.parent
VERSION = "1.7.0"

_perm_done: set = set()


def data_dir() -> Path:
    """Carpeta de datos del usuario (informes, logs, estado). Permisos solo para el usuario."""
    env = os.environ.get("COOKIEGUARD_HOME")
    if env:
        p = Path(env)
    elif IS_WIN:
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        p = Path(base) / "CookieGuard"
    else:
        base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
        p = Path(base) / "cookieguard"
    p.mkdir(parents=True, exist_ok=True)
    for sub in ("informes", "logs", "backups", "tmp", "forense"):
        (p / sub).mkdir(exist_ok=True)
    if str(p) not in _perm_done:
        _perm_done.add(str(p))
        restrict_permissions(p)
    return p


def restrict_permissions(p: Path) -> None:
    """Deja la carpeta accesible solo para el usuario actual."""
    marker = p / ".permisos_ok"
    if marker.exists():
        return
    try:
        if IS_WIN:
            user = os.environ.get("USERNAME", "")
            if user:
                run(["icacls", str(p), "/inheritance:r", "/grant:r", f"{user}:(OI)(CI)F"], timeout=20)
        else:
            os.chmod(p, 0o700)
        marker.write_text("ok", encoding="utf-8")
    except Exception:
        pass


def run(cmd, timeout: int = 30):
    """Ejecuta un comando sin ventana. Devuelve (codigo, stdout, stderr). Nunca lanza excepcion."""
    try:
        kw = {}
        if IS_WIN:
            kw["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL, **kw)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return -1, "", str(e)


def ps(script: str, timeout: int = 60):
    """Ejecuta PowerShell (solo Windows) con salida UTF-8."""
    full = "[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ProgressPreference='SilentlyContinue';" + script
    return run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-Command", full], timeout)


def is_admin() -> bool:
    try:
        if IS_WIN:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


# ---------------------------------------------------------------- configuracion
DEFAULT_CONFIG = {
    "umbrales": {"amarillo": 15, "rojo": 40},
    "puntos": {
        "I18_perfil_trampa": 90,
        "I19_inyeccion_memoria": 85
    },
    "dias": {"zombie_sin_uso": 90, "zombie_caduca_en": 365, "caduca_pronto": 7, "sin_uso": 90,
             "ejecutables_recientes": 14},
    "whitelist_procesos": [
        "chrome", "msedge", "brave", "opera", "vivaldi", "chromium", "yandex", "firefox", "librewolf", "waterfox",
        "msmpeng", "mssense", "searchindexer", "searchprotocolhost", "system", "svchost", "explorer",
        "chrome_crashpad_handler", "crashpad_handler", "elevation_service", "msedgewebview2", "onedrive",
        "backgroundtaskhost", "tracker-miner-fs", "baloo_file_extractor", "chrome-sandbox", "chrome_sandbox",
    ],
    "silencioso": False,
    "notificar_verde": True,
    "vigilante_activo": False,
    "vigilante_intervalo_s": 10,
    "canary_activo": False,
    "canary_url": "",
    "webhook_activo": False,
    "webhook_url": "",
    "killswitch_activo": False,
    "directorios_copias_sospechosas": [],
    "iocs_auto_actualizar": True,
    "iocs_feed_url": "https://raw.githubusercontent.com/4N0D1N/CookieGuard/main/catalogo/iocs.json",
    "iocs_ttl_horas": 24,
    "sesiones_escritorio_activas": True,
    "honeypot_activo": True,
    "memory_audit_activo": True,
    "extensiones_peligrosas": ["cookies", "<all_urls>", "webRequest", "webRequestBlocking", "debugger",
                               "nativeMessaging", "proxy", "*://*/*", "http://*/*", "https://*/*"],
}


def _deep_merge(a: dict, b: dict) -> dict:
    out = copy.deepcopy(a)
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config() -> dict:
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    for path in (APP_ROOT / "config" / "config.json", data_dir() / "config.json"):
        try:
            if path.exists():
                cfg = _deep_merge(cfg, json.loads(path.read_text(encoding="utf-8-sig")))
        except Exception as e:  # noqa: BLE001
            log(f"config invalida {path.name}: {e}")
    return cfg


def save_user_config(changes: dict) -> None:
    path = data_dir() / "config.json"
    cur = {}
    try:
        if path.exists():
            cur = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        cur = {}
    path.write_text(json.dumps(_deep_merge(cur, changes), indent=2, ensure_ascii=False), encoding="utf-8")


# ---------------------------------------------------------------- estado y log
def log(msg: str) -> None:
    try:
        f = data_dir() / "logs" / "cookieguard.log"
        if f.exists() and f.stat().st_size > 1_000_000:
            f.replace(f.with_suffix(".log.1"))
        with open(f, "a", encoding="utf-8") as fh:
            fh.write(f"{datetime.now().isoformat(timespec='seconds')} {msg}\n")
    except Exception:
        pass


def load_state() -> dict:
    f = data_dir() / "state.json"
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state(state: dict) -> None:
    f = data_dir() / "state.json"
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, f)


def load_catalog(name: str):
    return json.loads((APP_ROOT / "catalogo" / name).read_text(encoding="utf-8-sig"))


def now_ts() -> float:
    return time.time()
