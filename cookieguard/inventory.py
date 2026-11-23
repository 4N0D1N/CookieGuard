"""Inventario de cookies de sesion: lectura de metadatos, clasificacion, agrupacion y linea base."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from . import classifier
from .browsers import Profile, discover
from .common import load_config, load_state, log
from .sqlite_meta import DbLocked, read_metadata

CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
CHROMIUM_COLS = ["host_key", "name", "path", "creation_utc", "expires_utc", "last_access_utc", "last_update_utc",
                 "is_secure", "is_httponly", "samesite", "is_persistent", "has_expires", "source_scheme"]
FIREFOX_COLS = ["host", "name", "path", "expiry", "lastAccessed", "creationTime", "isSecure", "isHttpOnly",
                "sameSite"]


def chrome_time(us) -> datetime | None:
    """Microsegundos desde 1601-01-01 UTC -> hora local. 0/invalido -> None."""
    try:
        us = int(us)
        if us <= 0 or us > 2 ** 56:
            return None
        return (CHROME_EPOCH + timedelta(microseconds=us)).astimezone().replace(tzinfo=None)
    except (OverflowError, ValueError, TypeError):
        return None


def unix_time(value, unit: str = "s") -> datetime | None:
    """Epoch Unix en segundos ('s'), milisegundos ('ms') o microsegundos ('us') -> hora local."""
    try:
        v = float(value)
        if v <= 0:
            return None
        v = v / {"s": 1, "ms": 1e3, "us": 1e6}[unit]
        if v > 253402300799:
            return None
        return datetime.fromtimestamp(v)
    except (OverflowError, ValueError, TypeError, OSError):
        return None


def firefox_expiry(v) -> datetime | None:
    """Firefox guarda 'expiry' en segundos; versiones recientes pueden usar milisegundos."""
    try:
        return unix_time(v, "ms" if float(v) > 1e11 else "s")
    except (TypeError, ValueError):
        return None


def _chromium_records(p: Profile) -> list[dict]:
    rows = read_metadata(p.cookies_db, "cookies", CHROMIUM_COLS)
    out = []
    for r in rows:
        persistent = bool(r.get("is_persistent", r.get("has_expires", 1)))
        exp = chrome_time(r.get("expires_utc")) if persistent else None
        out.append({
            "browser": p.browser, "profile": p.profile, "host": r.get("host_key", ""), "name": r.get("name", ""),
            "path": r.get("path", "/"), "created": chrome_time(r.get("creation_utc")), "expires": exp,
            "last_access": chrome_time(r.get("last_access_utc")), "last_update": chrome_time(r.get("last_update_utc")),
            "secure": bool(r.get("is_secure")), "httponly": bool(r.get("is_httponly")),
            "samesite": r.get("samesite"), "persistent": persistent,
        })
    return out


def _firefox_records(p: Profile) -> list[dict]:
    rows = read_metadata(p.cookies_db, "moz_cookies", FIREFOX_COLS)
    out = []
    for r in rows:
        exp = firefox_expiry(r.get("expiry"))
        out.append({
            "browser": p.browser, "profile": p.profile, "host": r.get("host", ""), "name": r.get("name", ""),
            "path": r.get("path", "/"), "created": unix_time(r.get("creationTime"), "us"), "expires": exp,
            "last_access": unix_time(r.get("lastAccessed"), "us"), "last_update": None,
            "secure": bool(r.get("isSecure")), "httponly": bool(r.get("isHttpOnly")),
            "samesite": r.get("sameSite"), "persistent": bool(exp),
        })
    return out


def record_key(r: dict) -> str:
    return "|".join([r["browser"], r["profile"], r["host"], r["name"], r["path"] or "/"])


def collect(profiles: list[Profile] | None = None, cfg: dict | None = None):
    """Lee todas las cookies (solo metadatos). Devuelve (registros_de_sesion, estadisticas, errores)."""
    cfg = cfg or load_config()
    profiles = profiles if profiles is not None else discover()
    now = datetime.now()
    sessions, errors = [], []
    total = 0
    for p in profiles:
        try:
            recs = _chromium_records(p) if p.family == "chromium" else _firefox_records(p)
        except DbLocked as e:
            errors.append(f"{p.browser}/{p.profile}: {e}")
            continue
        except Exception as e:  # noqa: BLE001
            errors.append(f"{p.browser}/{p.profile}: error leyendo ({type(e).__name__})")
            log(f"error leyendo {p.browser}/{p.profile}: {e}")
            continue
        total += len(recs)
        for r in recs:
            r["now"] = now
            ok, conf, svc, why = classifier.classify(r)
            r.pop("now", None)
            if not ok:
                continue
            r["confianza"], r["motivo"] = conf, why
            r["servicio_id"] = svc["id"] if svc else None
            sessions.append(r)
    stats = {"perfiles": len(profiles), "cookies_totales": total, "cookies_sesion": len(sessions)}
    return sessions, stats, errors


def group_sessions(sessions: list[dict], cfg: dict | None = None, baseline: set | None = None) -> list[dict]:
    """Agrupa por servicio o dominio, con caducidad, ultimo uso, estado, zombie y novedades."""
    cfg = cfg or load_config()
    d = cfg["dias"]
    now = datetime.now()
    groups: dict[str, dict] = {}
    for r in sessions:
        svc = classifier.match_service(r["host"])
        if svc:
            key, nombre, cat = svc["id"], svc["nombre"], svc["categoria"]
        else:
            key = classifier.registrable(r["host"])
            nombre, cat = key, "otros"
        g = groups.setdefault(key, {
            "id": key, "nombre": nombre, "categoria": cat, "en_catalogo": bool(svc),
            "critico": classifier.categoria_critica(cat), "cookies": 0, "navegadores": set(), "perfiles": set(),
            "caducidad_max": None, "ultimo_uso": None, "nuevas": 0, "dominios": set(), "confianza": "Baja",
            "solo_sesion": 0,
        })
        g["cookies"] += 1
        g["navegadores"].add(r["browser"])
        g["perfiles"].add(f"{r['browser']}/{r['profile']}")
        g["dominios"].add(r["host"].lstrip("."))
        if r["expires"] and (g["caducidad_max"] is None or r["expires"] > g["caducidad_max"]):
            g["caducidad_max"] = r["expires"]
        if r["last_access"] and (g["ultimo_uso"] is None or r["last_access"] > g["ultimo_uso"]):
            g["ultimo_uso"] = r["last_access"]
        if r["confianza"] == "Alta" or (r["confianza"] == "Media" and g["confianza"] == "Baja"):
            g["confianza"] = r["confianza"]
        if baseline is not None and record_key(r) not in baseline:
            g["nuevas"] += 1
        if not r["persistent"]:
            g["solo_sesion"] += 1
    out = []
    for g in groups.values():
        exp, last = g["caducidad_max"], g["ultimo_uso"]
        days_idle = (now - last).days if last else None
        g["dias_sin_uso"] = days_idle
        g["zombie"] = bool(exp and (exp - now).days > d["zombie_caduca_en"] and
                           (days_idle is None or days_idle > d["zombie_sin_uso"]))
        if exp is None:
            estado = "Solo hasta cerrar el navegador"
        elif exp < now:
            estado = "Caducada"
        elif (exp - now).days <= d["caduca_pronto"]:
            estado = "Caduca pronto"
        elif days_idle is not None and days_idle > d["sin_uso"]:
            estado = f"Sin uso desde hace {days_idle} dias"
        else:
            estado = "Vigente"
        g["estado"] = estado
        g["riesgo"] = _group_risk(g)
        g["navegadores"] = sorted(g["navegadores"])
        g["perfiles"] = sorted(g["perfiles"])
        g["dominios"] = sorted(g["dominios"])
        out.append(g)
    out.sort(key=lambda g: (classifier.categoria_orden(g["categoria"]), g["nombre"].lower()))
    return out


def _group_risk(g: dict) -> str:
    score = 0
    score += 2 if g["critico"] else 0
    score += 2 if g["zombie"] else 0
    score += 1 if g["nuevas"] else 0
    score += 1 if g["caducidad_max"] and (g["caducidad_max"] - datetime.now()).days > 365 else 0
    return "Alto" if score >= 4 else "Medio" if score >= 2 else "Bajo"


def baseline_keys() -> set | None:
    b = load_state().get("baseline_sesiones")
    return set(b) if b is not None else None


def session_keys(sessions: list[dict]) -> list[str]:
    return sorted({record_key(r) for r in sessions})


def to_serializable(obj):
    if isinstance(obj, datetime):
        return obj.isoformat(timespec="seconds")
    if isinstance(obj, set):
        return sorted(obj)
    raise TypeError(type(obj))
