"""Clasificador de cookies de sesion/autenticacion y agrupacion por servicio."""
from __future__ import annotations

import re
from functools import lru_cache

from .common import load_catalog

_TWO_LEVEL = {"co.uk", "org.uk", "ac.uk", "com.au", "net.au", "com.br", "com.mx", "com.ar", "co.jp", "co.in",
              "com.tr", "com.es", "co.nz", "co.za", "com.cn", "com.co", "com.pe", "com.cl"}

_AUTH_RE = re.compile(r"(sess|(^|[_\-.])sid($|[_\-.\d])|auth|token|jwt|login|logged|ticket|sso|bearer|remember|"
                      r"credential|identity|userid|user_id|account)", re.I)
_TRACKER_RE = re.compile(r"^(_ga|_gid|_gat|_fbp|_fbc|_gcl_|__utm|_hj|_clck|_clsk|ide$|nid$|test_cookie|ajs_|"
                         r"amplitude|optimizely|__cf_bm|_cfuvid|cf_clearance|optanon|cookieconsent|_pk_|_uet|"
                         r"mp_|__gads|__gpi|datadog|_dd_s|_scid|_tt_|_pin_|personalization_id|guest_id|"
                         r"consent|cookie_?notice|euconsent|usprivacy|_rdt|_omappvp|_parsely|_cc_)", re.I)
_PREFIX_RE = re.compile(r"^(__secure-|__host-)", re.I)


@lru_cache(maxsize=1)
def catalog():
    cat = load_catalog("servicios.json")
    by_domain = {}
    for s in cat["servicios"]:
        for d in s["dominios"]:
            by_domain[d.lower()] = s
    return cat, by_domain


def registrable(host: str) -> str:
    h = host.lstrip(".").lower()
    parts = h.split(".")
    if len(parts) <= 2:
        return h
    if ".".join(parts[-2:]) in _TWO_LEVEL and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def match_service(host: str):
    """Devuelve la entrada del catalogo cuyo dominio coincide con host (o None)."""
    _, by_domain = catalog()
    h = host.lstrip(".").lower()
    labels = h.split(".")
    for i in range(len(labels) - 1):
        cand = ".".join(labels[i:])
        if cand in by_domain:
            return by_domain[cand]
    return None


def classify(rec: dict):
    """Devuelve (es_sesion: bool, confianza: 'Alta'|'Media'|'Baja'|'', servicio|None, motivo)."""
    svc = match_service(rec["host"])
    name = rec["name"] or ""
    base = _PREFIX_RE.sub("", name)
    if svc:
        # Indicadores de estado de navegación (no son secretos de autenticación)
        if name.lower() in {"logged_in", "dotcom_user", "has_recent_activity"}:
            return True, "Baja", svc, "indicador de estado de navegación (no confiere acceso por sí sola)"
        known = {c.lower() for c in svc.get("cookies", [])}
        if name.lower() in known or base.lower() in known or any(
                k.endswith("-") and name.lower().startswith(k) for k in known):
            return True, "Alta", svc, "cookie conocida del catalogo"
    if _TRACKER_RE.match(base):
        return False, "", svc, ""
    if _AUTH_RE.search(base):
        if rec.get("httponly") and rec.get("secure"):
            return True, "Media", svc, "nombre de sesion + HttpOnly + Secure"
        if rec.get("httponly") or rec.get("secure"):
            return True, "Baja", svc, "nombre de sesion + un flag de proteccion"
        return True, "Baja", svc, "nombre de sesion"
    exp, now = rec.get("expires"), rec.get("now")
    if rec.get("httponly") and rec.get("secure") and exp and now and (exp - now).days > 365 and len(base) <= 12 \
            and svc is None:
        return True, "Baja", svc, "HttpOnly+Secure con caducidad muy larga"
    return False, "", svc, ""


def categoria_critica(cat_id: str) -> bool:
    cat, _ = catalog()
    return cat_id in cat["categorias_criticas"]


def categoria_orden(cat_id: str) -> int:
    cat, _ = catalog()
    try:
        return cat["categorias_orden"].index(cat_id)
    except ValueError:
        return len(cat["categorias_orden"])
