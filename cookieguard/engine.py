"""Orquesta un analisis completo: inventario + indicadores + semaforo + informes + notificacion."""
from __future__ import annotations

import platform
import time
from datetime import datetime

from . import inventory, reports, risk
from .browsers import discover
from .common import VERSION, load_config, load_state, log, save_state
from .detections import Ctx, run_all
from .notify import notify


def run_analysis(profiles=None, scan_dirs=None, update_state: bool = True, progress=None) -> dict:
    t0 = time.time()
    cfg, state = load_config(), load_state()
    profiles = discover() if profiles is None else profiles
    sessions, stats, errors = inventory.collect(profiles, cfg)
    baseline = inventory.baseline_keys()
    grupos = inventory.group_sessions(sessions, cfg, baseline)
    ctx = Ctx(cfg, profiles, sessions, state, scan_dirs)
    ctx.extensions = []
    indicadores = run_all(ctx, progress)
    veredicto = risk.evaluate(indicadores, cfg)
    veredicto["lectura_incompleta"] = bool(errors)
    if errors:
        veredicto["aviso_lectura"] = (f"No se pudieron leer {len(errors)} base(s) de cookies (navegador abierto o sin permiso): "
                                      "cierra el navegador, reintenta como administrador o deja que se analice al iniciar sesion.")
        if veredicto["nivel"] == "verde":
            veredicto["texto"] = ("Sin indicios en lo que se pudo revisar, pero la lectura de cookies esta INCOMPLETA"
                                  if stats["cookies_sesion"] else
                                  "Sin indicios en los indicadores, pero NO se pudo leer ninguna cookie (navegador abierto)")
    res = {
        "generado": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "version": VERSION,
        "sistema": f"{platform.system()} {platform.release()}", "estadisticas": stats, "errores": errors,
        "veredicto": veredicto, "indicadores": indicadores, "grupos": grupos, "sesiones": sessions,
        "extensiones": ctx.extensions, "duracion_s": round(time.time() - t0, 1),
        "primera_ejecucion": baseline is None,
    }
    if update_state:
        state["baseline_sesiones"] = inventory.session_keys(sessions)
        pend = state.setdefault("pendiente", {})
        for k, v in ctx.new_state.items():
            if state.get(k) is None:
                state[k] = v           # primera vez: se fija la linea base
            else:
                pend[k] = v            # despues solo cambia si el usuario acepta los cambios
        hist = state.setdefault("historial", [])
        hist.append({"fecha": res["generado"], "nivel": veredicto["nivel"], "puntos": veredicto["puntos"],
                     "sesiones": stats["cookies_sesion"], "servicios": len(grupos), "segundos": res["duracion_s"]})
        state["historial"] = hist[-100:]
        state["ultimo"] = {"fecha": res["generado"], "nivel": veredicto["nivel"], "puntos": veredicto["puntos"]}
        save_state(state)
    log(f"analisis {veredicto['nivel']} {veredicto['puntos']}pts {res['duracion_s']}s "
        f"{stats['cookies_sesion']} sesiones")
    return res


def accept_baseline() -> int:
    """El usuario acepta como normales los cambios pendientes (persistencia, red, extensiones)."""
    st = load_state()
    pend = st.get("pendiente", {})
    n = len(pend)
    for k, v in pend.items():
        st[k] = v
    st["pendiente"] = {}
    save_state(st)
    return n


def run_login(open_report: bool = False, notify_user: bool = True) -> dict:
    """Analisis al iniciar sesion: genera informe y avisa segun el nivel y el modo silencioso."""
    res = run_analysis()
    path = reports.write_reports(res, open_browser=open_report)
    cfg = load_config()
    v = res["veredicto"]
    if notify_user:
        quiet = cfg.get("silencioso", False)
        if v["nivel"] != "verde" or (not quiet and cfg.get("notificar_verde", True)):
            titulo = f"CookieGuard: semaforo {v['nombre'].upper()}"
            msg = v["texto"] + (f". {v['principales'][0]}" if v["principales"] else "")
            res["notificacion"] = notify(titulo, msg[:220], path, v["nivel"])
    res["informe"] = str(path)
    return res
