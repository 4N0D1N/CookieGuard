"""Linea de comandos de CookieGuard.  python -m cookieguard <orden>"""
from __future__ import annotations

import argparse
import io
import json
import os
import sys

if sys.stdout is None:                      # pythonw: sin consola
    sys.stdout = io.StringIO()
if sys.stderr is None:
    sys.stderr = io.StringIO()
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass


def _print_summary(res):
    v = res["veredicto"]
    print(f"\n=== Semaforo: {v['nombre'].upper()} ({v['puntos']} puntos) - {v['texto']}")
    st = res["estadisticas"]
    print(f"    {st['cookies_sesion']} cookies de sesion en {len(res['grupos'])} servicios, "
          f"{st['perfiles']} perfiles. Duracion {res['duracion_s']} s")
    for i in res["indicadores"]:
        mark = {"ok": "OK ", "alerta": "!! ", "sin_datos": "?  ", "no_aplica": "-  ", "error": "ERR"}[i["estado"]]
        print(f"  [{mark}] {i['nombre']}: {i['resumen']}")
        if i["estado"] == "alerta":
            for h in i["hallazgos"][:5]:
                print(f"         - {h}")
    for e in res["errores"]:
        print(f"  (aviso) {e}")
    print(f"    {v['aviso']}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="cookieguard", description="CookieGuard: auditor de cookies de sesion")
    sub = ap.add_subparsers(dest="cmd")
    a = sub.add_parser("analizar", help="Analiza y abre el informe")
    a.add_argument("--no-abrir", action="store_true")
    a.add_argument("--json", action="store_true")
    sub.add_parser("login", help="Analisis silencioso de inicio de sesion (con notificacion)")
    sub.add_parser("gui", help="Abre la interfaz")
    sub.add_parser("vigilar", help="Vigilancia en tiempo real")
    i = sub.add_parser("instalar")
    i.add_argument("--dry-run", action="store_true")
    i.add_argument("--si", action="store_true", help="Acepta todas las preguntas")
    d = sub.add_parser("desinstalar")
    d.add_argument("--dry-run", action="store_true")
    d.add_argument("--si", action="store_true")
    sub.add_parser("incidente", help="ZIP forense sin valores de cookies")
    sub.add_parser("probar-notificacion")
    sub.add_parser("restaurar", help="Lista las copias de seguridad de cookies")
    r = sub.add_parser("restaurar-id")
    r.add_argument("id")
    sub.add_parser("canary", help="Asistente de cookies canary")
    sub.add_parser("version")
    for n in ("admin-instalar", "admin-desinstalar", "admin-sacl"):
        sub.add_parser(n)
    args, _extra = ap.parse_known_args(argv)

    from . import actions, engine, reports
    from .common import VERSION

    if args.cmd in (None, "gui"):
        try:
            from . import gui
            return gui.main()
        except (ImportError, Exception) as e:
            print(f"Aviso: Interfaz nativa no disponible ({e}).")
            print("Abriendo el dashboard visual e informe interactivo en tu navegador...")
            res = engine.run_login(open_report=True, notify_user=False)
            return 0
    if args.cmd == "version":
        print(VERSION)
    elif args.cmd == "analizar":
        res = engine.run_login(open_report=not args.no_abrir, notify_user=False)
        if args.json:
            print(reports.to_json(res))
        else:
            _print_summary(res)
            print(f"    Informe: {res['informe']}")
    elif args.cmd == "login":
        res = engine.run_login(open_report=False, notify_user=True)
        print(f"{res['veredicto']['nombre']} {res['informe']}")
    elif args.cmd == "vigilar":
        from . import watcher
        return watcher.main()
    elif args.cmd == "instalar":
        from . import installer
        return installer.install(dry_run=args.dry_run, assume_yes=args.si)
    elif args.cmd == "desinstalar":
        from . import installer
        return installer.uninstall(dry_run=args.dry_run, assume_yes=args.si)
    elif args.cmd in ("admin-instalar", "admin-desinstalar", "admin-sacl"):
        from . import installer
        return {"admin-instalar": installer.admin_install, "admin-desinstalar": installer.admin_uninstall,
                "admin-sacl": installer.apply_sacl}[args.cmd]() and 0
    elif args.cmd == "incidente":
        res = engine.run_analysis(update_state=False)
        print(actions.incident_zip(res))
    elif args.cmd == "probar-notificacion":
        from .notify import notify
        print(notify("CookieGuard", "Notificacion de prueba: todo funciona.", None, "verde"))
    elif args.cmd == "restaurar":
        for b in actions.list_backups():
            print(b["id"], b["fecha"], b["filas"], "filas", b["dominios"] or "(todas)")
    elif args.cmd == "restaurar-id":
        print(actions.restore_backup(args.id))
    elif args.cmd == "canary":
        from . import canary
        return canary.wizard_cli()
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
