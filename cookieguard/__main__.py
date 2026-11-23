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
    cn = sub.add_parser("canary", help="Gestion y siembra de cookies canary (cebos)")
    cn.add_argument("--plantar", action="store_true", help="Siembra cebos canary locales en todos los perfiles")
    cn.add_argument("--comprobar", action="store_true", help="Comprueba integridad de los cebos")
    cn.add_argument("--asistente", action="store_true", help="Abre asistente interactivo")

    ks = sub.add_parser("killswitch", help="Control de aislamiento de red de emergencia")
    ks.add_argument("--activar", action="store_true", help="Activa el corte de red saliente")
    ks.add_argument("--desactivar", action="store_true", help="Restaura la red normal")
    ks.add_argument("--estado", action="store_true", help="Muestra el estado actual")

    wh = sub.add_parser("webhook", help="Notificaciones remotas por webhook (ntfy/Discord/Telegram)")
    wh.add_argument("--probar", action="store_true", help="Envia alerta de prueba")
    wh.add_argument("--url", type=str, help="Configura la URL del webhook")
    sub.add_parser("hardening", help="Auditoría y endurecimiento de Preferences")
    sub.add_parser("tray", help="Inicia el vigilante con icono en bandeja de sistema")
    sub.add_parser("dbsc", help="Comprueba compatibilidad y sesiones DBSC")

    tr = sub.add_parser("triage", help="Modo rescate USB: genera informe y checklist en memoria/USB sin tocar disco")
    tr.add_argument("--salida", "-o", type=str, default=None, help="Carpeta de destino del informe de rescate")
    tr.add_argument("--no-abrir", action="store_true", help="No abre el navegador automáticamente")

    pr = sub.add_parser("procesos", help="Process Hunter: escanea procesos en memoria buscando infostealers activos")
    pr.add_argument("--json", action="store_true", help="Salida en formato JSON")

    u_ioc = sub.add_parser("update-iocs", help="Actualiza la base de datos de IoCs (Threat Intelligence)")
    u_ioc.add_argument("--feed", type=str, default=None, help="URL del feed personalizado")
    u_ioc.add_argument("--force", action="store_true", help="Fuerza la descarga ignorando la cache TTL")
    u_ioc.add_argument("--check", action="store_true", help="Comprueba el estado de la base de datos sin descargar")

    sub.add_parser("simular", help="Ejecuta simulador de ataque seguro para probar alertas y triaje")

    srv = sub.add_parser("service", help="Gestion del servicio en segundo plano y autoarranque")
    srv.add_argument("accion", choices=["install", "uninstall", "status"], help="Accion del servicio")

    ds = sub.add_parser("desktop-sessions", help="Audita sesiones de escritorio (Telegram, Discord, Wallets)")
    ds.add_argument("--json", action="store_true", help="Salida en formato JSON")

    ext = sub.add_parser("extensions", help="Audita extensiones de navegador y permisos abusivos")
    ext.add_argument("--json", action="store_true", help="Salida en formato JSON")
    hp = sub.add_parser("honeypot", help="Gestion de perfiles senuelo trampa contra infostealers")
    hp.add_argument("--setup", action="store_true", help="Crea perfiles trampa en los navegadores")
    hp.add_argument("--check", action="store_true", help="Comprueba si algun perfil trampa fue leido")
    hp.add_argument("--remove", action="store_true", help="Elimina los perfiles trampa")

    ma = sub.add_parser("memory-audit", help="Audita memoria y DLLs inyectadas en navegadores activos")
    ma.add_argument("--json", action="store_true", help="Salida en formato JSON")

    sn = sub.add_parser("snapshot", help="Genera snapshot forense de evidencias volatiles en ZIP")
    sn.add_argument("--motivo", type=str, default="manual", help="Motivo de la captura")
    sn.add_argument("--salida", type=str, default=None, help="Carpeta de destino")

    dos = sub.add_parser("dossier", help="Genera informe formal de incidente alineado con MITRE ATT&CK")
    dos.add_argument("--formato", choices=["html", "md"], default="html", help="Formato del dossier")
    dos.add_argument("--salida", type=str, default=None, help="Ruta del archivo generado")

    rev = sub.add_parser("revocar", help="Genera script por lotes para revocacion rapida de sesiones")
    rev.add_argument("--salida", type=str, default=None, help="Carpeta de destino del script")

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
        if getattr(args, "plantar", False):
            n = canary.plant_all_profiles()
            print(f"Sembrados {n} cebos canary en los perfiles disponibles.")
            return 0
        elif getattr(args, "comprobar", False):
            res = canary.verify_canaries()
            st_text = "Disparados: SI" if res["disparados"] else "Disparados: NO"
            print(f"Estado de Canaries: {res['activos']} activos | {st_text}")
            if res["disparados"]:
                for a in res["alertas"]:
                    print(f"  🚨 {a}")
            return 0
        else:
            return canary.wizard_cli()
    elif args.cmd == "killswitch":
        from . import killswitch
        if getattr(args, "activar", False):
            ok, msg = killswitch.enable()
            tag = "OK" if ok else "FALLO"
            print(f"[{tag}] {msg}")
            return 0 if ok else 1
        elif getattr(args, "desactivar", False):
            ok, msg = killswitch.disable()
            tag = "OK" if ok else "FALLO"
            print(f"[{tag}] {msg}")
            return 0 if ok else 1
        else:
            st = killswitch.status()
            st_str = "ACTIVO (Aislado)" if st.get("activo") else "Desactivado (Normal)"
            print(f"Killswitch de Red: {st_str}")
            if st.get("detalles"):
                print(f"  Detalle: {st['detalles']}")
            return 0
    elif args.cmd == "webhook":
        from . import webhook
        from .common import save_user_config
        url = getattr(args, "url", None)
        if url:
            save_user_config({"webhook_url": url, "webhook_activo": True})
            print(f"Webhook configurado y activado: {url}")
        if getattr(args, "probar", False) or not url:
            ok, msg = webhook.test_webhook(url or "")
            tag = "OK" if ok else "FALLO"
            print(f"[{tag}] {msg}")
            return 0 if ok else 1
        return 0
    elif args.cmd == "hardening":
        from . import browsers, hardening
        profiles = browsers.discover()
        res = hardening.audit_all_profiles(profiles)
        print(f"=== Auditoria de Endurecimiento de Navegadores (Puntuacion media: {res['puntuacion_media']}/100) ===")
        for p in res["perfiles"]:
            mark = "OK " if p["estado"] == "ok" else "!! "
            print(f"  [{mark}] {p['navegador']} ({p['perfil']}): {p['puntuacion']}/100")
            for h in p["hallazgos"]:
                print(f"         - Alerta: {h}")
            for r in p["recomendaciones"]:
                print(f"         * Recomendacion: {r}")
        return 0
    elif args.cmd == "dbsc":
        from . import browsers, dbsc, inventory
        profiles = browsers.discover()
        cookies, _errs, _meta = inventory.collect(profiles)
        from .classifier import classify_all
        sessions = classify_all(cookies)
        res = dbsc.evaluate_dbsc_readiness(profiles, sessions)
        comp = "SI" if res["compatible"] else "NO"
        print(f"=== Evaluacion de DBSC (Device Bound Session Credentials) ===")
        print(f"Navegadores compatibles: {comp} ({len(res['navegadores_compatibles'])} detectados)")
        print(f"Sesiones protegibles por hardware: {res['total_sesiones_protegibles']}")
        for s in res["sesiones_protegibles"]:
            print(f"  [DBSC] {s['servicio']} ({s['dominio']}): {s['estado_dbsc']} vía {s['soporte_hardware']}")
        for r in res["recomendaciones"]:
            print(f"  * {r}")
        return 0
    elif args.cmd == "tray":
        from . import tray
        tray.start_tray()
        return 0
    elif args.cmd == "triage":
        from . import triage
        res = triage.run_triage(salida_dir=getattr(args, "salida", None), open_report=not getattr(args, "no_abrir", False))
        print("\n=== MODO RESCATE USB COMPLETADO ===")
        print(f"Directorio de salida: {res['salida']}")
        print(f"Informe interactivo:  {res['html']}")
        print(f"Checklist urgente:    {res['txt']}")
        print(f"Metadatos JSON:       {res['json']}")
        if res.get("malware_encontrado"):
            print(f"\n🚨 ¡PELIGRO! Se detectaron {len(res['sospechosos'])} procesos sospechosos en ejecución.")
            for s in res['sospechosos']:
                print(f"   * {s['name']} (PID {s['pid']}): {s['motivo']}")
                print(f"     Comando para detener: {s['comando']}")
        else:
            print("\n[OK] Memoria limpia: no se encontraron infostealers evidentes en ejecución.")
        return 0
    elif args.cmd == "procesos":
        from . import process_hunter
        res = process_hunter.scan_processes()
        if getattr(args, "json", False):
            import json
            print(json.dumps(res, indent=2, ensure_ascii=False))
        else:
            print(f"\n=== PROCESS HUNTER: {res['total_procesos']} procesos analizados ===")
            if res.get("limpio"):
                print("[OK] No se detectaron infostealers ni procesos maliciosos en memoria.")
            else:
                print(f"🚨 ¡ALERTA! Se han detectado {res['sospechosos_count']} proceso(s) sospechoso(s):")
                for s in res["sospechosos"]:
                    print(f"\n  [!] {s['name']} (PID {s['pid']}) - {s['familia']} [{s['severidad']}]")
                    print(f"      Ruta: {s['exe']}")
                    print(f"      Motivo: {s['motivo']}")
                    print(f"      Acción: {s['comando']}")
        return 0
    elif args.cmd == "update-iocs":
        from . import ioc_updater
        if getattr(args, "check", False):
            iocs = ioc_updater.get_active_iocs()
            print("=== ESTADO DE BASE DE DATOS DE IOCs (THREAT INTELLIGENCE) ===")
            print(f"Version: {iocs.get('_version', 'local')}")
            print(f"Ultima actualizacion: {iocs.get('actualizado', 'No disponible')}")
            print(f"Hashes SHA-256 de stealers: {len(iocs.get('stealer_hashes_sha256', []))}")
            print(f"Dominios de C2/Exfiltracion: {len(iocs.get('c2_dominios', []))}")
            print(f"IPs y Subredes de C2:        {len(iocs.get('c2_ips', []))}")
            print(f"Nombres de ejecutables:       {len(iocs.get('stealer_nombres_ejecutables', []))}")
            return 0
        res = ioc_updater.update_iocs(feed_url=getattr(args, "feed", None), force=getattr(args, "force", False))
        tag = "OK" if res["success"] else "AVISO"
        print(f"[{tag}] {res['mensaje']}")
        print(f"Total hashes: {res['total_hashes']} | Dominios C2: {res['total_dominios']} | Version: {res.get('version', '')}")
        return 0 if res["success"] else 1
    elif args.cmd == "simular":
        from . import simulator
        res = simulator.run_attack_simulation()
        return 0 if res["todas_pasadas"] else 1
    elif args.cmd == "service":
        from . import service
        accion = getattr(args, "accion", "status")
        if accion == "install":
            res = service.install_service()
            print(f"[{'OK' if res.get('success') else 'FALLO'}] {res.get('mensaje')}")
            return 0 if res.get('success') else 1
        elif accion == "uninstall":
            res = service.uninstall_service()
            print(f"[{'OK' if res.get('success') else 'FALLO'}] {res.get('mensaje')}")
            return 0 if res.get('success') else 1
        else:
            res = service.status_service()
            print(f"Servicio ({res.get('plataforma')}): {'INSTALADO' if res.get('instalado') else 'NO INSTALADO'}")
            print(f"Detalle: {res.get('detalle') or res.get('estado') or 'N/A'}")
            return 0
    elif args.cmd == "desktop-sessions":
        from . import desktop_sessions
        res = desktop_sessions.audit_desktop_sessions()
        if getattr(args, "json", False):
            import json
            print(json.dumps(res, indent=2, ensure_ascii=False))
        else:
            print(f"=== SESIONES Y BILLETERAS DE ESCRITORIO ({res['apps_detectadas']} detectadas) ===")
            for s in res["sesiones"]:
                print(f"  [{s['criticidad']}] {s['app']} ({s['categoria']})")
                print(f"      Ruta: {s['ruta']} ({s['num_archivos']} ficheros, ult. mod. hace {s['horas_ultima_modificacion']}h)")
                print(f"      Consejo: {s['consejo']}")
        return 0
    elif args.cmd == "extensions":
        from . import extensions
        res = extensions.audit_browser_extensions()
        if getattr(args, "json", False):
            import json
            print(json.dumps(res, indent=2, ensure_ascii=False))
        else:
            print(f"=== EXTENSIONES DE NAVEGADOR AUDITADAS ({len(res)} extensiones) ===")
            for e in res[:15]:
                mark = "!!" if e["severidad"] in ("CRITICA", "ALTA") else "OK"
                print(f"  [{mark} - {e['severidad']}] {e['nombre']} v{e['version']} ({e['browser']})")
                print(f"      ID: {e['extension_id']} | Sideloaded: {'SI' if e['es_sideloaded'] else 'NO'}")
                if e["motivos"]:
                    print(f"      Riesgos: {', '.join(e['motivos'])}")
        return 0
    return 0



if __name__ == "__main__":
    sys.exit(main() or 0)
