"""Linea de comandos de CookieGuard.  python -m cookieguard <orden>"""
from __future__ import annotations

import argparse
import io
import json
import json as _json
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

    sc = sub.add_parser("stix", help="Exporta alertas actuales a un Bundle STIX 2.1")
    sc.add_argument("--salida", type=str, default=None, help="Ruta destino del JSON STIX")

    dc = sub.add_parser("dns-canary", help="Genera y revisa DNS canaries de detección pasiva")
    dc_sub = dc.add_subparsers(dest="dns_cmd")
    dc_gen = dc_sub.add_parser("generate", help="Genera un nombre canary único, no lo despliega")
    dc_gen.add_argument("--domain", required=True, help="Dominio DNS propio/controlado para recibir consultas")
    dc_gen.add_argument("--notes", default="", help="Nota local para identificar el token")
    dc_sub.add_parser("list", help="Lista registros canary almacenados localmente")
    dc_check = dc_sub.add_parser("check", help="Compara una lista DNS local con canaries almacenados")
    dc_check.add_argument("--file", required=True, help="Archivo de texto con nombres DNS observados")

    sn.add_argument("--cifrar", action="store_true", help="Cifra snapshot con contraseña solicitada de forma segura")
    sn.add_argument("--sin-anonimizar", action="store_true", help="Desactiva la anonimización automática; úsalo solo si necesitas preservar datos para análisis local")

    dec = sub.add_parser("snapshot-descifrar", help="Descifra un snapshot .cgenc con contraseña")
    dec.add_argument("archivo", help="Ruta al archivo .cgenc")
    dec.add_argument("--salida", type=str, default=None, help="Ruta destino del ZIP")


    shc = sub.add_parser("shortcuts", help="Audita accesos directos de navegador (.lnk y .desktop) buscando inyecciones de flags o proxies")
    shc.add_argument("--json", action="store_true", help="Salida en formato JSON")

    syn = sub.add_parser("sync", help="Audita cuentas sincronizadas y perfiles de navegador buscando sincronización no autorizada")
    syn.add_argument("--json", action="store_true", help="Salida en formato JSON")
    syn.add_argument("--sin-anonimizar", action="store_true", help="Muestra direcciones de correo completas")

    pb = sub.add_parser("playbook", help="Genera playbook interactivo y checklist de revocación de sesiones (HTML y Markdown)")
    pb.add_argument("--formato", choices=["html", "md", "ambos"], default="ambos", help="Formato del playbook")
    pb.add_argument("--salida", type=str, default=None, help="Carpeta o archivo de salida")

    crt = sub.add_parser("certs", help="Audita certificados raíz de intercepción y configuración de proxies locales MITM")
    crt.add_argument("--json", action="store_true", help="Salida en formato JSON")

    dbi = sub.add_parser("db-integrity", help="Audita la integridad física, time-stomping y bloqueos en SQLite de navegadores")
    dbi.add_argument("--json", action="store_true", help="Salida en formato JSON")

    sce = sub.add_parser("scan-extensions", help="Escanea el código de extensiones instaladas buscando firmas de exfiltración y C2")
    sce.add_argument("--json", action="store_true", help="Salida en formato JSON")

    dwn = sub.add_parser("downloads", help="Revisa metadatos del historial de descargas Chromium; no confirma infección")
    dwn.add_argument("--json", action="store_true", help="Salida en formato JSON")
    apb = sub.add_parser("appbound", help="Muestra indicadores App-Bound/DPAPI visibles; no valida protección en ejecución")
    apb.add_argument("--json", action="store_true", help="Salida en formato JSON")
    ct = sub.add_parser("canary-trap", help="Muestra una simulación Canary sin sembrar cookies ni capturar IPs")
    ct.add_argument("--dominio", default="login.microsoftonline.com", help="Dominio de referencia para la explicación")
    ct.add_argument("--callback", default=None, help="URL anotada como referencia; no se contacta")
    ct.add_argument("--json", action="store_true", help="Salida en formato JSON")

    dm = sub.add_parser("dummy", help="Resumen semáforo ultra-simplificado para dummies")
    dm.add_argument("--html", default=None, help="Ruta para generar informe HTML (opcional)")
    dm.add_argument("--json", action="store_true", help="Salida en formato JSON")

    sub.add_parser("resumen", help="Alias de 'dummy': resumen semáforo para dummies")

    per = sub.add_parser("persistence", help="Auditoría de persistencia y tareas programadas (schtasks, autostart, cron)")
    per.add_argument("--json", action="store_true", help="Salida en formato JSON")

    integ = sub.add_parser("integrity", help="Verifica firmas e integridad de binarios de navegadores instalados")
    integ.add_argument("--json", action="store_true", help="Salida en formato JSON")

    netw = sub.add_parser("network", help="Audita archivo hosts local (sinkholing/spoofing) y DNS")
    netw.add_argument("--json", action="store_true", help="Salida en formato JSON")

    sub.add_parser("hosts", help="Alias de 'network': audita archivo hosts local")

    sub.add_parser("version")
    for n in ("admin-instalar", "admin-desinstalar", "admin-sacl"):
        sub.add_parser(n)
    drl = sub.add_parser("drill", help="Modo Simulacro de Incidente en vivo (entrenamiento de respuesta y contencion)")
    drl.add_argument("--html", type=str, default=None, help="Ruta para generar informe HTML del simulacro")
    drl.add_argument("--json", action="store_true", help="Salida en formato JSON")
    sub.add_parser("simulacro", help="Alias de drill: simulacro de incidente en vivo")

    rep = sub.add_parser("report", help="Genera informe formal de incidente o dossier MITRE ATT&CK (PDF-ready o Markdown)")
    rep.add_argument("--formato", choices=["html", "md"], default="html", help="Formato del informe")
    rep.add_argument("--salida", type=str, default=None, help="Ruta de salida del archivo generado")
    sub.add_parser("informe", help="Alias de report: informe forense formal")

    cb = sub.add_parser("clipboard", help="Auditoria de portapapeles y deteccion de malware Clipper (MITRE T1115)")
    cb.add_argument("--limpiar", "--clear", action="store_true", help="Purga el portapapeles de forma segura")
    cb.add_argument("--json", action="store_true", help="Salida en formato JSON")
    sub.add_parser("clipper", help="Alias de clipboard: auditoria de portapapeles")

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
    elif args.cmd == "snapshot":
        import getpass
        from . import forensics
        password = getpass.getpass("Contraseña para cifrar el snapshot (déjala vacía para ZIP sin cifrar): ") if getattr(args, "cifrar", False) else None
        if getattr(args, "cifrar", False) and not password:
            print("FALLO: se solicitó cifrado pero no se proporcionó una contraseña.")
            return 1
        out_dir = getattr(args, "salida", None)
        try:
            path = forensics.capture_volatile_snapshot(
                reason=getattr(args, "motivo", "manual"),
                output_dir=out_dir,
                sanitize=not getattr(args, "sin_anonimizar", False),
                password=password
            )
        except (OSError, RuntimeError, ValueError) as e:
            print(f"No se pudo generar el snapshot: {e}")
            return 1
        print(f"Snapshot generado: {path}")
        return 0
    elif args.cmd == "snapshot-descifrar":
        import getpass
        from . import forensics
        password = getpass.getpass("Contraseña del snapshot: ")
        try:
            path = forensics.decrypt_snapshot(args.archivo, password, getattr(args, "salida", None))
        except (ValueError, RuntimeError, OSError) as e:
            print(f"No se pudo descifrar: {e}")
            return 1
        print(f"Snapshot descifrado: {path}")
        return 0
    elif args.cmd == "stix":
        from . import stix_export, engine
        res = engine.run_analysis(update_state=False)
        dest = stix_export.export_stix_bundle(res, getattr(args, "salida", None))
        print(f"Bundle STIX 2.1 generado: {dest}")
        return 0
    elif args.cmd == "dns-canary":
        from . import dns_canary
        subcmd = getattr(args, "dns_cmd", None)
        if subcmd == "generate":
            rec = dns_canary.generate_dns_canary_token(getattr(args, "domain"), getattr(args, "notes", ""))
            print(json.dumps(rec, indent=2, ensure_ascii=False))
            print("AVISO: solo se generó un FQDN. La señal externa requiere que el dominio sea tuyo y que un DNS autoritativo registre las consultas; no se despliega automáticamente en perfiles reales.")
            return 0
        elif subcmd == "list":
            print(json.dumps(dns_canary.list_dns_canary_tokens(), indent=2, ensure_ascii=False))
            return 0
        elif subcmd == "check":
            entries = open(args.file, encoding="utf-8").read().splitlines()
            alerts = dns_canary.check_dns_cache_for_canaries(entries)
            print(json.dumps(alerts, indent=2, ensure_ascii=False))
            return 0
        else:
            print("Uso: cookieguard dns-canary {generate|list|check}")
            return 2

    elif args.cmd == "shortcuts":
        from . import shortcuts_audit
        res = shortcuts_audit.audit_shortcuts()
        if getattr(args, "json", False):
            import json
            print(json.dumps(res, indent=2, ensure_ascii=False))
        else:
            print(f"=== AUDITORÍA DE ACCESOS DIRECTOS ({res['total_analizados']} analizados, {res['total_alertas']} alertas) ===")
            if res["alertas"]:
                for a in res["alertas"]:
                    print(f"  [ALERTA] {a['nombre']} ({a['archivo']})")
                    for h in a["hallazgos"]:
                        print(f"      - [{h['severidad']}] {h['descripcion']}")
                    if a.get("recomendacion"):
                        print(f"      Recomendación: {a['recomendacion']}")
            else:
                print("  [OK] No se detectaron flags sospechosos ni secuestro de accesos directos.")
        return 0 if not res["alertas"] else 1
    elif args.cmd == "sync":
        from . import sync_audit
        res = sync_audit.audit_all_profiles_sync(anonymize=not getattr(args, "sin_anonimizar", False))
        if getattr(args, "json", False):
            import json
            print(json.dumps(res, indent=2, ensure_ascii=False))
        else:
            print(f"=== AUDITORÍA DE SINCRONIZACIÓN DE PERFILES ({res['total_perfiles']} perfiles, {res['perfiles_con_sync']} con sync activo) ===")
            for p in res["perfiles"]:
                sync_mark = "SYNC ACTIVO" if p["sync_activo"] else "Sin sync"
                print(f"  [{sync_mark}] {p['navegador']} - {p['perfil']}")
                if p["cuentas"]:
                    for c in p["cuentas"]:
                        print(f"      Cuenta: {c.get('email', '(sin email)')} ({c.get('dominio', '')})")
                if p["servicios_sincronizados"]:
                    print(f"      Datos: {', '.join(p['servicios_sincronizados'])}")
                if p["hallazgos"]:
                    for h in p["hallazgos"]:
                        print(f"      - {h}")
        return 0
    elif args.cmd == "playbook":
        from pathlib import Path
        from . import playbooks
        fmt = getattr(args, "formato", "ambos")
        salida = getattr(args, "salida", None)
        out_p = Path(salida) if salida else None
        generados = []
        if fmt in ("html", "ambos"):
            dest_html = out_p if (out_p and str(out_p).endswith(".html")) else (out_p / "checklist_revocacion.html" if out_p else None)
            path_html = playbooks.generate_playbook_html(output_path=dest_html)
            generados.append(str(path_html))
        if fmt in ("md", "ambos"):
            dest_md = out_p if (out_p and str(out_p).endswith(".md")) else (out_p / "PLAYBOOK_REVOCACION.md" if out_p else None)
            path_md = playbooks.generate_playbook_markdown(output_path=dest_md)
            generados.append(str(path_md))
        print("Playbook(s) de revocación generados con éxito:")
        for g in generados:
            print(f"  - {g}")
        return 0
    elif args.cmd == "certs":
        from . import cert_audit
        res = cert_audit.audit_certificates_and_proxies()
        if getattr(args, "json", False):
            import json
            print(json.dumps(res, indent=2, ensure_ascii=False))
        else:
            print(f"=== AUDITORÍA DE CERTIFICADOS RAÍZ Y PROXIES ({res['certificados_analizados']} certs revisados, {res['total_alertas']} alertas) ===")
            if res["proxy"]["system_proxy_enabled"] or res["proxy"]["env_proxies"]:
                print(f"  [PROXY] Estado: {'ACTIVO' if res['proxy']['system_proxy_enabled'] else 'Por variables de entorno'}")
                if res["proxy"]["proxy_server"]:
                    print(f"      Servidor: {res['proxy']['proxy_server']}")
                for k, v in res["proxy"]["env_proxies"].items():
                    print(f"      Env {k}: {v}")
            else:
                print("  [PROXY] No se detectaron proxies de sistema ni variables de entorno activas.")
            if res["alertas"]:
                print("\n  [ALERTAS DETECTADAS]:")
                for a in res["alertas"]:
                    print(f"    - [{a.get('severidad', 'Media')}] {a.get('descripcion')}")
                if res.get("recomendacion"):
                    print(f"\n  Recomendación: {res['recomendacion']}")
            else:
                print("  [OK] No se detectaron certificados CA de depuración/MITM ni proxies anómalos.")
        return 0 if not res["alertas"] else 1
    elif args.cmd == "db-integrity":
        from . import db_integrity
        res = db_integrity.audit_browser_databases()
        if getattr(args, "json", False):
            import json
            print(json.dumps(res, indent=2, ensure_ascii=False))
        else:
            print(f"=== AUDITORÍA DE INTEGRIDAD DE BASES DE DATOS SQLITE ({res['total_dbs_analizadas']} DBs, {res['total_alertas']} alertas) ===")
            for db in res["bases_de_datos"]:
                estado = "ALERTA" if db["hallazgos"] else "OK"
                print(f"  [{estado}] {db.get('navegador', 'Navegador')} ({db.get('perfil', 'Default')}) - {db['nombre']}")
                print(f"      Tamaño: {db['tamano_bytes']} bytes | Page size: {db['page_size']} | Freelist: {db['freelist_count']}")
                if db.get("quick_check"):
                    print(f"      quick_check: {db['quick_check']} | WAL: {'SÍ' if db['wal_presente'] else 'NO'}")
                for h in db["hallazgos"]:
                    print(f"      - [{h['severidad']}] {h['descripcion']}")
        return 0 if res.get("total_alertas", 0) == 0 else 1
    elif args.cmd == "scan-extensions":
        from . import extension_scanner
        res = extension_scanner.scan_all_browser_extensions()
        if getattr(args, "json", False):
            import json
            print(json.dumps(res, indent=2, ensure_ascii=False))
        else:
            print(f"=== ESCÁNER DE CÓDIGO DE EXTENSIONES ({res['total_extensiones_analizadas']} analizadas, {res['total_alertas']} con alertas) ===")
            if res["alertas"]:
                for a in res["alertas"]:
                    print(f"  [ALERTA] {a['nombre']} ({a['navegador']} - {a['perfil']})")
                    for h in a["hallazgos"]:
                        print(f"      - [{h['severidad']}] {h['archivo']}: {h['descripcion']} ({h['coincidencias']} coincidencias)")
            else:
                print("  [OK] No se detectaron firmas maliciosas ni canales C2 en el código de las extensiones.")
        return 0 if not res["alertas"] else 1
    elif args.cmd == "downloads":
        from . import browsers, downloads_audit
        res = downloads_audit.audit_all_downloads(browsers.discover())
        if args.json:
            print(_json.dumps(res, indent=2, ensure_ascii=False))
        else:
            print(f"=== REVISIÓN DE DESCARGAS CHROMIUM ({res['perfiles_analizados']} perfiles, {res['total_sospechosas']} elementos para revisar) ===")
            if res["candidata_mas_reciente"]:
                c = res["candidata_mas_reciente"]
                print(f"  Más reciente marcada: {c['archivo']} | {c['fecha'] or 'fecha desconocida'} | {c['dominio_origen'] or 'origen desconocido'}")
                print("  Esto es una pista basada en metadatos, no prueba de infección ni de ser el origen del incidente.")
            print(f"  {res['recomendacion']}")
        return 0
    elif args.cmd == "appbound":
        from . import browsers, appbound_audit
        res = appbound_audit.audit_appbound_encryption(browsers._chromium_roots())
        if args.json:
            print(_json.dumps(res, indent=2, ensure_ascii=False))
        else:
            print(f"=== INDICADORES APP-BOUND / DPAPI ({res['navegadores_auditados']} archivos Local State) ===")
            for item in res["detalles"]:
                print(f"  {item['navegador']}: App-Bound marker={'presente' if item['marcador_app_bound'] else 'no detectado'}; DPAPI marker={'presente' if item['marcador_dpapi_legacy'] else 'no detectado'}")
            print(f"  {res['resumen']}")
        return 0
    elif args.cmd in ("dummy", "resumen"):
        from . import dummy_summary, engine, persistence_audit, network_audit
        try:
            res_analysis = engine.run_analysis(update_state=False)
            veredicto = res_analysis.get("veredicto", {})
            is_red = veredicto.get("nivel") == "rojo"
            crit_sessions = sum(len(g.get("sesiones", [])) for g in res_analysis.get("grupos", []) if g.get("criticidad") == "alta")
        except Exception:
            is_red = False
            crit_sessions = 0
        
        p_res = persistence_audit.run_persistence_audit()
        n_res = network_audit.run_network_audit()
        
        summary = dummy_summary.compute_traffic_light(
            has_critical_detections=is_red,
            active_critical_sessions=crit_sessions,
            has_persistence_alerts=p_res.get("has_alerts", False),
            has_hosts_hijack=n_res.get("has_critical", False)
        )
        if getattr(args, "json", False):
            import json as _j
            print(_j.dumps(summary, indent=2, ensure_ascii=False))
        else:
            print(dummy_summary.format_dummy_summary_cli(summary))
            html_path = getattr(args, "html", None)
            if html_path:
                dummy_summary.generate_dummy_summary_html(summary, html_path)
                print("[+] Informe HTML generado con éxito en: " + str(html_path))
        return 0

    elif args.cmd == "persistence":
        from . import persistence_audit
        res = persistence_audit.run_persistence_audit()
        if getattr(args, "json", False):
            import json as _j
            print(_j.dumps(res, indent=2, ensure_ascii=False))
        else:
            print(f"=== AUDITORÍA DE PERSISTENCIA ({res['total_audited']} elementos analizados, {res['suspicious_count']} sospechosos) ===")
            if res["suspicious_items"]:
                for s in res["suspicious_items"]:
                    print(f"  [ALERTA PERSISTENCIA] Tipo: {s.get('tipo')} | Archivo/Tarea: {s.get('nombre') or s.get('tarea') or s.get('archivo')}")
                    for a in s.get("alertas", []):
                        print(f"      - [{a.get('severidad', 'WARNING')}] {a.get('descripcion')}")
                        print(f"        Comando: {a.get('comando')}")
            else:
                print("  [OK] No se detectaron entradas de persistencia ni tareas sospechosas.")
        return 0 if not res["has_alerts"] else 1

    elif args.cmd == "integrity":
        from . import binary_integrity
        res = binary_integrity.audit_binary_integrity()
        if getattr(args, "json", False):
            import json as _j
            print(_j.dumps(res, indent=2, ensure_ascii=False))
        else:
            print(f"=== INTEGRIDAD DE BINARIOS DE NAVEGADOR ({res['total_audited']} binarios encontrados) ===")
            for r in res["results"]:
                v = r["verification"]
                status_mark = "ALERTA" if r["is_tampered_risk"] else "OK"
                print(f"  [{status_mark}] {r['browser']}: {r['path']}")
                if "subject" in v and v["subject"]:
                    print(f"      Firma: {v.get('status')} | Emisor: {v['subject']}")
                elif "has_suid" in v:
                    print(f"      Estado: {v.get('status')} | SUID: {'SÍ' if v['has_suid'] else 'NO'} | Ruta del sistema: {'SÍ' if v['is_system_path'] else 'NO'}")
            if res["has_tampered_risk"]:
                print("[!] ADVERTENCIA: Hay binario(s) con anomalías de integridad o firmas.")
            else:
                print("[OK] Todos los ejecutables auditados tienen integridad y firmas válidas.")
        return 0 if not res["has_tampered_risk"] else 1

    elif args.cmd in ("network", "hosts"):
        from . import network_audit
        res = network_audit.run_network_audit()
        if getattr(args, "json", False):
            import json as _j
            print(_j.dumps(res, indent=2, ensure_ascii=False))
        else:
            print(f"=== AUDITORÍA DE RED LOCAL Y ARCHIVO HOSTS ({res['total_hosts_entries']} reglas en {res['hosts_path']}) ===")
            if res["anomalies"]:
                for a in res["anomalies"]:
                    print(f"  [ALERTA - {a.get('severidad')}] {a.get('tipo')}: Línea {a.get('linea')}")
                    print(f"      Detalle: {a.get('detalle')}")
            else:
                print("  [OK] No se detectaron redirecciones maliciosas ni bloqueo de antivirus en el archivo hosts.")
            if "dns_info" in res and res["dns_info"].get("nameservers"):
                print(f"  Servidores DNS detectados: {', '.join(res['dns_info']['nameservers'])}")
        return 0 if not res.get("has_critical", False) else 1

    elif args.cmd == "canary-trap":
        from .canary import generate_ip_trap_canary
        res = generate_ip_trap_canary(domain=args.dominio, callback_url=args.callback)
        if args.json:
            print(_json.dumps(res, indent=2, ensure_ascii=False))
        else:
            print("=== SIMULACIÓN SEGURA CANARY (SIN CAPTURA DE IP) ===")
            print(f"  Dominio de referencia: {res['dominio_referencia']}")
            print(f"  Cookie creada: no | Solicitudes realizadas: 0 | IP capturada: no")
            print(f"  {res['limite']}")
            print(f"  {res['siguiente_paso']}")
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
    elif args.cmd in ("drill", "simulacro"):
        from . import simulator
        out_html = getattr(args, "html", None)
        res = simulator.run_incident_drill(interactive=not getattr(args, "json", False), output_html=out_html)
        if getattr(args, "json", False):
            import json as _j
            print(_j.dumps(res, indent=2, ensure_ascii=False))
        return 0
    elif args.cmd in ("dossier", "report", "informe"):
        from . import incident_report, engine
        res_analysis = engine.run_analysis(update_state=False)
        formato = getattr(args, "formato", "html")
        salida = getattr(args, "salida", None)
        path = incident_report.generate_incident_dossier(res_analysis, output_path=salida, formato=formato)
        print(f"Informe ejecutivo forense ({formato.upper()}) generado con exito:")
        print(f"  -> {path}")
        return 0
    elif args.cmd in ("clipboard", "clipper"):
        from . import clipboard_audit
        if getattr(args, "limpiar", False) or getattr(args, "clear", False):
            ok = clipboard_audit.clear_system_clipboard()
            if ok:
                print("[OK] Portapapeles purgado correctamente. Ningun secreto residual en memoria.")
            else:
                print("[AVISO] No se pudo purgar el portapapeles o no hay soporte en este entorno.")
            return 0 if ok else 1
        res = clipboard_audit.audit_clipboard()
        if getattr(args, "json", False):
            import json as _j
            print(_j.dumps(res, indent=2, ensure_ascii=False))
        else:
            print("=== AUDITORIA DE PORTAPAPELES Y CLIPPER MALWARE (MITRE T1115) ===")
            if not res["accesible"]:
                print("  [INFO] Portapapeles vacio o no accesible directamente en este entorno.")
            elif res["has_alerts"]:
                print(f"  Se detectaron {res.get('total_alertas', 0)} alertas de seguridad en el portapapeles:")
                for a in res["alertas"]:
                    print(f"     - [{a.get('severidad')}] {a.get('tipo')}: {a.get('descripcion')}")
                    print(f"       Accion recomendada: {a.get('recomendacion')}")
            else:
                print("  [OK] Portapapeles limpio: no se encontraron tokens activos ni direcciones vulnerables a clipper.")
            print(f"  Recomendacion: {res.get('recomendacion')}")
        return 0 if not res.get("has_critical", False) else 1
    return 0



if __name__ == "__main__":
    sys.exit(main() or 0)
