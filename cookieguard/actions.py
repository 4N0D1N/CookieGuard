"""Acciones por servicio, borrado local con copia de seguridad, rotacion guiada, modo incidente y hardening."""
from __future__ import annotations

import hashlib
import json
import platform
import shutil
import sqlite3
import urllib.parse
import webbrowser
import zipfile
from datetime import datetime
from pathlib import Path

from . import classifier, reports
from .browsers import Profile
from .common import IS_WIN, VERSION, data_dir, is_admin, load_state, log, ps, run, save_state

KIND_TEXT = {"sesiones": "cerrar todas las sesiones dispositivos", "password": "cambiar contrasena",
             "seguridad": "seguridad cuenta 2FA passkeys", "historial": "actividad reciente inicios de sesion",
             "2fa": "verificacion en dos pasos"}
KIND_LABEL = {"sesiones": "Cerrar todas las sesiones/dispositivos", "password": "Cambiar contrasena",
              "seguridad": "Seguridad / 2FA / passkeys", "historial": "Historial de inicios de sesion"}


# ------------------------------------------------------------------ URLs por servicio
def service_entry(service_id: str):
    cat, _ = classifier.catalog()
    for s in cat["servicios"]:
        if s["id"] == service_id:
            return s
    return None


def url_for(group: dict, kind: str):
    """Devuelve (url, nota, es_busqueda). Si el dominio no esta en el catalogo, se abre una busqueda guiada."""
    svc = service_entry(group["id"]) if group.get("en_catalogo") else None
    if svc and svc["urls"].get(kind):
        return svc["urls"][kind], svc.get("nota", ""), False
    dom = (group["dominios"][0] if group.get("dominios") else group["id"]).lstrip(".")
    q = urllib.parse.quote(f"{dom} {KIND_TEXT.get(kind, kind)}")
    return (f"https://duckduckgo.com/?q={q}",
            "Dominio sin entrada en el catalogo: se abre una busqueda guiada. Verifica que la pagina es la oficial.", True)


def open_url(url: str) -> bool:
    if not url.lower().startswith(("https://", "http://")):
        return False
    return webbrowser.open(url)


# ------------------------------------------------------------------ navegadores abiertos
def running_browsers() -> list[str]:
    from .detections import _is_browser_proc, list_processes, norm_name
    return sorted({norm_name(p["name"]) for p in list_processes() if _is_browser_proc(p["name"])})


def close_browsers() -> None:
    """Cierra los navegadores (solo se llama tras confirmacion explicita del usuario)."""
    for n in running_browsers():
        if IS_WIN:
            run(["taskkill", "/IM", n + ".exe", "/F"], 20)
        else:
            run(["pkill", "-x", n], 10)


# ------------------------------------------------------------------ borrado local con copia y restauracion
def _table_cols(p: Profile):
    return ("moz_cookies", "host") if p.family == "firefox" else ("cookies", "host_key")


def _where(col: str, domains):
    if domains is None:
        return "1=1", []
    clauses, params = [], []
    for d in domains:
        d = d.lstrip(".")
        esc = d.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        clauses.append(f"({col} = ? OR {col} = ? OR {col} LIKE ? ESCAPE '\\')")
        params += [d, "." + d, "%." + esc]
    return " OR ".join(clauses), params


def delete_local(profiles: list[Profile], domains: list[str] | None, force_closed_check: bool = True) -> dict:
    """Borra cookies de los dominios dados (o todas si domains=None). Necesita el navegador CERRADO.
    Antes hace copia de seguridad de cada base afectada. No lee valores."""
    if force_closed_check:
        run_b = running_browsers()
        if run_b:
            return {"ok": False, "motivo": "Cierra primero estos navegadores: " + ", ".join(run_b), "borradas": 0}
    bid = datetime.now().strftime("%Y%m%d_%H%M%S")
    bdir = data_dir() / "backups" / bid
    manifest, total = [], 0
    for i, p in enumerate(profiles):
        table, col = _table_cols(p)
        where, params = _where(col, domains)
        try:
            con = sqlite3.connect(str(p.cookies_db), timeout=5)
            n = con.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}", params).fetchone()[0]
            con.close()
        except sqlite3.Error as e:
            log(f"borrado: {p.browser}/{p.profile} no accesible: {e}")
            continue
        if n == 0:
            continue
        dest = bdir / f"{i}_{p.browser}_{p.profile}".replace(" ", "_").replace("/", "_")
        dest.mkdir(parents=True, exist_ok=True)
        for suf in ("", "-wal", "-journal"):
            s = Path(str(p.cookies_db) + suf)
            if s.exists():
                shutil.copy2(s, dest / (p.cookies_db.name + suf))
        manifest.append({"original": str(p.cookies_db), "copia": str(dest / p.cookies_db.name),
                         "navegador": p.browser, "perfil": p.profile, "filas": n})
        con = sqlite3.connect(str(p.cookies_db), timeout=5)
        con.execute(f"DELETE FROM {table} WHERE {where}", params)
        con.commit()
        con.close()
        total += n
    if manifest:
        (bdir / "manifest.json").write_text(json.dumps(
            {"fecha": datetime.now().isoformat(timespec="seconds"), "dominios": domains, "entradas": manifest},
            indent=1), encoding="utf-8")
    log(f"borrado local: {total} cookies, copia {bid if manifest else '-'}")
    return {"ok": True, "borradas": total, "copia": bid if manifest else None,
            "motivo": "" if manifest else "No habia cookies que borrar"}


def list_backups() -> list[dict]:
    out = []
    for d in sorted((data_dir() / "backups").glob("*/manifest.json"), reverse=True):
        try:
            m = json.loads(d.read_text(encoding="utf-8"))
            out.append({"id": d.parent.name, "fecha": m["fecha"], "dominios": m["dominios"],
                        "filas": sum(e["filas"] for e in m["entradas"])})
        except (OSError, ValueError, KeyError):
            continue
    return out


def restore_backup(bid: str, check_browsers: bool = True) -> dict:
    run_b = running_browsers() if check_browsers else []
    if run_b:
        return {"ok": False, "motivo": "Cierra primero estos navegadores: " + ", ".join(run_b)}
    bdir = data_dir() / "backups" / bid
    m = json.loads((bdir / "manifest.json").read_text(encoding="utf-8"))
    pre = data_dir() / "backups" / f"prerestore_{datetime.now():%Y%m%d_%H%M%S}"
    pre.mkdir(parents=True, exist_ok=True)
    n = 0
    for e in m["entradas"]:
        orig, copia = Path(e["original"]), Path(e["copia"])
        if orig.exists():
            shutil.copy2(orig, pre / f"{n}_{orig.name}")
        for suf in ("-wal", "-journal"):
            Path(str(orig) + suf).unlink(missing_ok=True)
        shutil.copy2(copia, orig)
        for suf in ("-wal", "-journal"):
            s = Path(str(copia) + suf)
            if s.exists():
                shutil.copy2(s, Path(str(orig) + suf))
        n += 1
    return {"ok": True, "restauradas": n}


# ------------------------------------------------------------------ rotacion guiada
STEPS = [("sesiones", "1. Cerrar TODAS las sesiones/dispositivos"), ("password", "2. Cambiar la contrasena"),
         ("seguridad", "3. Revisar 2FA, passkeys y metodos de recuperacion"),
         ("historial", "4. Revisar actividad/inicios de sesion recientes")]
REMINDER = ("Cambiar la contrasena NO siempre invalida una cookie ya robada: cierra tambien TODAS las sesiones. "
            "Hazlo desde un dispositivo limpio.")


def rotation_plan(grupos: list[dict]) -> list[dict]:
    """Checklist ordenada por criticidad (correo -> gestor -> SSO -> banca/cripto -> trabajo -> redes -> resto)."""
    st = load_state().get("rotacion", {})
    plan = []
    for g in sorted(grupos, key=lambda g: (classifier.categoria_orden(g["categoria"]), not g["critico"], g["nombre"].lower())):
        r = st.get(g["id"], {})
        plan.append({"id": g["id"], "nombre": g["nombre"], "categoria": g["categoria"], "critico": g["critico"],
                     "pasos": {k: bool(r.get("pasos", {}).get(k)) for k, _ in STEPS},
                     "rotado": r.get("rotado"), "revisado": r.get("revisado")})
    return plan


def mark_step(service_id: str, step: str, done: bool = True) -> None:
    st = load_state()
    r = st.setdefault("rotacion", {}).setdefault(service_id, {"pasos": {}})
    r["pasos"][step] = done
    now = datetime.now().isoformat(timespec="seconds")
    r["revisado"] = now
    if all(r["pasos"].get(k) for k in ("sesiones", "password")):
        r["rotado"] = r.get("rotado") or now
    save_state(st)


def mark_reviewed(service_id: str) -> None:
    st = load_state()
    r = st.setdefault("rotacion", {}).setdefault(service_id, {"pasos": {}})
    r["revisado"] = datetime.now().isoformat(timespec="seconds")
    save_state(st)


def rotation_progress(plan: list[dict]) -> tuple[int, int]:
    total = sum(len(p["pasos"]) for p in plan)
    done = sum(sum(1 for v in p["pasos"].values() if v) for p in plan)
    return done, total


# ------------------------------------------------------------------ modo incidente
def incident_zip(res: dict) -> Path:
    """ZIP forense: indicadores, hashes y hallazgos. Sin valores de cookies."""
    out = data_dir() / "informes" / f"incidente_{datetime.now():%Y%m%d_%H%M%S}.zip"
    hashes = []
    for i in res["indicadores"]:
        for h in i["hallazgos"]:
            cand = h.split(" (")[0].strip()
            p = Path(cand)
            try:
                if p.is_file() and p.stat().st_size < 200_000_000:
                    hashes.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p}")
            except OSError:
                pass
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("resultado.json", reports.to_json(res))
        z.writestr("informe.html", reports.build_html(res))
        z.writestr("hashes_sha256.txt", "\n".join(hashes) or "(sin ficheros que hashear)")
        z.writestr("eventos_relevantes.txt", "\n".join(
            f"[{i['id']}] {h}" for i in res["indicadores"] for h in i["hallazgos"]) or "(sin hallazgos)")
        z.writestr("sistema.txt", f"CookieGuard {VERSION}\n{platform.platform()}\nGenerado: {res['generado']}\n"
                                  "Este paquete NO contiene valores de cookies ni contrasenas.\n")
    return out


# ------------------------------------------------------------------ hardening
ASR = {"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": "Bloquear robo de credenciales de LSASS",
       "5beb7efe-fd9a-4556-801d-275e5ffc04cc": "Bloquear scripts ofuscados",
       "d3e037e1-3eb8-44c8-a917-57927947596d": "Bloquear JS/VBS que lanzan ejecutables descargados"}


def _read_prefs(p: Profile) -> dict:
    try:
        return json.loads((p.path / "Preferences").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def hardening_checks(profiles: list[Profile]) -> list[dict]:
    res = []

    def add(id_, titulo, estado, detalle, recomendacion, aplicable=False):
        res.append({"id": id_, "titulo": titulo, "estado": estado, "detalle": detalle,
                    "recomendacion": recomendacion, "aplicable": aplicable})

    seen = set()
    for p in profiles:
        if p.family == "chromium" and str(p.root) not in seen:
            seen.add(str(p.root))
            try:
                ver = (p.root / "Last Version").read_text().strip()
            except OSError:
                ver = "desconocida"
            major = int(ver.split(".")[0]) if ver[:1].isdigit() else 0
            if p.browser == "Chrome" and IS_WIN:
                add(f"ver_{p.browser}", f"Chrome {ver}: soporte de DBSC",
                    "ok" if major >= 146 else "mejorable",
                    "DBSC (cookies ligadas al dispositivo) esta disponible desde Chrome 146 en Windows" if major >= 146
                    else "Version anterior a Chrome 146: sin DBSC", "Actualiza Chrome (chrome://settings/help)")
            else:
                add(f"ver_{p.browser}", f"{p.browser} {ver}", "info", "DBSC depende del navegador y del sitio",
                    "Mantén el navegador actualizado")
    n_prof = {}
    for p in profiles:
        n_prof[p.browser] = n_prof.get(p.browser, 0) + 1
    for p in profiles:
        if p.family != "chromium":
            continue
        pr = _read_prefs(p)
        if pr.get("credentials_enable_service", True) or pr.get("profile", {}).get("password_manager_enabled", False):
            add(f"pwd_{p.browser}_{p.profile}", f"{p.browser}/{p.profile}: guarda contrasenas en el navegador",
                "mejorable", "El gestor del navegador guarda contrasenas en 'Login Data'",
                "Usa un gestor dedicado (Bitwarden, 1Password...) y desactiva 'Ofrecer guardar contrasenas'")
        if pr.get("session", {}).get("restore_on_startup") == 1:
            add(f"restore_{p.browser}_{p.profile}", f"{p.browser}/{p.profile}: 'continuar donde lo dejaste'",
                "mejorable", "Mantiene sesiones y pestanas entre reinicios",
                "En perfiles criticos, ajusta 'Al abrir el navegador' a 'Abrir la pagina Nueva pestana'")
    for b, n in n_prof.items():
        if n == 1:
            add(f"perfiles_{b}", f"{b}: un solo perfil", "mejorable",
                "Todo (banca, trabajo, ocio) comparte las mismas cookies",
                "Crea perfiles separados: uno solo para banca/cripto/correo principal")
    add("clear_exit", "Borrar cookies al cerrar para sitios sensibles", "recomendacion",
        "Reduce el tiempo que una cookie robada sigue siendo util",
        "Chrome/Edge: Configuracion > Privacidad > Cookies > 'Borrar al cerrar' para bancos y cripto")
    add("passkeys", "Passkeys / FIDO2", "recomendacion", "Las passkeys no se pueden reutilizar tras un robo de cookie "
        "de contrasena, y las llaves FIDO2 impiden el phishing", "Activa passkeys o llaves FIDO2 en correo, banca y cripto")
    if IS_WIN:
        code, out, _ = ps("$o=@{};try{$s=Get-MpComputerStatus;$o.rtp=$s.RealTimeProtectionEnabled;$o.tp=$s.IsTamperProtected}catch{};"
                          "try{$p=Get-MpPreference;$o.pua=$p.PUAProtection;$o.ids=@($p.AttackSurfaceReductionRules_Ids);"
                          "$o.act=@($p.AttackSurfaceReductionRules_Actions)}catch{};$o|ConvertTo-Json -Compress", 60)
        try:
            d = json.loads(out)
        except Exception:  # noqa: BLE001
            d = {}
        add("def_rtp", "Defender: proteccion en tiempo real", "ok" if d.get("rtp") else "mejorable", "", "Activala")
        add("def_tamper", "Defender: proteccion contra alteraciones", "ok" if d.get("tp") else "mejorable",
            "", "Actívala en Seguridad de Windows > Proteccion antivirus > Administrar configuracion")
        ids = [str(i).lower() for i in (d.get("ids") or [])]
        acts = d.get("act") or []
        for rid, desc in ASR.items():
            on = rid in ids and (acts[ids.index(rid)] in (1, "1") if len(acts) > ids.index(rid) else False) if rid in ids else False
            add(f"asr_{rid}", f"Regla ASR: {desc}", "ok" if on else "mejorable", rid, "Aplicar (requiere administrador)", True)
        add("def_pua", "Defender: proteccion contra apps potencialmente no deseadas", "ok" if d.get("pua") == 1 else "mejorable",
            "", "Aplicar (requiere administrador)", True)
        try:
            code_lsa, out_lsa, _ = ps("(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL", 15)
            lsa_val = out_lsa.strip()
            add("lsa_ppl", "LSA Protection (RunAsPPL contra volcado de credenciales en memoria)",
                "ok" if lsa_val in ("1", "2") else "mejorable",
                f"valor actual {lsa_val or 'no configurado'}",
                "Seguridad de Windows > Aislamiento del nucleo > Proteccion de autoridad de seguridad local")
        except Exception:
            pass
    else:
        try:
            sc = Path("/proc/sys/kernel/yama/ptrace_scope").read_text().strip()
            add("ptrace", "ptrace_scope (lectura de memoria entre procesos)", "ok" if sc != "0" else "mejorable",
                f"valor actual {sc}", "sudo sysctl kernel.yama.ptrace_scope=1")
        except OSError:
            pass
        try:
            preg = Path("/proc/sys/fs/protected_regular").read_text().strip()
            add("protected_regular", "fs.protected_regular (proteccion contra escritura en /tmp)",
                "ok" if preg in ("1", "2") else "mejorable",
                f"valor actual {preg}", "sudo sysctl fs.protected_regular=2")
        except OSError:
            pass
        try:
            dmp = Path("/proc/sys/fs/suid_dumpable").read_text().strip()
            add("suid_dumpable", "fs.suid_dumpable (evitar volcados de memoria privilegiados)",
                "ok" if dmp == "0" else "mejorable",
                f"valor actual {dmp}", "sudo sysctl fs.suid_dumpable=0")
        except OSError:
            pass
    return res


def apply_hardening(check_id: str, undo: bool = False):
    """Aplica (o deshace) un ajuste de Defender. Requiere administrador. Devuelve (ok, mensaje)."""
    if not IS_WIN:
        return False, "En Linux aplica el comando indicado con sudo."
    if not is_admin():
        return False, "Ejecuta CookieGuard como administrador para aplicar este ajuste."
    if check_id.startswith("asr_"):
        rid = check_id[4:]
        if rid not in ASR:
            return False, "Regla desconocida"
        cmd = (f"Remove-MpPreference -AttackSurfaceReductionRules_Ids {rid}" if undo else
               f"Add-MpPreference -AttackSurfaceReductionRules_Ids {rid} -AttackSurfaceReductionRules_Actions Enabled")
    elif check_id == "def_pua":
        cmd = f"Set-MpPreference -PUAProtection {'Disabled' if undo else 'Enabled'}"
    else:
        return False, "Este ajuste no se puede aplicar automaticamente"
    code, out, err = ps(cmd, 60)
    return code == 0, (out + err).strip() or "Hecho"


# ------------------------------------------------------------------ Killswitch de emergencia
def killswitch_status() -> dict:
    from . import killswitch
    return killswitch.status()


def enable_killswitch(dry_run: bool = False) -> tuple[bool, str]:
    from . import killswitch
    return killswitch.enable(dry_run=dry_run)


def disable_killswitch(dry_run: bool = False) -> tuple[bool, str]:
    from . import killswitch
    return killswitch.disable(dry_run=dry_run)
