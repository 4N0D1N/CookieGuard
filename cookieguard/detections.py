"""Los 12 grupos de indicadores de posible robo de cookies (Windows y Linux).

Cada indicador devuelve un dict:
  id, nombre, mitre, estado (ok | alerta | sin_datos | no_aplica | error), puntos, resumen,
  explicacion (lenguaje sencillo), hallazgos (lista de textos), falta (que permiso/herramienta falta).
Ningun indicador lee valores de cookies ni contrasenas.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path

from . import classifier
from .browsers import Profile, sensitive_files
from .common import IS_LINUX, IS_WIN, data_dir, is_admin, load_catalog, log, ps, run
from .sqlite_meta import table_names

BROWSER_NAMES = {"chrome", "msedge", "brave", "opera", "opera_gx", "vivaldi", "chromium", "chromium-browser",
                 "yandex", "browser", "firefox", "librewolf", "waterfox", "google-chrome", "microsoft-edge",
                 "chrome_proxy", "arc", "firefox-bin"}
SENSITIVE_NAMES = {"cookies", "login data", "web data", "local state", "cookies.sqlite", "logins.json", "key4.db",
                   "login data for account", "cookies-journal", "cookies.sqlite-wal"}
SCRIPT_PARENTS = {"powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "python", "python3", "pythonw",
                  "node", "bash", "sh", "rundll32", "regsvr32", "wmic", "curl", "perl", "ruby"}
NOT_FLAG_HOSTS = {"bash", "sh", "zsh", "dash", "fish", "cmd", "powershell", "pwsh", "grep", "rg", "git", "conhost",
                  "wsl", "tmux", "less", "cat", "sed", "awk"}
DANGEROUS_FLAGS = [
    (r"--remote-debugging-(port|pipe)", "depuracion remota activada", 35),
    (r"--remote-allow-origins", "permite origenes de depuracion remota", 30),
    (r"--headless", "navegador sin ventana (headless)", 20),
    (r"--load-extension", "carga una extension desde disco", 25),
    (r"--disable-extensions-except", "carga solo una extension concreta", 15),
    (r"--disable-web-security", "seguridad web desactivada", 20),
    (r"--no-sandbox", "sandbox desactivado", 8),
]
STEALER_FAMILIES = re.compile(r"(lumma|redline|vidar|stealc|raccoon|azorult|agenttesla|formbook|snake|stealer|"
                              r"infostealer|pws[:/]|trojanspy|spyware|risepro|meduza|rhadamanthys|amadey|"
                              r"mars|poullight|aurora|atomic|titan|redcap|cryptbot|zloader|icedid|qakbot)", re.I)


# ------------------------------------------------------------------ contexto y utilidades
class Ctx:
    """Datos compartidos por los indicadores (procesos, perfiles, estado...)."""

    def __init__(self, cfg, profiles: list[Profile], sessions: list[dict], state: dict,
                 scan_dirs: list[Path] | None = None):
        self.cfg, self.profiles, self.sessions, self.state = cfg, profiles, sessions, state
        self.scan_dirs = scan_dirs
        self._procs = None
        self._walk = None
        self.extensions: list = []
        self.new_state: dict = {}
        self.destinos = load_catalog("destinos-exfil.json")
        self.whitelist = {w.lower() for w in cfg.get("whitelist_procesos", [])} | set(BROWSER_NAMES)

    @property
    def procs(self):
        if self._procs is None:
            self._procs = list_processes()
        return self._procs

    def pts(self, ind_id: str, frac: float) -> int:
        mx = self.cfg.get("puntos", {}).get(ind_id, 10)
        return int(round(mx * max(0.0, min(1.0, frac))))


def norm_name(name: str) -> str:
    n = (name or "").lower()
    n = os.path.basename(n.replace("\\", "/"))
    return n[:-4] if n.endswith(".exe") else n


def mk(ind_id, nombre, mitre, explicacion):
    return {"id": ind_id, "nombre": nombre, "mitre": mitre, "estado": "ok", "puntos": 0, "resumen": "",
            "explicacion": explicacion, "hallazgos": [], "falta": ""}


def list_processes() -> list[dict]:
    procs = []
    if IS_WIN:
        code, out, _ = ps("Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine,"
                          "ExecutablePath | ConvertTo-Json -Compress", 90)
        try:
            data = json.loads(out) if out.strip() else []
            if isinstance(data, dict):
                data = [data]
            for d in data:
                procs.append({"pid": d.get("ProcessId"), "ppid": d.get("ParentProcessId"),
                              "name": d.get("Name") or "", "cmd": d.get("CommandLine") or "",
                              "exe": d.get("ExecutablePath") or ""})
        except Exception as e:  # noqa: BLE001
            log(f"procesos: {e}")
    else:
        for d in Path("/proc").iterdir():
            if not d.name.isdigit():
                continue
            try:
                cmd = (d / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace").strip()
                comm = (d / "comm").read_text().strip()
                stat = (d / "stat").read_text()
                ppid = int(stat.rsplit(")", 1)[1].split()[1])
                try:
                    exe = os.readlink(d / "exe")
                except OSError:
                    exe = ""
                procs.append({"pid": int(d.name), "ppid": ppid, "name": comm, "cmd": cmd, "exe": exe})
            except (OSError, ValueError, IndexError):
                continue
    return procs


def wevt(log_name: str, query: str, count: int = 300):
    """Consulta del registro de eventos de Windows. Devuelve (estado, [eventos])."""
    if not IS_WIN:
        return "no_aplica", []
    code, out, err = run(["wevtutil", "qe", log_name, f"/q:{query}", f"/c:{count}", "/rd:true", "/f:xml"], 60)
    if code == 5:
        return "sin_permiso", []
    if code != 0:
        return "sin_log", []
    out = re.sub(r' xmlns="[^"]+"', "", out)
    import xml.etree.ElementTree as ET
    events = []
    try:
        root = ET.fromstring("<Events>" + out + "</Events>")
        for ev in root.findall("Event"):
            d = {"EventID": (ev.findtext("System/EventID") or ""),
                 "Time": (ev.find("System/TimeCreated").get("SystemTime") if ev.find("System/TimeCreated") is not None else "")}
            for x in ev.findall("EventData/Data"):
                d[x.get("Name") or ""] = x.text or ""
            events.append(d)
    except ET.ParseError:
        return "sin_log", []
    return "ok", events


def _sysmon(ids, count=400):
    q = "*[System[(" + " or ".join(f"EventID={i}" for i in ids) + ")]]"
    return wevt("Microsoft-Windows-Sysmon/Operational", q, count)


def _is_browser_proc(name: str) -> bool:
    n = norm_name(name)
    return n in BROWSER_NAMES or any(n.startswith(b) for b in ("chrome", "msedge", "firefox", "brave"))


# ------------------------------------------------------------------ I01 acceso a ficheros sensibles
def i01(ctx: Ctx):
    r = mk("I01_acceso_ficheros", "Procesos ajenos leyendo ficheros del navegador", "T1555.003 / T1539",
           "Un programa que NO es el navegador ha abierto las bases de cookies o contrasenas. Es la firma "
           "tipica de un infostealer.")
    hits = []
    if IS_WIN:
        st, evs = wevt("Security", "*[System[(EventID=4663 or EventID=4656)]]", 600)
        if st != "ok":
            r["estado"] = "sin_datos"
            r["falta"] = ("Permisos de administrador para leer el registro de Seguridad" if st == "sin_permiso"
                          else "Auditoria del sistema de ficheros y SACL (se activan en la instalacion)")
            r["resumen"] = "Sin datos: " + r["falta"]
            return r
        if not evs:
            r["estado"] = "sin_datos"
            r["falta"] = "No hay eventos 4663: la auditoria/SACL aun no esta activada (ejecuta Instalar)"
            r["resumen"] = r["falta"]
            return r
        for e in evs:
            obj = (e.get("ObjectName") or "")
            if os.path.basename(obj.replace("\\", "/")).lower() not in SENSITIVE_NAMES:
                continue
            proc = norm_name(e.get("ProcessName", ""))
            if proc in ctx.whitelist or not proc:
                continue
            hits.append(f"{e.get('ProcessName')} abrio {os.path.basename(obj)} ({e.get('Time', '')[:19]})")
    else:
        files = {str(f) for f in sensitive_files(ctx.profiles)}
        for p in Path("/proc").iterdir():
            if not p.name.isdigit():
                continue
            try:
                comm = (p / "comm").read_text().strip()
                if norm_name(comm) in ctx.whitelist:
                    continue
                for fd in (p / "fd").iterdir():
                    try:
                        if os.readlink(fd) in files:
                            hits.append(f"{comm} (PID {p.name}) tiene abierto {os.path.basename(os.readlink(fd))}")
                    except OSError:
                        pass
            except OSError:
                continue
        if is_admin():
            code, out, _ = run(["ausearch", "-k", "cookieguard", "-i", "--just-one"], 20)
            if code == 0 and out.strip():
                for line in out.splitlines():
                    if "exe=" in line and "comm=" in line:
                        m = re.search(r'comm="?([^"\s]+)', line)
                        if m and norm_name(m.group(1)) not in ctx.whitelist:
                            hits.append(f"auditd: {m.group(1)} accedio a un fichero vigilado")
    hits = sorted(set(hits))
    if hits:
        r["estado"], r["hallazgos"] = "alerta", hits[:30]
        r["puntos"] = ctx.pts(r["id"], 1.0)
        r["resumen"] = f"{len(hits)} acceso(s) de programas no autorizados"
    else:
        r["resumen"] = "Ningun programa ajeno ha tocado los ficheros sensibles"
        if not IS_WIN:
            r["falta"] = ("Solo se ve el instante actual (instala auditd para historico)" if not is_admin() else "")
    return r


# ------------------------------------------------------------------ I02 flags peligrosos
def i02(ctx: Ctx):
    r = mk("I02_flags_navegador", "Navegador lanzado de forma peligrosa", "T1539 / T1185",
           "Los ladrones de sesion arrancan el navegador con depuracion remota o sin ventana para extraer las "
           "cookies ya descifradas.")
    byid = {p["pid"]: p for p in ctx.procs}
    hits, worst = [], 0
    for p in ctx.procs:
        cmd = p["cmd"] or ""
        if norm_name(p["name"]) in NOT_FLAG_HOSTS:     # shells/grep que solo CITAN el flag en su texto
            continue
        is_b = _is_browser_proc(p["name"])
        for rx, why, pts in DANGEROUS_FLAGS:
            if re.search(r"(?:^|\s)" + rx, cmd, re.I):
                if not is_b and "remote-debugging" not in rx:
                    continue
                hits.append(f"{p['name']} (PID {p['pid']}): {why}")
                worst = max(worst, pts)
        if is_b:
            m = re.search(r'--user-data-dir[= ]"?([^"\s]+)', cmd)
            if m and re.search(r"(temp|tmp|downloads|public|programdata)", m.group(1), re.I):
                hits.append(f"{p['name']} (PID {p['pid']}): perfil en carpeta sospechosa {m.group(1)}")
                worst = max(worst, 30)
            par = byid.get(p["ppid"])
            if par and norm_name(par["name"]) in SCRIPT_PARENTS and "--type=" not in cmd:
                hits.append(f"{p['name']} lanzado por {par['name']} (proceso padre inusual)")
                worst = max(worst, 15)
    hist_note = ""
    if IS_WIN:
        st, evs = _sysmon([1], 300)
        src = "Sysmon"
        if st != "ok":
            st, evs = wevt("Security", "*[System[(EventID=4688)]]", 300)
            src = "evento 4688"
        if st == "ok":
            for e in evs:
                cmd = e.get("CommandLine") or e.get("ProcessCommandLine") or ""
                if re.search(r"--remote-debugging-(port|pipe)|--remote-allow-origins", cmd, re.I):
                    hits.append(f"historico ({src}): {cmd[:140]}")
                    worst = max(worst, 30)
        else:
            hist_note = "Historico no disponible (sin Sysmon ni auditoria 4688)"
    hits = sorted(set(hits))
    r["falta"] = hist_note
    if hits:
        r["estado"], r["hallazgos"] = "alerta", hits[:30]
        r["puntos"] = ctx.pts(r["id"], max(worst, 10) / 35)
        r["resumen"] = f"{len(hits)} lanzamiento(s) sospechoso(s)"
    else:
        r["resumen"] = "Ningun navegador con flags peligrosos ahora mismo"
    return r


# ------------------------------------------------------------------ I03 acceso a memoria
def i03(ctx: Ctx):
    r = mk("I03_memoria_navegador", "Acceso a la memoria del navegador", "T1055 / T1003",
           "Algunos stealers leen la memoria del navegador para sacar claves o cookies. Solo se ve con Sysmon.")
    if not IS_WIN:
        r["estado"], r["resumen"] = "no_aplica", "En Linux se vigila con auditd/ptrace (ver Tecnico.md)"
        try:
            scope = Path("/proc/sys/kernel/yama/ptrace_scope").read_text().strip()
            r["resumen"] = f"ptrace_scope={scope} (1 o mas limita la lectura de memoria entre procesos)"
            if scope == "0":
                r["estado"], r["puntos"] = "alerta", ctx.pts(r["id"], 0.3)
                r["hallazgos"] = ["ptrace_scope=0: cualquier proceso del usuario puede leer la memoria de otro. "
                                  "Recomendado: sudo sysctl kernel.yama.ptrace_scope=1"]
        except OSError:
            pass
        return r
    st, evs = _sysmon([10], 400)
    if st != "ok":
        r["estado"], r["falta"] = "sin_datos", "Sysmon instalado con reglas/sysmon-cookieguard.xml"
        r["resumen"] = "Sin datos: " + r["falta"]
        return r
    hits = []
    for e in evs:
        tgt, src = norm_name(e.get("TargetImage", "")), norm_name(e.get("SourceImage", ""))
        acc = e.get("GrantedAccess", "")
        if (_is_browser_proc(tgt) or "elevation" in tgt) and src not in ctx.whitelist:
            hits.append(f"{e.get('SourceImage')} -> {e.get('TargetImage')} (acceso {acc})")
    hits = sorted(set(hits))
    if hits:
        r["estado"], r["hallazgos"] = "alerta", hits[:30]
        r["puntos"] = ctx.pts(r["id"], 1.0)
        r["resumen"] = f"{len(hits)} acceso(s) a memoria de navegador"
    else:
        r["resumen"] = "Sin accesos sospechosos a la memoria del navegador"
    return r


def _looks_like_app_profile(fp: Path) -> bool:
    """True si la BD vive dentro del perfil de una app Chromium/Electron/WebView2 legitima
    (hay 'Local State' o 'Preferences' en las carpetas superiores). Un stealer copia a Temp sueltas."""
    low = str(fp).lower()
    if any(k in low for k in ("ebwebview", "\\electron", "cefsharp", "/electron")):
        return True
    p = fp.parent
    for _ in range(4):
        if (p / "Local State").exists() or (p / "Preferences").exists():
            return True
        if p.parent == p:
            break
        p = p.parent
    return False


# ------------------------------------------------------------------ recorrido de carpetas (I04/I06)
def _walk_dirs(ctx: Ctx) -> dict:
    """Recorre carpetas candidatas UNA vez. Devuelve {'bd': [...], 'txt': [...], 'zip': [...], 'abe': [...]}"""
    if ctx._walk is not None:
        return ctx._walk
    cat = ctx.destinos
    stealer_files = {n.lower() for n in cat["archivos_stealer"]}
    abe_tools = [t.lower() for t in cat["herramientas_abe"]]
    home = Path.home()
    if ctx.scan_dirs is not None:
        dirs = list(ctx.scan_dirs)
    elif IS_WIN:
        dirs = [Path(tempfile.gettempdir()), Path(os.environ.get("APPDATA", home / "AppData/Roaming")),
                Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")), Path("C:/Users/Public"), home / "Downloads",
                home / "Desktop"]
    else:
        dirs = [Path("/tmp"), Path("/var/tmp"), Path("/dev/shm"), home / "Downloads", home / "Desktop",
                home / ".cache", home / ".local/share"]
    dirs += [Path(d) for d in ctx.cfg.get("directorios_copias_sospechosas", [])]
    excl = {str(p.root).lower() for p in ctx.profiles} | {str(data_dir()).lower()}
    excl_words = ("user data", "google-chrome", "chromium", "microsoft-edge", "mozilla", "brave", "vivaldi",
                  "cookieguard", "opera", "snap", "flatpak", ".var", "site-packages", "node_modules", "pip", "npm")
    res = {"bd": [], "txt": [], "zip": [], "abe": []}
    t0, nfiles = time.time(), 0
    exts_db = {"", ".db", ".sqlite", ".sqlite3", ".tmp", ".dat", ".bak", ".old", ".copy", ".cookies", ".data"}
    for base in dirs:
        if not base.is_dir():
            continue
        base_depth = len(base.parts)
        for root, subdirs, files in os.walk(base, followlinks=False):
            rl = root.lower()
            if len(Path(root).parts) - base_depth >= 4 or any(rl.startswith(e) for e in excl):
                subdirs[:] = []
                continue
            subdirs[:] = [d for d in subdirs if not any(w in d.lower() for w in excl_words)]
            for fn in files:
                nfiles += 1
                if nfiles > 40000 or time.time() - t0 > 25:
                    ctx._walk = res
                    return res
                low, fp = fn.lower(), Path(root) / fn
                stem, ext = os.path.splitext(low)
                if any(t in low for t in abe_tools):
                    res["abe"].append(str(fp))
                try:
                    size = fp.stat().st_size
                except OSError:
                    continue
                if low in stealer_files:
                    res["txt"].append(f"{fp} (nombre tipico de stealer)")
                elif ext == ".txt" and 50 < size < 5_000_000:
                    try:
                        with open(fp, "rb") as fh:
                            if b"Netscape HTTP Cookie File" in fh.read(100):
                                res["txt"].append(f"{fp} (cookies formato Netscape)")
                    except OSError:
                        pass
                elif ext == ".zip" and size < 30_000_000 and len(res["zip"]) < 50:
                    try:
                        with zipfile.ZipFile(fp) as z:
                            names = [os.path.basename(n).lower() for n in z.namelist()[:500]]
                        hit = [n for n in names if n in stealer_files or "cookies" in n and n.endswith(".txt")]
                        if hit:
                            res["zip"].append(f"{fp} (contiene {', '.join(sorted(set(hit))[:3])})")
                    except (zipfile.BadZipFile, OSError):
                        pass
                if (ext in exts_db or low in SENSITIVE_NAMES) and 4096 <= size <= 200_000_000:
                    try:
                        with open(fp, "rb") as fh:
                            head = fh.read(16)
                    except OSError:
                        continue
                    if head == b"SQLite format 3\x00":
                        if _looks_like_app_profile(fp):
                            res["apps_ignoradas"] = res.get("apps_ignoradas", 0) + 1
                            continue
                        try:
                            tabs = {t.lower() for t in table_names(fp)}
                        except Exception:  # noqa: BLE001
                            continue
                        found = tabs & {"cookies", "moz_cookies", "logins", "autofill", "credit_cards"}
                        if found:
                            res["bd"].append(f"{fp} (SQLite con tablas {', '.join(sorted(found))})")
    ctx._walk = res
    return res


def i04(ctx: Ctx):
    r = mk("I04_abe_elevation", "Abuso del cifrado ligado a la aplicacion (App-Bound)", "T1555.003 / T1559",
           "Chrome protege las cookies con un servicio de elevacion (App-Bound Encryption). Los stealers modernos "
           "lo abusan o intentan saltarselo (ChromeKatz, inyeccion, depuracion remota).")
    if not IS_WIN:
        r["estado"], r["resumen"] = "no_aplica", "App-Bound Encryption es una funcion de Chrome en Windows"
        return r
    hits = []
    code, out, _ = ps("Get-CimInstance Win32_Service | Where-Object {$_.Name -match 'Elevation'} | "
                      "Select-Object Name,PathName,State | ConvertTo-Json -Compress", 40)
    try:
        d = json.loads(out) if out.strip() else []
        d = [d] if isinstance(d, dict) else d
        for s in d:
            path = (s.get("PathName") or "").strip('"').lower()
            if path and not re.search(r"\\(program files|program files \(x86\))\\(google|microsoft|brave|bravesoftware)", path):
                hits.append(f"Servicio de elevacion {s.get('Name')} apunta a ruta no estandar: {s.get('PathName')}")
    except Exception:  # noqa: BLE001
        pass
    for p in ctx.procs:
        if norm_name(p["name"]) == "elevation_service":
            exe = (p["exe"] or "").lower()
            if exe and not re.search(r"\\program files( \(x86\))?\\", exe):
                hits.append(f"elevation_service.exe ejecutandose fuera de Program Files: {p['exe']}")
        cl = (p["cmd"] or "").lower()
        if any(t in cl or t in (p["name"] or "").lower() for t in ctx.destinos["herramientas_abe"]):
            hits.append(f"Proceso con nombre de herramienta de bypass ABE: {p['name']} (PID {p['pid']})")
    for f in _walk_dirs(ctx)["abe"]:
        hits.append(f"Fichero con nombre de herramienta de bypass ABE: {f}")
    st, evs = _sysmon([10], 300)
    for e in evs if st == "ok" else []:
        if "elevation_service" in norm_name(e.get("TargetImage", "")) and norm_name(e.get("SourceImage", "")) not in ctx.whitelist:
            hits.append(f"{e.get('SourceImage')} accedio al servicio de elevacion")
    hits = sorted(set(hits))
    if st != "ok":
        r["falta"] = "Sysmon (evento 10) para ver accesos al servicio de elevacion"
    if hits:
        r["estado"], r["hallazgos"] = "alerta", hits[:30]
        r["puntos"] = ctx.pts(r["id"], 1.0)
        r["resumen"] = f"{len(hits)} indicio(s) de abuso del cifrado App-Bound"
    else:
        r["resumen"] = "Servicio de elevacion y procesos con aspecto normal"
    return r


# ------------------------------------------------------------------ I05 extensiones
def _manifest_name(ext_dir: Path, manifest: dict) -> str:
    name = manifest.get("name", "")
    if name.startswith("__MSG_"):
        key = name[6:-2]
        for loc in ("es", "en", "en_US", manifest.get("default_locale", "en")):
            f = ext_dir / "_locales" / loc / "messages.json"
            try:
                msgs = json.loads(f.read_text(encoding="utf-8-sig"))
                for k, v in msgs.items():
                    if k.lower() == key.lower():
                        return v.get("message", name)
            except (OSError, ValueError):
                continue
    return name


def forced_extension_ids() -> set:
    ids = set()
    if IS_WIN:
        try:
            import winreg
            for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                for sub in (r"Software\Policies\Google\Chrome\ExtensionInstallForcelist",
                            r"Software\Policies\Microsoft\Edge\ExtensionInstallForcelist",
                            r"Software\Policies\BraveSoftware\Brave\ExtensionInstallForcelist"):
                    try:
                        with winreg.OpenKey(hive, sub) as k:
                            i = 0
                            while True:
                                _, v, _ = winreg.EnumValue(k, i)
                                ids.add(str(v).split(";")[0])
                                i += 1
                    except OSError:
                        continue
        except ImportError:
            pass
    else:
        for d in ("/etc/opt/chrome/policies/managed", "/etc/chromium/policies/managed", "/etc/opt/edge/policies/managed",
                  "/etc/brave/policies/managed"):
            for f in Path(d).glob("*.json") if Path(d).is_dir() else []:
                try:
                    for v in json.loads(f.read_text()).get("ExtensionInstallForcelist", []):
                        ids.add(str(v).split(";")[0])
                except (OSError, ValueError):
                    pass
        f = Path("/etc/firefox/policies/policies.json")
        try:
            for k, v in json.loads(f.read_text()).get("policies", {}).get("ExtensionSettings", {}).items():
                if isinstance(v, dict) and v.get("installation_mode") in ("force_installed", "normal_installed"):
                    ids.add(k)
        except (OSError, ValueError):
            pass
    return ids


def list_extensions(profiles: list[Profile], cfg: dict, baseline_ids: set | None = None) -> list[dict]:
    dang = {d.lower() for d in cfg["extensiones_peligrosas"]}
    forced = forced_extension_ids()
    out = []
    for p in profiles:
        if p.family == "chromium":
            prefs = {}
            for pf in ("Secure Preferences", "Preferences"):
                try:
                    prefs = (json.loads((p.path / pf).read_text(encoding="utf-8")).get("extensions", {})
                             .get("settings", {}))
                    if prefs:
                        break
                except (OSError, ValueError):
                    continue
            edir = p.path / "Extensions"
            if not edir.is_dir():
                continue
            for ex in edir.iterdir():
                vers = sorted([v for v in ex.iterdir() if v.is_dir()]) if ex.is_dir() else []
                if not vers:
                    continue
                vd = vers[-1]
                try:
                    m = json.loads((vd / "manifest.json").read_text(encoding="utf-8-sig"))
                except (OSError, ValueError):
                    continue
                perms = [str(x) for x in m.get("permissions", []) if isinstance(x, (str,))]
                perms += [str(x) for x in m.get("host_permissions", [])]
                perms += [str(x) for x in m.get("optional_permissions", [])]
                for cs in m.get("content_scripts", []):
                    perms += [str(x) for x in cs.get("matches", [])]
                info = prefs.get(ex.name, {}) if isinstance(prefs, dict) else {}
                loc = info.get("location")
                dangerous = sorted({x for x in perms if x.lower() in dang})
                out.append({"browser": p.browser, "profile": p.profile, "id": ex.name,
                            "nombre": _manifest_name(vd, m) or ex.name, "version": m.get("version", ""),
                            "permisos": sorted(set(perms)), "peligrosos": dangerous,
                            "modo_dev": loc == 4, "fuera_tienda": bool(info) and info.get("from_webstore") is False and loc != 5,
                            "forzada": ex.name in forced,
                            "nueva": baseline_ids is not None and f"{p.browser}|{p.profile}|{ex.name}" not in baseline_ids})
        else:
            try:
                data = json.loads((p.path / "extensions.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            for a in data.get("addons", []):
                if a.get("type") != "extension" or a.get("location") in ("app-builtin", "app-system-defaults"):
                    continue
                up = a.get("userPermissions") or {}
                perms = list(up.get("permissions", [])) + list(up.get("origins", []))
                dangerous = sorted({x for x in perms if x.lower() in dang or x == "<all_urls>"})
                out.append({"browser": p.browser, "profile": p.profile, "id": a.get("id", ""),
                            "nombre": (a.get("defaultLocale") or {}).get("name", a.get("id", "")),
                            "version": a.get("version", ""), "permisos": sorted(set(perms)), "peligrosos": dangerous,
                            "modo_dev": a.get("temporarilyInstalled", False) or a.get("signedState", 2) in (0, None, -1),
                            "fuera_tienda": False, "forzada": a.get("id") in forced,
                            "nueva": baseline_ids is not None and f"{p.browser}|{p.profile}|{a.get('id')}" not in baseline_ids})
    return out


def i05(ctx: Ctx):
    r = mk("I05_extensiones", "Extensiones del navegador con permisos peligrosos", "T1176 / T1539",
           "Una extension maliciosa con permiso de cookies, 'todas las paginas' o depuracion puede robar sesiones "
           "sin tocar el equipo. Se vigilan las nuevas, las instaladas fuera de la tienda y las forzadas por politica.")
    base = ctx.state.get("baseline_extensiones")
    exts = list_extensions(ctx.profiles, ctx.cfg, set(base) if base is not None else None)
    ctx.new_state["baseline_extensiones"] = sorted({f"{e['browser']}|{e['profile']}|{e['id']}" for e in exts})
    ctx.extensions = exts
    hits, worst = [], 0.0
    for e in exts:
        flags = []
        if e["nueva"]:
            flags.append("nueva desde el ultimo analisis")
        if e["modo_dev"]:
            flags.append("modo desarrollador / sin firma")
        if e["fuera_tienda"]:
            flags.append("instalada fuera de la tienda")
        if e["forzada"]:
            flags.append("forzada por politica")
        if e["peligrosos"] and flags:
            hits.append(f"{e['nombre']} [{e['browser']}/{e['profile']}]: {', '.join(flags)}; permisos {', '.join(e['peligrosos'][:4])}")
            worst = max(worst, 1.0 if e["nueva"] or e["forzada"] else 0.6)
        elif e["forzada"] or (e["modo_dev"] and not e["peligrosos"]):
            hits.append(f"{e['nombre']} [{e['browser']}/{e['profile']}]: {', '.join(flags)}")
            worst = max(worst, 0.3)
    r["resumen"] = f"{len(exts)} extension(es) revisadas"
    if hits:
        r["estado"], r["hallazgos"] = "alerta", hits[:30]
        r["puntos"] = ctx.pts(r["id"], worst)
        r["resumen"] += f"; {len(hits)} a revisar"
    if base is None:
        r["resumen"] += " (primera ejecucion: linea base creada)"
    return r


# ------------------------------------------------------------------ I06 copias de bases de datos
def i06(ctx: Ctx):
    r = mk("I06_copias_bd", "Copias sospechosas de bases de datos del navegador", "T1555.003 / T1074",
           "Los stealers copian las bases de cookies/contrasenas a carpetas temporales (o las empaquetan en ZIP/TXT) "
           "antes de enviarlas.")
    w = _walk_dirs(ctx)
    hits = w["bd"] + w["txt"] + w["zip"]
    if hits:
        r["estado"], r["hallazgos"] = "alerta", hits[:30]
        r["puntos"] = ctx.pts(r["id"], 1.0 if w["bd"] else 0.7)
        r["resumen"] = f"{len(hits)} fichero(s) sospechoso(s) fuera de las carpetas del navegador"
    else:
        r["resumen"] = "Sin copias sospechosas en Temp, AppData, Public, Descargas..."
        if w.get("apps_ignoradas"):
            r["resumen"] += f" ({w['apps_ignoradas']} bases de apps Chromium/Electron legitimas ignoradas)"
    return r


# ------------------------------------------------------------------ I07 red / exfiltracion
def _dns_cache_names() -> list[str]:
    names = []
    if IS_WIN:
        code, out, _ = run(["ipconfig", "/displaydns"], 40)
        names = re.findall(r"(?:Record Name|Nombre de registro)[ .]*:\s*(\S+)", out, re.I)
    return names


def i07(ctx: Ctx):
    r = mk("I07_red_exfil", "Conexiones hacia destinos de exfiltracion", "T1567 / T1041",
           "Los stealers envian lo robado a Telegram, webhooks de Discord, sitios de subida anonima o tuneles. "
           "Estos servicios tambien tienen usos legitimos: es un indicio, no una prueba.")
    pats = ctx.destinos["dominios"]
    hits, total = [], 0
    names = _dns_cache_names()
    st_evs = []
    if IS_WIN:
        st, evs = _sysmon([3, 22], 400)
        if st == "ok":
            st_evs = evs
    for n in names:
        for d in pats:
            host = d["patron"].split("/")[0]
            if n.lower() == host or n.lower().endswith("." + host):
                hits.append(f"DNS cache: {n} ({d['tipo']})")
                total += d["peso"]
                break
    for e in st_evs:
        n = (e.get("QueryName") or e.get("DestinationHostname") or "").lower()
        proc = norm_name(e.get("Image", ""))
        for d in pats:
            host = d["patron"].split("/")[0]
            if n and (n == host or n.endswith("." + host)) and proc not in ctx.whitelist:
                hits.append(f"Sysmon: {e.get('Image')} -> {n} ({d['tipo']})")
                total += d["peso"] + 3
                break
    hits = sorted(set(hits))
    if not IS_WIN:
        r["falta"] = "Linux no expone la cache DNS; se recomienda systemd-resolved con log o Sysmon for Linux"
        r["estado"], r["resumen"] = "sin_datos", "Sin datos: " + r["falta"]
        return r
    if hits:
        r["estado"], r["hallazgos"] = "alerta", hits[:30]
        r["puntos"] = ctx.pts(r["id"], min(1.0, (total + 3) / 15))
        r["resumen"] = f"{len(hits)} destino(s) de la lista de exfiltracion"
    else:
        r["resumen"] = "Cache DNS sin destinos de exfiltracion conocidos"
    if not st_evs:
        r["falta"] = "Sysmon (eventos 3 y 22) para saber QUE proceso se conecto"
    return r


# ------------------------------------------------------------------ I08 Defender
def i08(ctx: Ctx):
    r = mk("I08_defender", "Microsoft Defender: detecciones y proteccion", "T1562.001 / T1555",
           "Detecciones de familias de stealer, proteccion en tiempo real desactivada o exclusiones raras suelen "
           "acompanar a un robo de credenciales.")
    if not IS_WIN:
        r["estado"], r["resumen"] = "no_aplica", "Defender es de Windows; en Linux usa tu antivirus/EDR habitual"
        return r
    script = ("$o=@{};try{$o.st=Get-MpComputerStatus|Select-Object RealTimeProtectionEnabled,IsTamperProtected,"
              "AntivirusEnabled}catch{};try{$o.det=@(Get-MpThreatDetection|Select-Object ThreatID,ProcessName,"
              "InitialDetectionTime -First 200);$o.thr=@(Get-MpThreat|Select-Object ThreatID,ThreatName)}catch{};"
              "try{$p=Get-MpPreference;$o.exp=@($p.ExclusionPath)+@($p.ExclusionProcess)+@($p.ExclusionExtension)}catch{};"
              "$o|ConvertTo-Json -Depth 4 -Compress")
    code, out, _ = ps(script, 90)
    try:
        d = json.loads(out)
    except Exception:  # noqa: BLE001
        r["estado"], r["falta"] = "sin_datos", "No se pudo consultar Defender (otro antivirus o sin permisos)"
        r["resumen"] = r["falta"]
        return r
    hits, frac = [], 0.0
    st = d.get("st") or {}
    if st.get("AntivirusEnabled") is False or st.get("RealTimeProtectionEnabled") is False:
        hits.append("Proteccion en tiempo real DESACTIVADA")
        frac = max(frac, 0.8)
    if st.get("IsTamperProtected") is False:
        hits.append("Proteccion contra alteraciones desactivada")
        frac = max(frac, 0.3)
    names = {str(t.get("ThreatID")): t.get("ThreatName", "") for t in (d.get("thr") or []) if isinstance(t, dict)}
    for t in d.get("det") or []:
        if not isinstance(t, dict):
            continue
        nm = names.get(str(t.get("ThreatID")), "")
        if STEALER_FAMILIES.search(nm):
            hits.append(f"Deteccion de familia de stealer: {nm} ({str(t.get('InitialDetectionTime'))[:10]})")
            frac = 1.0
    exps = [e for e in (d.get("exp") or []) if e and "administrator" not in str(e).lower()]
    for e in exps:
        if re.search(r"(\\temp|\\downloads|\\appdata|\\users\\public|programdata|^[a-z]:\\?$|\.exe$|\.dll$)", str(e), re.I):
            hits.append(f"Exclusion de Defender sospechosa: {e}")
            frac = max(frac, 0.6)
    if d.get("exp") and any("administrator" in str(e).lower() for e in d["exp"]):
        r["falta"] = "Administrador para leer las exclusiones de Defender"
    if hits:
        r["estado"], r["hallazgos"] = "alerta", sorted(set(hits))[:30]
        r["puntos"] = ctx.pts(r["id"], frac)
        r["resumen"] = f"{len(set(hits))} hallazgo(s) en Defender"
    else:
        r["resumen"] = "Defender activo y sin detecciones de stealers"
    return r


# ------------------------------------------------------------------ I09 persistencia
def _persistence_snapshot() -> set:
    snap = set()
    home = Path.home()
    if IS_WIN:
        try:
            import winreg
            for hive, hn in ((winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
                for sub in (r"Software\Microsoft\Windows\CurrentVersion\Run", r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                            r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"):
                    try:
                        with winreg.OpenKey(hive, sub) as k:
                            i = 0
                            while True:
                                n, v, _ = winreg.EnumValue(k, i)
                                snap.add(f"run|{hn}\\{sub.split(chr(92))[-1]}|{n}|{v}")
                                i += 1
                    except OSError:
                        continue
        except ImportError:
            pass
        for d in (Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup",
                  Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "Microsoft/Windows/Start Menu/Programs/StartUp"):
            if d.is_dir():
                for f in d.iterdir():
                    if f.name.lower() != "desktop.ini":
                        snap.add(f"startup|{f}")
        code, out, _ = ps("Get-ScheduledTask | Where-Object {$_.TaskPath -notlike '\\Microsoft\\*'} | ForEach-Object {"
                          "'task|'+$_.TaskPath+$_.TaskName+'|'+(($_.Actions|ForEach-Object{$_.Execute+' '+$_.Arguments}) -join ';')}", 90)
        snap |= {l.strip() for l in out.splitlines() if l.startswith("task|")}
        code, out, _ = ps("Get-CimInstance Win32_Service | Where-Object {$_.PathName -and $_.PathName -notmatch 'Windows\\\\' "
                          "-and $_.PathName -notmatch 'Program Files'} | ForEach-Object {'svc|'+$_.Name+'|'+$_.PathName}", 60)
        snap |= {l.strip() for l in out.splitlines() if l.startswith("svc|")}
        code, out, _ = ps("Get-CimInstance -Namespace root\\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | "
                          "ForEach-Object {'wmi|'+$_.__CLASS+'|'+$_.Name}", 40)
        snap |= {l.strip() for l in out.splitlines() if l.startswith("wmi|")}
    else:
        for d in (home / ".config/autostart", home / ".config/systemd/user", Path("/etc/xdg/autostart")):
            if d.is_dir():
                for f in d.iterdir():
                    try:
                        snap.add(f"auto|{f}|{hashlib.sha256(f.read_bytes()).hexdigest()[:12]}")
                    except OSError:
                        snap.add(f"auto|{f}")
        code, out, _ = run(["crontab", "-l"], 10)
        for l in out.splitlines():
            if l.strip() and not l.startswith("#"):
                snap.add("cron|" + l.strip())
        for d in ("/etc/cron.d",):
            if Path(d).is_dir():
                for f in Path(d).iterdir():
                    snap.add(f"cron.d|{f}")
        for rc in (".bashrc", ".profile", ".bash_profile", ".zshrc"):
            f = home / rc
            if f.is_file():
                snap.add(f"rc|{rc}|{hashlib.sha256(f.read_bytes()).hexdigest()[:12]}")
    return snap


def i09(ctx: Ctx):
    r = mk("I09_persistencia", "Persistencia nueva en el sistema", "T1547 / T1053 / T1546.003",
           "Un malware que quiere sobrevivir al reinicio crea entradas de arranque, tareas, servicios o suscripciones "
           "WMI. Se comparan con la linea base de la primera ejecucion.")
    snap = _persistence_snapshot()
    base = ctx.state.get("baseline_persistencia")
    ctx.new_state["baseline_persistencia"] = sorted(snap)
    if base is None:
        r["resumen"] = f"Linea base creada ({len(snap)} elementos)"
        return r
    new = sorted(snap - set(base))
    if new:
        r["estado"], r["hallazgos"] = "alerta", [n[:200] for n in new[:30]]
        sus = sum(1 for n in new if re.search(r"(\\temp\\|appdata|downloads|/tmp/|powershell|wscript|mshta|curl )", n, re.I))
        r["puntos"] = ctx.pts(r["id"], min(1.0, 0.3 + 0.2 * len(new) + 0.4 * sus))
        r["resumen"] = f"{len(new)} elemento(s) de arranque nuevo(s) desde la linea base"
    else:
        r["resumen"] = "Sin persistencia nueva"
    return r


# ------------------------------------------------------------------ I10 ejecutables recientes
def i10(ctx: Ctx):
    r = mk("I10_ejecutables", "Ejecutables recientes sin firmar en Descargas/Temp", "T1204 / T1553.005",
           "Los stealers suelen llegar como ejecutables descargados o en Temp. Se miran los recientes sin firma valida "
           "o sin marca de descarga (Mark-of-the-Web).")
    days = ctx.cfg["dias"]["ejecutables_recientes"]
    cutoff = time.time() - days * 86400
    home = Path.home()
    dirs = ctx.scan_dirs if ctx.scan_dirs is not None else (
        [home / "Downloads", Path(tempfile.gettempdir())] if IS_WIN else [home / "Downloads", Path("/tmp"), Path("/dev/shm")])
    ext_ok = {".exe", ".dll", ".scr", ".msi", ".com", ".ps1", ".vbs", ".js", ".bat", ".cmd", ".jar", ".hta"}
    files = []
    for base in dirs:
        base = Path(base)
        if not base.is_dir():
            continue
        for root, subdirs, fs in os.walk(base):
            if len(Path(root).parts) - len(base.parts) >= 2 or "cookieguard" in root.lower():
                subdirs[:] = []
                continue
            for fn in fs:
                fp = Path(root) / fn
                try:
                    st = fp.stat()
                except OSError:
                    continue
                if st.st_mtime < cutoff:
                    continue
                if IS_WIN and fp.suffix.lower() in ext_ok:
                    files.append((st.st_mtime, fp))
                elif not IS_WIN and (st.st_mode & 0o111) and st.st_size > 0:
                    try:
                        with open(fp, "rb") as fh:
                            h = fh.read(4)
                        if h == b"\x7fELF" or h[:2] == b"#!":
                            files.append((st.st_mtime, fp))
                    except OSError:
                        pass
            if len(files) > 400:
                break
    files.sort(reverse=True)
    files = [f for _, f in files[:60]]
    hits = []
    if IS_WIN and files:
        lst = data_dir() / "tmp" / f"lista_{os.getpid()}.txt"
        lst.write_text("\n".join(str(f) for f in files), encoding="utf-8")
        code, out, _ = ps(f"Get-Content -LiteralPath '{lst}' | ForEach-Object {{ $s=Get-AuthenticodeSignature -LiteralPath $_ "
                          "-ErrorAction SilentlyContinue; '' + $s.Status + '|' + $_ }", 120)
        try:
            lst.unlink()
        except OSError:
            pass
        for line in out.splitlines():
            if "|" not in line:
                continue
            status, path = line.split("|", 1)
            if status.strip() != "Valid":
                motw = os.path.exists(path.strip() + ":Zone.Identifier")
                if path.lower().endswith((".dll", ".js", ".bat", ".cmd", ".vbs", ".ps1")) and motw:
                    continue
                hits.append(f"{path.strip()} ({'sin firma valida' if status.strip() != 'NotSigned' else 'sin firmar'}"
                            f"{'' if motw else ', sin marca de descarga'})")
    elif files:
        hits = [f"{f} (ejecutable reciente)" for f in files]
    if hits:
        r["estado"], r["hallazgos"] = "alerta", hits[:30]
        r["puntos"] = ctx.pts(r["id"], min(1.0, 0.3 + 0.1 * len(hits)))
        r["resumen"] = f"{len(hits)} ejecutable(s) reciente(s) sin firma valida"
    else:
        r["resumen"] = "Sin ejecutables recientes sospechosos"
    return r


# ------------------------------------------------------------------ I11 manipulacion de red local
def i11(ctx: Ctx):
    r = mk("I11_manipulacion_red", "Manipulacion de la red local (proxy, certificados, hosts, DNS)", "T1557 / T1553.004",
           "Un atacante puede desviar el trafico con un proxy, instalar un certificado raiz propio, editar el fichero "
           "hosts o cambiar los DNS para interceptar sesiones.")
    snap: dict = {}
    hits, frac = [], 0.0
    hosts_path = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/drivers/etc/hosts" if IS_WIN else Path("/etc/hosts")
    try:
        lines = [l.strip() for l in hosts_path.read_text(encoding="utf-8", errors="replace").splitlines()
                 if l.strip() and not l.strip().startswith("#")]
        snap["hosts"] = sorted(lines)
        for l in lines:
            parts = l.split()
            if len(parts) >= 2 and parts[0] not in ("127.0.0.1", "::1", "0.0.0.0") and any(
                    classifier.match_service(h) for h in parts[1:]):
                hits.append(f"hosts redirige un servicio conocido: {l[:100]}")
                frac = max(frac, 0.9)
    except OSError:
        pass
    if IS_WIN:
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as k:
                for n in ("ProxyEnable", "ProxyServer", "AutoConfigURL"):
                    try:
                        snap[n] = str(winreg.QueryValueEx(k, n)[0])
                    except OSError:
                        pass
        except (ImportError, OSError):
            pass
        code, out, _ = ps("Get-ChildItem Cert:\\CurrentUser\\Root,Cert:\\LocalMachine\\Root | ForEach-Object {$_.Thumbprint+'|'+$_.Subject}", 60)
        snap["certs"] = sorted({l.strip() for l in out.splitlines() if "|" in l})
        code, out, _ = ps("Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object {$_.ServerAddresses} | Sort-Object -Unique", 30)
        snap["dns"] = sorted({l.strip() for l in out.splitlines() if l.strip()})
    else:
        snap["proxy_env"] = sorted(f"{k}={v}" for k, v in os.environ.items() if k.lower() in ("http_proxy", "https_proxy", "all_proxy"))
        try:
            snap["dns"] = sorted(l.split()[1] for l in Path("/etc/resolv.conf").read_text().splitlines()
                                 if l.startswith("nameserver") and len(l.split()) > 1)
        except OSError:
            pass
        certs = []
        for d in ("/usr/local/share/ca-certificates", str(Path.home() / ".pki")):
            if Path(d).is_dir():
                certs += [str(p) for p in Path(d).rglob("*") if p.is_file() and p.suffix in (".crt", ".pem", ".cer")]
        snap["certs"] = sorted(certs)
    base = ctx.state.get("baseline_red")
    ctx.new_state["baseline_red"] = snap
    if snap.get("ProxyEnable") == "1" or snap.get("AutoConfigURL") or snap.get("proxy_env"):
        hits.append(f"Hay un proxy configurado: {snap.get('ProxyServer') or snap.get('AutoConfigURL') or snap.get('proxy_env')}")
        frac = max(frac, 0.4)
    if base is not None:
        for key, label, w in (("certs", "Certificado raiz nuevo", 1.0), ("dns", "Servidor DNS cambiado", 0.6),
                              ("hosts", "Linea nueva en hosts", 0.5)):
            new = sorted(set(map(str, snap.get(key, []))) - set(map(str, base.get(key, []))))
            for n in new[:10]:
                hits.append(f"{label}: {n[:140]}")
                frac = max(frac, w)
        for key in ("ProxyServer", "AutoConfigURL"):
            if snap.get(key) and snap.get(key) != base.get(key):
                hits.append(f"Proxy cambiado ({key})")
                frac = max(frac, 0.8)
    r["resumen"] = "Linea base creada" if base is None else "Sin cambios en proxy, certificados, hosts ni DNS"
    if hits:
        r["estado"], r["hallazgos"] = "alerta", sorted(set(hits))[:30]
        r["puntos"] = ctx.pts(r["id"], frac)
        r["resumen"] = f"{len(set(hits))} cambio(s)/hallazgo(s) de red"
    return r


# ------------------------------------------------------------------ I12 anomalias en cookies
def i12(ctx: Ctx):
    r = mk("I12_anomalias_cookies", "Anomalias en las propias cookies", "T1539",
           "Muchas cookies de servicios criticos creadas a la vez en un momento raro, o actividad del navegador "
           "cuando esta cerrado, pueden indicar importacion o manipulacion de sesiones.")
    now = datetime.now()
    buckets: dict = {}
    for s in ctx.sessions:
        svc = classifier.match_service(s["host"])
        if not svc or not classifier.categoria_critica(svc["categoria"]):
            continue
        for key in ("created", "last_update"):
            t = s.get(key)
            if t and now - t < timedelta(days=14):
                buckets.setdefault(int(t.timestamp() // 120), set()).add(svc["id"])
    hits, frac = [], 0.0
    for b, svcs in buckets.items():
        if len(svcs) >= 6:
            t = datetime.fromtimestamp(b * 120)
            odd = t.hour < 6
            hits.append(f"{len(svcs)} servicios criticos con cookies escritas a la vez ({t:%d/%m %H:%M})"
                        f"{' - hora inusual' if odd else ''}")
            frac = max(frac, 0.9 if odd else 0.5)
    hb = ctx.state.get("latido_navegadores")
    if not hb:
        r["falta"] = "Vigilante activo para detectar actividad con el navegador cerrado"
    if hits:
        r["estado"], r["hallazgos"] = "alerta", hits[:20]
        r["puntos"] = ctx.pts(r["id"], frac)
        r["resumen"] = f"{len(hits)} patron(es) anomalo(s)"
    else:
        r["resumen"] = "Sin patrones anomalos en las cookies"
    return r



# ------------------------------------------------------------------ I13 canary cookies
def i13(ctx: Ctx):
    r = mk("I13_canary_cookie", "Disparo o manipulacion de Canary Cookie (Senuelo)", "T1539",
           "Las cookies senuelo (canary) detectan cualquier intento de volcado o manipulacion "
           "de bases de datos por infostealers con 0% de falsos positivos.")
    try:
        from . import canary
        res = canary.verify_canaries(ctx.profiles)
        if res.get("disparados"):
            r["estado"] = "alerta"
            r["hallazgos"] = res.get("alertas", [])
            r["puntos"] = ctx.pts(r["id"], 1.0)
            r["resumen"] = f"¡Cebo trampa disparado! {len(r[hallazgos])} anomalia(s)"
        elif res.get("activos", 0) > 0:
            r["estado"] = "ok"
            r["resumen"] = f"{res[activos]} cebo(s) canary vigilados e intactos"
        else:
            cfg = ctx.state.get("config", {})
            if cfg.get("canary_activo"):
                r["estado"] = "ok"
                r["resumen"] = "Canarytoken externo activo"
            else:
                r["estado"] = "sin_datos"
                r["resumen"] = "Sin cebos canary sembrados"
                r["falta"] = "Sembrar cebos canary locales con el asistente (cookieguard canary)"
    except Exception as e:
        r["estado"] = "error"
        r["resumen"] = f"Error comprobando canaries: {e}"
    return r


# ------------------------------------------------------------------ I14 DPAPI / master key
def i14(ctx: Ctx):
    r = mk("I14_dpapi_masterkey", "Auditoria de acceso a clave maestra (Local State / DPAPI)", "T1555.003",
           "Los infostealers necesitan leer el fichero Local State de Chromium para extraer la clave "
           "cifrada y descifrarla mediante la API DPAPI de Windows o el Secret Service de Linux.")
    hallazgos = []

    # 1. Rutas de Local State y credenciales
    ls_paths = set()
    for p in ctx.profiles:
        if p.family == "chromium":
            f = p.root / "Local State"
            if f.is_file():
                ls_paths.add(f.resolve())
        elif p.family == "firefox":
            for n in ("key4.db", "logins.json"):
                f = p.path / n
                if f.is_file():
                    ls_paths.add(f.resolve())

    # 2. En Linux, revisar /proc/[pid]/fd en procesos ajenos a navegadores
    if IS_LINUX:
        for pr in ctx.procs:
            pid = pr.get("pid")
            name = (pr.get("name") or "").lower()
            if not pid or norm_name(name) in ctx.whitelist:
                continue
            fd_dir = Path(f"/proc/{pid}/fd")
            if not fd_dir.is_dir():
                continue
            try:
                for entry in fd_dir.iterdir():
                    try:
                        target = os.readlink(entry)
                        t_lower = target.lower()
                        if any(str(lsp).lower() == t_lower or t_lower.endswith("/local state") or t_lower.endswith("/key4.db") for lsp in ls_paths):
                            hallazgos.append(f"Proceso no autorizado '{name}' (PID {pid}) mantiene abierto descriptor hacia clave maestra: {target}")
                    except (OSError, ValueError):
                        continue
            except (PermissionError, OSError):
                continue

    # 3. Deteccion de herramientas o comandos de volcado de DPAPI / Master Key
    SUSPICIOUS_DPAPI_CMDS = re.compile(r"(sharpdpapi|hackbrowserdata|mimikatz|pypykatz|lazagne|dump-chrome-cookies|vaultcmd|decrypt_chrome)", re.I)
    for pr in ctx.procs:
        cmd = pr.get("cmd") or ""
        name = pr.get("name") or ""
        if SUSPICIOUS_DPAPI_CMDS.search(cmd) or SUSPICIOUS_DPAPI_CMDS.search(name):
            hallazgos.append(f"Proceso sospechoso de volcado de DPAPI/credenciales detectado: '{name}' (PID {pr.get('pid')}): {cmd[:120]}")

    # 4. En Windows, revisar logs de Sysmon Event ID 11 (FileCreate) o Event ID 10 para Local State
    if IS_WIN:
        st, evs = _sysmon([11], count=200)
        for ev in evs if st == "ok" else []:
            if not isinstance(ev, dict):
                continue
            fn = (ev.get("TargetFilename") or "").lower()
            img = (ev.get("Image") or "").lower()
            if "local state" in fn and not any(b in img for b in ctx.whitelist):
                hallazgos.append(f"Sysmon EID 11: Proceso '{img}' accedio a clave maestra '{fn}'")

    if hallazgos:
        r["estado"] = "alerta"
        r["hallazgos"] = hallazgos
        r["puntos"] = ctx.pts(r["id"], 1.0)
        r["resumen"] = f"¡Alerta! {len(hallazgos)} acceso(s) sospechoso(s) a claves maestras de cookies"
    else:
        if ls_paths:
            r["estado"] = "ok"
            r["resumen"] = f"{len(ls_paths)} fichero(s) Local State/Master Key vigilados sin accesos anómalos"
        else:
            r["estado"] = "sin_datos"
            r["resumen"] = "No se detectaron perfiles con ficheros Local State"
            r["falta"] = "No hay perfiles de navegador Chromium/Firefox activos en este equipo"

    return r



def i15(ctx: Ctx):
    r = mk("I15_procesos_infostealer", "Procesos maliciosos activos (Infostealer Hunter)", "T1059 / T1036 / T1555",
           "Escanea la memoria y procesos en ejecución en busca de troyanos infostealer conocidos "
           "(Lumma, Stealc, RedLine), suplantación de nombres de sistema (masquerading) y ejecutables sospechosos.")
    try:
        from .process_hunter import scan_processes
        res = scan_processes(ctx.procs)
        if not res.get("limpio", True):
            r["estado"] = "alerta"
            r["puntos"] = ctx.pts(r["id"], 1.0)
            hallazgos = []
            for s in res.get("sospechosos", []):
                hallazgos.append(
                    f"[{s.get('severidad', 'ALTA')}] Proceso '{s.get('name')}' (PID {s.get('pid')}): "
                    f"{s.get('motivo')} - Familia: {s.get('familia')} - Acción: {s.get('comando')}"
                )
            r["hallazgos"] = hallazgos
            r["resumen"] = f"¡Alerta! {len(hallazgos)} proceso(s) malicioso(s) o sospechoso(s) detectados en memoria"
        else:
            r["estado"] = "ok"
            r["resumen"] = f"{res.get('total_procesos', 0)} procesos analizados en memoria sin indicios de infostealers"
    except Exception as e:
        log(f"i15 fallo: {e}")
        r["estado"] = "error"
        r["resumen"] = f"Error al escanear procesos: {e}"
    return r

INDICATORS = [i01, i02, i03, i04, i05, i06, i07, i08, i09, i10, i11, i12, i13, i14, i15]



def run_all(ctx: Ctx, progress=None) -> list[dict]:
    """Ejecuta los 15 indicadores en paralelo. Un fallo en uno no detiene a los demas."""
    results: dict = {}

    def _one(fn):
        t0 = time.time()
        try:
            res = fn(ctx)
        except Exception as e:  # noqa: BLE001
            log(f"indicador {fn.__name__} fallo: {type(e).__name__}: {e}")
            res = mk(fn.__name__.upper(), fn.__name__, "", "")
            res["id"] = {"i01": "I01_acceso_ficheros", "i02": "I02_flags_navegador", "i03": "I03_memoria_navegador",
                         "i04": "I04_abe_elevation", "i05": "I05_extensiones", "i06": "I06_copias_bd",
                         "i07": "I07_red_exfil", "i08": "I08_defender", "i09": "I09_persistencia",
                         "i10": "I10_ejecutables", "i11": "I11_manipulacion_red",
                         "i12": "I12_anomalias_cookies", "i13": "I13_canary_cookie", "i14": "I14_dpapi_masterkey", "i15": "I15_procesos_infostealer"}[fn.__name__]
            res["estado"], res["resumen"] = "error", f"El indicador fallo ({type(e).__name__}); ver el log"
        res["segundos"] = round(time.time() - t0, 1)
        if progress:
            progress(res)
        return res

    # procesos primero (varios indicadores lo usan) para evitar consultas duplicadas
    _ = ctx.procs
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = [ex.submit(_one, fn) for fn in INDICATORS]
        for f in futs:
            res = f.result()
            results[res["id"]] = res
    return [results[k] for k in sorted(results)]
