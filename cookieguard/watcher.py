"""Vigilante en tiempo real (proceso ligero). Detecta: procesos con depuracion remota, procesos ajenos con los
ficheros de cookies abiertos (Linux) o eventos 4663/Sysmon (Windows con auditoria). Lanza una alerta con botones:
suspender/matar, bloquear en el firewall, ver detalles, marcar como de confianza."""
from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from .browsers import discover, sensitive_files
from .common import IS_WIN, data_dir, is_admin, load_config, load_state, log, ps, run, save_state, save_user_config
from .detections import (NOT_FLAG_HOSTS, SENSITIVE_NAMES, _is_browser_proc, list_processes, norm_name, wevt)


# ------------------------------------------------------------------ medicion de consumo propio
def self_usage() -> dict:
    mem = 0
    try:
        if IS_WIN:
            import ctypes
            from ctypes import wintypes

            class PMC(ctypes.Structure):
                _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                            ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                            ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
            pmc = PMC()
            pmc.cb = ctypes.sizeof(PMC)
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.GetCurrentProcess.restype = wintypes.HANDLE
            k32.K32GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PMC), wintypes.DWORD]
            k32.K32GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb)
            mem = pmc.WorkingSetSize
        else:
            mem = int(Path("/proc/self/statm").read_text().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    except Exception:  # noqa: BLE001
        pass
    return {"cpu_s": round(time.process_time(), 2), "mem_mb": round(mem / 1048576, 1)}


def toolhelp_snapshot() -> dict:
    """Windows: {pid: (ppid, nombre)} con la API nativa (sin lanzar PowerShell; coste casi nulo)."""
    import ctypes
    from ctypes import wintypes

    class PE(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k.Process32FirstW.argtypes = k.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PE)]
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    h = k.CreateToolhelp32Snapshot(0x2, 0)
    out = {}
    pe = PE()
    pe.dwSize = ctypes.sizeof(PE)
    ok = k.Process32FirstW(h, ctypes.byref(pe))
    while ok:
        out[pe.th32ProcessID] = (pe.th32ParentProcessID, pe.szExeFile)
        ok = k.Process32NextW(h, ctypes.byref(pe))
    k.CloseHandle(h)
    return out


# ------------------------------------------------------------------ acciones sobre un proceso
def suspend(pid: int) -> bool:
    try:
        if IS_WIN:
            import ctypes
            h = ctypes.windll.kernel32.OpenProcess(0x0800, False, pid)
            if not h:
                return False
            ok = ctypes.windll.ntdll.NtSuspendProcess(h) == 0
            ctypes.windll.kernel32.CloseHandle(h)
            return ok
        os.kill(pid, signal.SIGSTOP)
        return True
    except Exception as e:  # noqa: BLE001
        log(f"suspender {pid}: {e}")
        return False


def resume(pid: int) -> bool:
    try:
        if IS_WIN:
            import ctypes
            h = ctypes.windll.kernel32.OpenProcess(0x0800, False, pid)
            ok = bool(h) and ctypes.windll.ntdll.NtResumeProcess(h) == 0
            if h:
                ctypes.windll.kernel32.CloseHandle(h)
            return ok
        os.kill(pid, signal.SIGCONT)
        return True
    except Exception:  # noqa: BLE001
        return False


def kill(pid: int) -> bool:
    if IS_WIN:
        return run(["taskkill", "/PID", str(pid), "/F"], 15)[0] == 0
    try:
        os.kill(pid, signal.SIGKILL)
        return True
    except OSError:
        return False


def block_exe(exe: str) -> tuple[bool, str]:
    """Windows: regla de salida del Firewall por ejecutable (necesita administrador).
    Linux: no hay filtro por ejecutable sin root; se quita el permiso de ejecucion."""
    if not exe:
        return False, "No se conoce la ruta del ejecutable"
    if IS_WIN:
        if not is_admin():
            return False, "Hace falta administrador para crear la regla de firewall"
        name = f"CookieGuard bloqueo {os.path.basename(exe)}"
        code, out, err = run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=out",
                              "action=block", f"program={exe}", "enable=yes"], 20)
        if code == 0:
            st = load_state()
            st.setdefault("reglas_firewall", []).append(name)
            save_state(st)
        return code == 0, (out + err).strip()
    try:
        os.chmod(exe, os.stat(exe).st_mode & ~0o111)
        return True, "Permiso de ejecucion retirado (Linux no filtra por ejecutable sin root)"
    except OSError as e:
        return False, str(e)


def details(pid: int, exe: str = "", cmd: str = "", ppid: int = 0) -> dict:
    procs = {p["pid"]: p for p in list_processes()}
    p = procs.get(pid, {"exe": exe, "cmd": cmd, "ppid": ppid, "name": ""})
    exe = p.get("exe") or exe
    out = {"pid": pid, "ruta": exe, "linea_comandos": p.get("cmd") or cmd,
           "padre": f"{procs.get(p.get('ppid'), {}).get('name', '?')} (PID {p.get('ppid')})"}
    try:
        out["sha256"] = hashlib.sha256(Path(exe).read_bytes()).hexdigest() if exe and Path(exe).stat().st_size < 300_000_000 else "n/d"
    except OSError:
        out["sha256"] = "n/d"
    if IS_WIN and exe:
        c, o, _ = ps(f"$s=Get-AuthenticodeSignature -LiteralPath '{exe}';\"$($s.Status) - $($s.SignerCertificate.Subject)\"", 30)
        out["firma"] = o.strip() or "n/d"
    else:
        out["firma"] = "n/a (Linux)"
    return out


def trust(name: str) -> None:
    cfg = load_config()
    wl = sorted(set(cfg["whitelist_procesos"]) | {norm_name(name)})
    save_user_config({"whitelist_procesos": wl})


# ------------------------------------------------------------------ bucle de vigilancia
class Watcher:
    def __init__(self):
        self.cfg = load_config()
        self.whitelist = {w.lower() for w in self.cfg["whitelist_procesos"]}
        self.profiles = discover()
        self.files = {str(f) for f in sensitive_files(self.profiles)}
        self.seen: dict = {}
        self.last_event_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        self.sources = []

    def _emit(self, key, titulo, motivo, p):
        if time.time() - self.seen.get(key, 0) < 600:
            return
        self.seen[key] = time.time()
        al = {"fecha": datetime.now().isoformat(timespec="seconds"), "titulo": titulo, "motivo": motivo,
              "pid": p.get("pid"), "nombre": p.get("name"), "exe": p.get("exe"), "cmd": (p.get("cmd") or "")[:300],
              "ppid": p.get("ppid")}
        with open(data_dir() / "alertas.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(al, ensure_ascii=False) + "\n")
        log(f"ALERTA {titulo}: {motivo}")
        path = data_dir() / "tmp" / f"alerta_{int(time.time())}.json"
        path.write_text(json.dumps(al), encoding="utf-8")
        if self.cfg.get("webhook_activo"):
            try:
                from . import webhook
                webhook.send_alert({
                    "nivel": "CRITICO",
                    "resumen": f"{titulo}: {motivo}",
                    "indicadores": [titulo]
                })
            except Exception as e:
                log(f"Fallo webhook watcher: {e}")
        if self.cfg.get("killswitch_auto_en_rojo"):
            try:
                from . import killswitch
                killswitch.enable()
            except Exception as e:
                log(f"Fallo auto-killswitch: {e}")
        kw = {"creationflags": 0x08000000} if IS_WIN else {}
        subprocess.Popen([sys.executable, "-m", "cookieguard.watcher", "--alerta", str(path)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, **kw)

    def procs_fast(self) -> list[dict]:
        """Lista de procesos barata: en Windows solo se consulta PowerShell para los procesos NUEVOS."""
        if not IS_WIN:
            return list_processes()
        cur = toolhelp_snapshot()
        if not hasattr(self, "_cache"):
            self._cache = {p["pid"]: p for p in list_processes()}
        new = [pid for pid, (_, nm) in cur.items()
               if pid not in self._cache or self._cache[pid]["name"].lower() != nm.lower()]
        if new:
            flt = " -or ".join(f"$_.ProcessId -eq {pid}" for pid in new[:200])
            code, out, _ = ps(f"Get-CimInstance Win32_Process | Where-Object {{ {flt} }} | Select-Object ProcessId,"
                              "ParentProcessId,Name,CommandLine,ExecutablePath | ConvertTo-Json -Compress", 60)
            try:
                data = json.loads(out) if out.strip() else []
                for d in ([data] if isinstance(data, dict) else data):
                    self._cache[d["ProcessId"]] = {"pid": d["ProcessId"], "ppid": d["ParentProcessId"],
                                                   "name": d.get("Name") or "", "cmd": d.get("CommandLine") or "",
                                                   "exe": d.get("ExecutablePath") or ""}
            except Exception:  # noqa: BLE001
                pass
            for pid in new:
                if pid not in self._cache or self._cache[pid]["name"].lower() != cur[pid][1].lower():
                    self._cache[pid] = {"pid": pid, "ppid": cur[pid][0], "name": cur[pid][1], "cmd": "", "exe": ""}
        self._cache = {pid: p for pid, p in self._cache.items() if pid in cur}
        return list(self._cache.values())

    def tick(self):
        self.cfg = load_config()
        self.whitelist = {w.lower() for w in self.cfg["whitelist_procesos"]}
        procs = self.procs_fast()
        running = {norm_name(p["name"]) for p in procs if _is_browser_proc(p["name"])}
        st = load_state()
        hb = st.setdefault("latido_navegadores", {})
        for b in running:
            hb[b] = time.time()
        save_state(st)
        for p in procs:
            cmd = p["cmd"] or ""
            if norm_name(p["name"]) in NOT_FLAG_HOSTS:
                continue
            if re.search(r"(?:^|\s)--remote-(debugging-(port|pipe)|allow-origins)", cmd):
                if norm_name(p["name"]) not in ("msedgewebview2",) or "--remote-allow-origins" in cmd:
                    self._emit(f"dbg{p['pid']}", "Navegador con depuracion remota",
                               f"{p['name']} (PID {p['pid']}) se lanzo con depuracion remota: asi se roban cookies ya descifradas.", p)
            elif _is_browser_proc(p["name"]) and "--headless" in cmd and "--type=" not in cmd:
                self._emit(f"hl{p['pid']}", "Navegador sin ventana (headless)",
                           f"{p['name']} (PID {p['pid']}) se ejecuta en modo headless.", p)
        if not IS_WIN:
            self.sources = ["procesos", "ficheros abiertos (/proc)"]
            byname = {p["pid"]: p for p in procs}
            for pid, p in byname.items():
                if norm_name(p["name"]) in self.whitelist:
                    continue
                try:
                    for fd in Path(f"/proc/{pid}/fd").iterdir():
                        try:
                            if os.readlink(fd) in self.files:
                                self._emit(f"fd{pid}", "Proceso ajeno lee ficheros del navegador",
                                           f"{p['name']} (PID {pid}) tiene abierto {os.path.basename(os.readlink(fd))}.", p)
                        except OSError:
                            pass
                except OSError:
                    continue
        else:
            self.sources = ["procesos"]
            st4, evs = wevt("Security", "*[System[(EventID=4663)]]", 50)
            if st4 == "ok":
                self.sources.append("eventos 4663")
                for e in evs:
                    if e.get("Time", "")[:19] <= self.last_event_time:
                        continue
                    base = os.path.basename((e.get("ObjectName") or "").replace("\\", "/")).lower()
                    nm = norm_name(e.get("ProcessName", ""))
                    if base in SENSITIVE_NAMES and nm not in self.whitelist and nm:
                        pid = int(e.get("ProcessId", "0"), 16) if str(e.get("ProcessId", "")).startswith("0x") else 0
                        self._emit(f"ev{nm}{base}", "Proceso ajeno accede a ficheros del navegador",
                                   f"{e.get('ProcessName')} abrio {base}.",
                                   {"pid": pid, "name": nm, "exe": e.get("ProcessName"), "cmd": "", "ppid": 0})
                self.last_event_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
            stm, evs = wevt("Microsoft-Windows-Sysmon/Operational", "*[System[(EventID=10)]]", 30)
            if stm == "ok":
                self.sources.append("Sysmon 10")
                for e in evs:
                    if e.get("Time", "")[:19] <= self.last_event_time:
                        continue
                    if _is_browser_proc(e.get("TargetImage", "")) and norm_name(e.get("SourceImage", "")) not in self.whitelist:
                        self._emit(f"mem{e.get('SourceProcessId')}", "Acceso a la memoria del navegador",
                                   f"{e.get('SourceImage')} accedio a {e.get('TargetImage')}.",
                                   {"pid": int(e.get("SourceProcessId", 0) or 0), "name": norm_name(e.get("SourceImage", "")),
                                    "exe": e.get("SourceImage"), "cmd": "", "ppid": 0})


def main() -> int:
    if "--alerta" in sys.argv:
        return alert_dialog(Path(sys.argv[sys.argv.index("--alerta") + 1]))
    w = Watcher()
    interval = max(3, int(w.cfg.get("vigilante_intervalo_s", 10)))
    pidf = data_dir() / "vigilante.pid"
    pidf.write_text(str(os.getpid()))
    log(f"vigilante iniciado (cada {interval}s)")
    n, t0 = 0, time.time()
    while True:
        try:
            w.tick()
        except Exception as e:  # noqa: BLE001
            log(f"vigilante error: {type(e).__name__}: {e}")
        n += 1
        if n % 30 == 0 or n == 2:
            u = self_usage()
            wall = time.time() - t0
            (data_dir() / "vigilante_estado.json").write_text(json.dumps(
                {"pid": os.getpid(), "fuentes": w.sources, "cpu_medio_pct": round(100 * u["cpu_s"] / max(wall, 1), 2),
                 "memoria_mb": u["mem_mb"], "ciclos": n, "ultimo": datetime.now().isoformat(timespec="seconds")}))
        time.sleep(interval)


def alert_dialog(path: Path) -> int:
    try:
        import tkinter as tk
        from tkinter import messagebox
    except (ImportError, Exception):
        from .notify import notify
        al = json.loads(path.read_text(encoding="utf-8"))
        notify(al.get("titulo", "Alerta de Sesiones"),
               f"{al.get('motivo', '')} | Proceso: {al.get('nombre')} (PID {al.get('pid')})",
               nivel="rojo")
        return 0
    al = json.loads(path.read_text(encoding="utf-8"))
    root = tk.Tk()
    root.title("CookieGuard - ALERTA")
    root.attributes("-topmost", True)
    tk.Label(root, text=al["titulo"], font=("Segoe UI", 14, "bold"), fg="#c62828").pack(padx=14, pady=(12, 4))
    tk.Label(root, text=al["motivo"], wraplength=480, justify="left").pack(padx=14)
    tk.Label(root, text=f"Proceso: {al['nombre']}  PID {al['pid']}\n{al['exe']}", justify="left", fg="#555").pack(padx=14, pady=6)
    pid = int(al["pid"] or 0)

    def info(msg):
        messagebox.showinfo("CookieGuard", msg, parent=root)

    def do_susp():
        info("Proceso suspendido" if suspend(pid) else "No se pudo suspender (permisos o ya no existe)")

    def do_kill():
        if messagebox.askyesno("Confirmar", f"Terminar el proceso {al['nombre']} (PID {pid})?", parent=root):
            info("Proceso terminado" if kill(pid) else "No se pudo terminar")

    def do_block():
        ok, msg = block_exe(al["exe"])
        info(("Bloqueado. " if ok else "No se pudo bloquear. ") + msg)

    def do_det():
        d = details(pid, al["exe"], al["cmd"], al.get("ppid") or 0)
        info("\n".join(f"{k}: {v}" for k, v in d.items()))

    def do_trust():
        trust(al["nombre"] or "")
        info(f"{al['nombre']} anadido a la lista de confianza")
        root.destroy()

    f = tk.Frame(root)
    f.pack(pady=10)
    for txt, cmd in (("Suspender", do_susp), ("Matar", do_kill), ("Bloquear", do_block), ("Detalles", do_det),
                     ("Es de confianza", do_trust), ("Cerrar", root.destroy)):
        tk.Button(f, text=txt, command=cmd, width=13).pack(side="left", padx=3)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
