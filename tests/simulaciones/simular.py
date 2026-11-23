"""Simulaciones BENIGNAS: cada una provoca un indicador real y luego se limpia sola.

Uso:  python tests/simulaciones/simular.py todas
      python tests/simulaciones/simular.py debug_flag crear     (deja la simulacion activa)
      python tests/simulaciones/simular.py debug_flag limpiar   (la elimina)

Nada se instala en tus navegadores ni se lee ningun valor de cookie: se crean ficheros/entradas falsos y se borran.
"""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from cookieguard import detections as D  # noqa: E402
from cookieguard.common import IS_WIN, data_dir, load_config  # noqa: E402

SIM_DIR = Path(tempfile.gettempdir()) / "cg_simulacion"
PIDF = SIM_DIR / "debug.pid"


def _ctx(**kw):
    return D.Ctx(load_config(), kw.pop("profiles", []), [], kw.pop("state", {}), kw.pop("scan_dirs", None))


# ---------------------------------------------------------------- 1. acceso a fichero de cookies
def acceso_fichero_crear():
    """Un proceso ajeno (python) mantiene abierto un 'fichero de cookies' de un perfil falso."""
    from helpers_sim import fake_profile
    prof = fake_profile(SIM_DIR / "perfil")
    p = subprocess.Popen([sys.executable, "-c", f"import time;f=open(r'{prof.cookies_db}','rb');time.sleep(120)"])
    (SIM_DIR / "fd.pid").write_text(str(p.pid))
    time.sleep(1.5)
    return prof


def acceso_fichero_comprobar():
    if IS_WIN:
        return None, "OMITIDA en Windows: requiere auditoria 4663 + SACL (se activan con Instalar). Comprueba con CHECKLIST."
    prof = acceso_fichero_crear()
    r = D.i01(D.Ctx(load_config(), [prof], [], {}, None))
    return r["estado"] == "alerta" and any("python" in h.lower() for h in r["hallazgos"]), r["resumen"]


def acceso_fichero_limpiar():
    _kill(SIM_DIR / "fd.pid")


# ---------------------------------------------------------------- 2. flag de depuracion remota
def debug_flag_crear():
    p = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(120)", "--remote-debugging-port=9222"])
    PIDF.parent.mkdir(exist_ok=True)
    PIDF.write_text(str(p.pid))
    time.sleep(1.0)


def debug_flag_comprobar():
    debug_flag_crear()
    r = D.i02(_ctx())
    return r["estado"] == "alerta" and r["puntos"] >= 30, r["resumen"]


def debug_flag_limpiar():
    _kill(PIDF)


# ---------------------------------------------------------------- 3. copia falsa de base de datos en Temp
def copia_bd_crear():
    d = Path(tempfile.gettempdir()) / "cg_simulacion_copia"
    d.mkdir(exist_ok=True)
    con = sqlite3.connect(d / "Cookies_copia.db")
    con.execute("CREATE TABLE cookies (host_key TEXT, name TEXT)")
    con.executemany("INSERT INTO cookies VALUES (?,?)", [("falso.test", "x")] * 400)
    con.commit()
    con.close()


def copia_bd_comprobar():
    copia_bd_crear()
    r = D.i06(_ctx(scan_dirs=[Path(tempfile.gettempdir())]))
    return r["estado"] == "alerta" and any("Cookies_copia.db" in h for h in r["hallazgos"]), r["resumen"]


def copia_bd_limpiar():
    import shutil
    shutil.rmtree(Path(tempfile.gettempdir()) / "cg_simulacion_copia", ignore_errors=True)


# ---------------------------------------------------------------- 4. entrada de arranque (Run / autostart)
def run_key_crear():
    if IS_WIN:
        import winreg
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run") as k:
            winreg.SetValueEx(k, "CookieGuardSim", 0, winreg.REG_SZ, "cmd /c echo prueba-cookieguard")
    else:
        d = Path.home() / ".config/autostart"
        d.mkdir(parents=True, exist_ok=True)
        (d / "cookieguard-sim.desktop").write_text("[Desktop Entry]\nType=Application\nName=sim\nExec=/bin/true\n")


def run_key_comprobar():
    base = sorted(D._persistence_snapshot())
    run_key_crear()
    r = D.i09(_ctx(state={"baseline_persistencia": base}))
    return r["estado"] == "alerta", r["resumen"]


def run_key_limpiar():
    if IS_WIN:
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, "CookieGuardSim")
        except OSError:
            pass
    else:
        (Path.home() / ".config/autostart/cookieguard-sim.desktop").unlink(missing_ok=True)


# ---------------------------------------------------------------- 5. extension con permiso 'cookies'
def extension_crear():
    from helpers_sim import fake_profile
    prof = fake_profile(SIM_DIR / "perfil_ext")
    ext = prof.path / "Extensions" / ("b" * 32) / "1.0_0"
    ext.mkdir(parents=True, exist_ok=True)
    (ext / "manifest.json").write_text(json.dumps({"name": "Extension de prueba CookieGuard", "version": "1.0",
                                                   "permissions": ["cookies"], "host_permissions": ["<all_urls>"]}))
    (prof.path / "Preferences").write_text(json.dumps({"extensions": {"settings": {"b" * 32: {"location": 4}}}}))
    return prof


def extension_comprobar():
    prof = extension_crear()
    c = D.Ctx(load_config(), [prof], [], {"baseline_extensiones": []}, None)
    r = D.i05(c)
    return r["estado"] == "alerta" and "cookies" in " ".join(r["hallazgos"]), r["resumen"]


def extension_limpiar():
    import shutil
    shutil.rmtree(SIM_DIR / "perfil_ext", ignore_errors=True)


# ---------------------------------------------------------------- utilidades
def _kill(pidf: Path):
    try:
        pid = int(pidf.read_text())
        if IS_WIN:
            subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
        else:
            os.kill(pid, 9)
    except (OSError, ValueError):
        pass
    pidf.unlink(missing_ok=True)


SIMS = {"acceso_fichero": (acceso_fichero_comprobar, acceso_fichero_limpiar),
        "debug_flag": (debug_flag_comprobar, debug_flag_limpiar),
        "copia_bd": (copia_bd_comprobar, copia_bd_limpiar),
        "run_key": (run_key_comprobar, run_key_limpiar),
        "extension_cookies": (extension_comprobar, extension_limpiar)}
CREAR = {"acceso_fichero": acceso_fichero_crear, "debug_flag": debug_flag_crear, "copia_bd": copia_bd_crear,
         "run_key": run_key_crear, "extension_cookies": extension_crear}


def main():
    SIM_DIR.mkdir(exist_ok=True)
    sys.path.insert(0, str(Path(__file__).parent))
    a = sys.argv[1:] or ["todas"]
    if a[0] == "todas":
        fallos = 0
        for name, (check, clean) in SIMS.items():
            try:
                ok, msg = check()
            except Exception as e:  # noqa: BLE001
                ok, msg = False, f"excepcion {type(e).__name__}: {e}"
            finally:
                clean()
            estado = "OMITIDA" if ok is None else ("OK     " if ok else "FALLO  ")
            fallos += 0 if ok in (None, True) else 1
            print(f"[{estado}] {name}: {msg}")
        import shutil
        shutil.rmtree(SIM_DIR, ignore_errors=True)
        print("Limpieza completada." + (f" {fallos} simulacion(es) con FALLO." if fallos else " Todo en verde."))
        return 1 if fallos else 0
    name, action = a[0], (a[1] if len(a) > 1 else "crear")
    (CREAR[name] if action == "crear" else SIMS[name][1])()
    print(f"{name}: {action} hecho")
    return 0


if __name__ == "__main__":
    sys.exit(main())
