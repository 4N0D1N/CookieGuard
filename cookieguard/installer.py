"""Instalacion / desinstalacion (Windows y Linux). Cada paso pregunta antes de tocar el sistema.
--dry-run muestra lo que se haria sin cambiar nada."""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

from .browsers import discover, sensitive_files
from .common import APP_ROOT, IS_WIN, data_dir, is_admin, load_state, ps, run, save_state

TASK_LOGIN = "CookieGuard-InicioSesion"
TASK_SACL = "CookieGuard-ReaplicarSACL"
AUDIT_GUID = "{0CCE921D-69AE-11D9-BED3-505054503030}"   # subcategoria "Sistema de archivos"
START_DIR_WIN = Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/CookieGuard"
APP_DIR = lambda: data_dir() / "app"  # noqa: E731


def _ask(msg: str, assume_yes: bool) -> bool:
    if assume_yes:
        print(f"[?] {msg} -> si")
        return True
    try:
        return input(f"[?] {msg} [s/N]: ").strip().lower() in ("s", "si", "y", "yes")
    except EOFError:
        return False


def _pyw() -> str:
    exe = Path(sys.executable)
    if IS_WIN:
        w = exe.with_name("pythonw.exe")
        return str(w if w.exists() else exe)
    return str(exe)


def _launcher(name: str, argv: str) -> Path:
    """Pequeno .pyw que fija la ruta de la app y lanza una orden (sin consola)."""
    p = APP_DIR() / f"{name}.pyw"
    p.write_text(f"import sys\nsys.path.insert(0, r'{APP_DIR()}')\nfrom cookieguard.__main__ import main\n"
                 f"main({argv})\n", encoding="utf-8")
    return p


def _copy_app() -> None:
    dst = APP_DIR()
    if dst.resolve() == APP_ROOT.resolve():
        return
    if dst.exists():
        shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(APP_ROOT, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "tmp", "*.zip", ".git"))


def _shortcut_win(name: str, target: str, args: str, icon_desc: str) -> None:
    START_DIR_WIN.mkdir(parents=True, exist_ok=True)
    lnk = START_DIR_WIN / f"{name}.lnk"
    ps(f"$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{lnk}');$s.TargetPath='{target}';"
       f"$s.Arguments='{args}';$s.Description='{icon_desc}';$s.WorkingDirectory='{APP_DIR()}';$s.Save()", 30)


def elevate(args: list[str]) -> int:
    """Ejecuta 'python -m cookieguard <args>' con elevacion (UAC una sola vez) y espera."""
    if is_admin():
        code, out, err = run([sys.executable, "-m", "cookieguard"] + args, 300)
        print(out + err)
        return code
    quoted = ",".join("'" + a.replace("'", "''") + "'" for a in (["-m", "cookieguard"] + args))
    code, out, err = ps(f"$p=Start-Process -FilePath '{sys.executable}' -ArgumentList {quoted} -Verb RunAs -Wait -PassThru "
                        f"-WorkingDirectory '{APP_DIR()}' -WindowStyle Hidden;exit $p.ExitCode", 600)
    return code


# ------------------------------------------------------------------ pasos con administrador (Windows)
def admin_install() -> int:
    """Audit policy + SACL + tarea que reaplica SACL. Se ejecuta ELEVADO."""
    st = load_state()
    code, out, _ = run(["auditpol", "/get", f"/subcategory:{AUDIT_GUID}", "/r"], 20)
    st["auditoria_previa"] = out.strip().splitlines()[-1] if out.strip() else ""
    run(["auditpol", "/set", f"/subcategory:{AUDIT_GUID}", "/success:enable"], 20)
    apply_sacl(st)
    save_state(st)
    run(["schtasks", "/Create", "/TN", TASK_SACL, "/SC", "ONLOGON", "/DELAY", "0001:00", "/RL", "HIGHEST", "/F", "/TR",
         f'"{_pyw()}" "{APP_DIR() / "sacl.pyw"}"'], 30)
    return 0


def apply_sacl(st: dict | None = None) -> int:
    """Pone una regla de auditoria (lectura, exito) en los ficheros sensibles de cada perfil."""
    own = st is None
    st = st if st is not None else load_state()
    files = [str(f) for f in sensitive_files(discover())]
    done = set(st.get("sacl_ficheros", []))
    for f in files:
        if f in done:
            continue
        s = ("$p='%s';$a=Get-Acl -LiteralPath $p -Audit;$r=New-Object Security.AccessControl.FileSystemAuditRule("
             "'Everyone','ReadData','Success');$a.AddAuditRule($r);Set-Acl -LiteralPath $p -AclObject $a" % f.replace("'", "''"))
        code, _, _ = ps(s, 30)
        if code == 0:
            done.add(f)
    st["sacl_ficheros"] = sorted(done)
    if own:
        save_state(st)
    return len(done)


def admin_uninstall() -> int:
    st = load_state()
    for f in st.get("sacl_ficheros", []):
        ps("$p='%s';$a=Get-Acl -LiteralPath $p -Audit;$r=New-Object Security.AccessControl.FileSystemAuditRule("
           "'Everyone','ReadData','Success');[void]$a.RemoveAuditRule($r);Set-Acl -LiteralPath $p -AclObject $a"
           % f.replace("'", "''"), 30)
    st["sacl_ficheros"] = []
    prev = st.get("auditoria_previa", "")
    if "No Auditing" in prev or "Sin auditor" in prev or not prev:
        run(["auditpol", "/set", f"/subcategory:{AUDIT_GUID}", "/success:disable", "/failure:disable"], 20)
    for n in st.get("reglas_firewall", []):
        run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={n}"], 20)
    st["reglas_firewall"] = []
    run(["schtasks", "/Delete", "/TN", TASK_SACL, "/F"], 20)
    save_state(st)
    return 0


# ------------------------------------------------------------------ instalar / desinstalar
def install(dry_run: bool = False, assume_yes: bool = False) -> int:
    print(f"== Instalacion de CookieGuard ({'SIMULACION' if dry_run else 'real'}) ==")
    steps = []

    def step(txt, fn):
        steps.append(txt)
        print(f"  -> {txt}")
        if not dry_run:
            fn()

    if not _ask(f"Copiar el programa a {APP_DIR()} y crear los lanzadores?", assume_yes):
        return 1
    step("Copiar ficheros", lambda: (_copy_app(), _launcher("login", "['login']"), _launcher("gui", "['gui']"),
                                     _launcher("vigilante", "['vigilar']"), _launcher("sacl", "['admin-sacl']"),
                                     _launcher("analizar", "['analizar']")))
    if _ask("Crear la tarea 'al iniciar sesion' (analisis automatico con notificacion)?", assume_yes):
        if IS_WIN:
            step("Tarea programada al iniciar sesion (retraso 45 s, sin ventana)", lambda: print(
                run(["schtasks", "/Create", "/TN", TASK_LOGIN, "/SC", "ONLOGON", "/DELAY", "0000:45", "/RL", "LIMITED",
                     "/F", "/TR", f'"{_pyw()}" "{APP_DIR() / "login.pyw"}"'], 30)[1:]))
        else:
            def autostart():
                d = Path.home() / ".config/autostart"
                d.mkdir(parents=True, exist_ok=True)
                (d / "cookieguard.desktop").write_text(
                    "[Desktop Entry]\nType=Application\nName=CookieGuard\nComment=Analisis de cookies al iniciar sesion\n"
                    f"Exec=sh -c 'sleep 30; {sys.executable} {APP_DIR() / 'login.pyw'}'\nX-GNOME-Autostart-enabled=true\n")
            step("Autoarranque (~/.config/autostart)", autostart)
    if _ask("Activar auditoria de acceso a ficheros del navegador (pide permisos de administrador UNA vez)?", assume_yes):
        if IS_WIN:
            step("Auditoria 'Sistema de archivos' + SACL de lectura + tarea que las reaplica (UAC)",
                 lambda: print("codigo", elevate(["admin-instalar"])))
        else:
            files = [str(f) for f in sensitive_files(discover())]
            rules = "\n".join(f"-w {f} -p r -k cookieguard" for f in files)
            print("  -> Reglas auditd (necesita sudo):\n" + rules)
            if not dry_run and shutil.which("sudo") and shutil.which("auditctl"):
                tmp = data_dir() / "tmp" / "cookieguard.rules"
                tmp.write_text(rules + "\n")
                run(["sudo", "sh", "-c", f"cp {tmp} /etc/audit/rules.d/cookieguard.rules && augenrules --load"], 120)
            elif not dry_run:
                print("     auditd/sudo no disponibles: instala auditd y guarda las reglas en /etc/audit/rules.d/")
    if IS_WIN and _ask("Instalar Sysmon con reglas/sysmon-cookieguard.xml (descarga de Microsoft, necesita administrador)?", assume_yes):
        cfgf = APP_ROOT / "reglas" / "sysmon-cookieguard.xml"
        cmd = f'winget install --id Microsoft.Sysinternals.Sysmon -e --accept-source-agreements --accept-package-agreements ; ' \
              f'$s=Get-Command sysmon64,sysmon -ErrorAction SilentlyContinue|Select -First 1; if($s){{& $s.Source -accepteula -i "{cfgf}"}}'
        step("Sysmon (winget) + configuracion", lambda: print(elevate_ps(cmd)))
    if _ask("Crear accesos directos (menu Inicio / aplicaciones)?", assume_yes):
        if IS_WIN:
            step("Accesos directos en el menu Inicio", lambda: (
                _shortcut_win("CookieGuard", _pyw(), f'\\"{APP_DIR() / "gui.pyw"}\\"', "Abrir CookieGuard"),
                _shortcut_win("Analizar ahora", _pyw(), f'\\"{APP_DIR() / "analizar.pyw"}\\"', "Analizar ahora")))
        else:
            def desk():
                d = Path.home() / ".local/share/applications"
                d.mkdir(parents=True, exist_ok=True)
                (d / "cookieguard.desktop").write_text(
                    f"[Desktop Entry]\nType=Application\nName=CookieGuard\nExec={sys.executable} {APP_DIR() / 'gui.pyw'}\n"
                    "Categories=Security;\nTerminal=false\n")
            step("Entrada en el menu de aplicaciones", desk)
    if not dry_run:
        print("  -> Primer analisis (fija la linea base)...")
        from .engine import run_login
        r = run_login(open_report=False, notify_user=True)
        print(f"     Semaforo {r['veredicto']['nombre']}. Informe: {r['informe']}")
    print("Listo. Cierra sesion y vuelve a entrar: el analisis se lanzara solo." if not dry_run else "Simulacion terminada.")
    return 0


def elevate_ps(cmd: str) -> int:
    if is_admin():
        return ps(cmd, 600)[0]
    code, _, _ = ps(f"Start-Process powershell -Verb RunAs -Wait -WindowStyle Hidden -ArgumentList '-NoProfile','-Command',"
                    f"'{cmd.replace(chr(39), chr(39) * 2)}'", 900)
    return code


def uninstall(dry_run: bool = False, assume_yes: bool = False) -> int:
    print(f"== Desinstalacion de CookieGuard ({'SIMULACION' if dry_run else 'real'}) ==")
    keep = _ask("Conservar los informes y copias de seguridad de cookies?", assume_yes)

    def do(txt, fn):
        print(f"  -> {txt}")
        if not dry_run:
            try:
                fn()
            except Exception as e:  # noqa: BLE001
                print("     aviso:", e)

    if IS_WIN:
        do("Borrar tarea de inicio de sesion", lambda: run(["schtasks", "/Delete", "/TN", TASK_LOGIN, "/F"], 20))
        do("Quitar auditoria, SACL, reglas de firewall y tarea SACL (UAC)", lambda: elevate(["admin-desinstalar"]))
        if _ask("Desinstalar tambien Sysmon?", assume_yes):
            do("Desinstalar Sysmon", lambda: elevate_ps("$s=Get-Command sysmon64,sysmon -ErrorAction SilentlyContinue|Select -First 1;"
                                                         "if($s){& $s.Source -u force}"))
        do("Quitar accesos directos", lambda: shutil.rmtree(START_DIR_WIN, ignore_errors=True))
    else:
        for f in (Path.home() / ".config/autostart/cookieguard.desktop",
                  Path.home() / ".local/share/applications/cookieguard.desktop"):
            do(f"Borrar {f}", lambda f=f: f.unlink(missing_ok=True))
        if shutil.which("sudo") and Path("/etc/audit/rules.d/cookieguard.rules").exists():
            do("Quitar reglas auditd (sudo)", lambda: run(["sudo", "sh", "-c",
                                                          "rm -f /etc/audit/rules.d/cookieguard.rules && augenrules --load"], 60))
    pidf = data_dir() / "vigilante.pid"
    if pidf.exists():
        do("Parar el vigilante", lambda: run(["taskkill", "/PID", pidf.read_text().strip(), "/F"], 10) if IS_WIN
           else run(["kill", pidf.read_text().strip()], 10))
    do("Borrar el programa instalado", lambda: shutil.rmtree(APP_DIR(), ignore_errors=True))
    if not keep:
        do("Borrar informes, copias y estado", lambda: shutil.rmtree(data_dir(), ignore_errors=True))
    print("Desinstalacion terminada." if not dry_run else "Simulacion terminada.")
    return 0
