"""Notificaciones: toast nativo de Windows (WinRT) o globo de bandeja; notify-send en Linux."""
from __future__ import annotations

import os
import shutil
import subprocess

from .common import IS_WIN, log, run

_TOAST_PS = r"""
$ErrorActionPreference='Stop'
[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime]
[void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType=WindowsRuntime]
$t=[Security.SecurityElement]::Escape($env:CG_TITLE); $m=[Security.SecurityElement]::Escape($env:CG_MSG)
$u=[Security.SecurityElement]::Escape($env:CG_URL)
$act=''; if($u){ $act="<actions><action content='Abrir informe' arguments='$u' activationType='protocol'/></actions>" }
$xml=New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml("<toast scenario='reminder'><visual><binding template='ToastGeneric'><text>$t</text><text>$m</text></binding></visual>$act</toast>")
$id='{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($id).Show([Windows.UI.Notifications.ToastNotification]::new($xml))
"""

_BALLOON_PS = r"""
Add-Type -AssemblyName System.Windows.Forms
$n=New-Object System.Windows.Forms.NotifyIcon
$n.Icon=[System.Drawing.SystemIcons]::Shield; $n.Visible=$true
$n.ShowBalloonTip(8000,$env:CG_TITLE,$env:CG_MSG,'Warning'); Start-Sleep -Seconds 9; $n.Dispose()
"""


def notify(title: str, message: str, report_path=None, nivel: str = "verde") -> str:
    """Devuelve el metodo usado ('toast', 'globo', 'notify-send', 'consola')."""
    env = dict(os.environ, CG_TITLE=title, CG_MSG=message, CG_URL=(report_path.as_uri() if report_path else ""))
    try:
        if IS_WIN:
            kw = {"creationflags": 0x08000000, "env": env, "capture_output": True, "timeout": 20}
            cmd = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"]
            p = subprocess.run(cmd + [_TOAST_PS], **kw)
            if p.returncode == 0:
                return "toast"
            log("toast fallo, uso globo de bandeja")
            subprocess.Popen(cmd + [_BALLOON_PS], creationflags=0x08000000, env=env, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
            return "globo"
        if shutil.which("notify-send"):
            urg = "critical" if nivel == "rojo" else "normal"
            run(["notify-send", "-a", "CookieGuard", "-u", urg, title, message], 10)
            return "notify-send"
    except Exception as e:  # noqa: BLE001
        log(f"notificacion fallo: {e}")
    print(f"[CookieGuard] {title}: {message}")
    return "consola"
