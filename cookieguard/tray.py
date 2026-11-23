"""Módulo de icono en bandeja del sistema (System Tray) y vigilante continuo.

Soporta icono interactivo mediante pystray + Pillow si están disponibles,
y fallback automático a modo daemon silencioso con notificaciones nativas de escritorio.
"""
from __future__ import annotations

import threading
import time
import webbrowser
from typing import Callable

from .actions import enable_killswitch, disable_killswitch
from .canary import plant_all_profiles
from .common import IS_WIN, IS_LINUX, log, data_dir


def has_pystray() -> bool:
    try:
        import pystray  # noqa: F401
        from PIL import Image  # noqa: F401
        return True
    except ImportError:
        return False


def open_last_report():
    report_file = data_dir() / "informe.html"
    if report_file.is_file():
        webbrowser.open(report_file.as_uri())
    else:
        log("No hay informe generado todavia.")


def _create_default_icon_image():
    """Genera un icono circular de CookieGuard en memoria si PIL esta presente."""
    try:
        from PIL import Image, ImageDraw
        img = Image.new("RGBA", (64, 64), color=(0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        # Escudo azul/cyan
        draw.ellipse([4, 4, 60, 60], fill=(14, 165, 233, 255), outline=(255, 255, 255, 255), width=2)
        # Punto blanco de cookie
        draw.ellipse([26, 26, 38, 38], fill=(255, 255, 255, 255))
        return img
    except Exception:
        return None


class TrayApp:
    def __init__(self, on_analyze: Callable | None = None):
        self.on_analyze = on_analyze
        self.icon = None
        self._running = False

    def run(self):
        if not has_pystray():
            log("pystray o Pillow no disponibles; ejecutando vigilante en modo daemon en segundo plano")
            self._run_daemon_loop()
            return

        import pystray
        image = _create_default_icon_image()
        if not image:
            self._run_daemon_loop()
            return

        menu = pystray.Menu(
            pystray.MenuItem("CookieGuard v1.2.0", lambda: None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("🔍 Analizar ahora", self._action_analyze),
            pystray.MenuItem("📊 Ver último informe", lambda: open_last_report()),
            pystray.MenuItem("🪤 Sembrar Canary Cookies", lambda: plant_all_profiles()),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("🚨 Aislar Red (Killswitch)", lambda: enable_killswitch()),
            pystray.MenuItem("🌐 Restaurar Red", lambda: disable_killswitch()),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("❌ Salir", self._action_exit),
        )

        self.icon = pystray.Icon("cookieguard", image, "CookieGuard - Vigilante de Sesiones", menu)
        self._running = True
        self.icon.run()

    def _action_analyze(self):
        if self.on_analyze:
            threading.Thread(target=self.on_analyze, daemon=True).start()
        else:
            from .engine import run_audit
            threading.Thread(target=run_audit, daemon=True).start()

    def _action_exit(self):
        self._running = False
        if self.icon:
            self.icon.stop()

    def _run_daemon_loop(self):
        self._running = True
        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            self._running = False
            log("Vigilante en segundo plano detenido por el usuario")


def start_tray():
    app = TrayApp()
    app.run()


if __name__ == "__main__":
    start_tray()
