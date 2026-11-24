"""Guardián ligero en segundo plano con escaneos periódicos locales.

No se afirma un consumo fijo ni protección completa: el coste depende del sistema,
permisos y herramientas disponibles. Las señales son heurísticas y requieren revisión.
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .clipboard_audit import audit_clipboard
from .common import data_dir, log
from .notify import notify
from .process_hunter import scan_processes
from .unpacked_extension_audit import audit_running_browser_flags


class GuardianMonitor:
    """Monitor opcional en segundo plano; no realiza contención ni cambios en el host."""
    def __init__(self, interval_seconds: int = 15, enable_clipboard_check: bool = False,
                 on_alert: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.interval = max(10, int(interval_seconds))
        self.enable_clipboard = enable_clipboard_check
        self.on_alert = on_alert
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._status_file = data_dir() / "guardian_status.json"
        self._seen_alert_keys: set[str] = set()
        self.stats = {"rondas_ejecutadas": 0, "alertas_emitidas": 0, "ultimo_escaneo": None, "estado": "detenido"}

    def check_once(self) -> List[Dict[str, Any]]:
        alerts: List[Dict[str, Any]] = []
        try:
            result = scan_processes()
            for item in result.get("sospechosos", []):
                alerts.append({"tipo": "proceso_sospechoso", "nivel": item.get("severidad", "ALTA"),
                               "titulo": f"Proceso a revisar: {item.get('name', 'desconocido')}",
                               "detalle": item.get("motivo", "Indicador heurístico"), "pid": item.get("pid"),
                               "clave": f"proc_{item.get('pid')}_{item.get('name')}"})
        except Exception as exc:
            log(f"Guardian: error en escaneo de procesos: {exc}")
        try:
            for item in audit_running_browser_flags():
                alerts.append({"tipo": "flag_navegador", "nivel": item.get("nivel", "ALTA"),
                               "titulo": f"Argumento de navegador a revisar: {item.get('proceso')}",
                               "detalle": f"{item.get('flag')} (PID {item.get('pid')})", "pid": item.get("pid"),
                               "clave": f"flag_{item.get('pid')}_{item.get('flag')}"})
        except Exception as exc:
            log(f"Guardian: error en revisión de argumentos: {exc}")
        if self.enable_clipboard:
            try:
                result = audit_clipboard()
                if result.get("has_alerts"):
                    kinds = ", ".join(a.get("tipo", "patrón") for a in result.get("alertas", [])[:2])
                    alerts.append({"tipo": "portapapeles", "nivel": "ALTA",
                                   "titulo": "El portapapeles contiene un patrón sensible",
                                   "detalle": f"Revisa el contenido localmente. Categorías: {kinds}",
                                   "clave": f"clipboard_{int(time.time() // 60)}"})
            except Exception as exc:
                log(f"Guardian: error en auditoría de portapapeles: {exc}")

        self.stats["rondas_ejecutadas"] += 1
        self.stats["ultimo_escaneo"] = datetime.now(timezone.utc).isoformat()
        for alert in alerts:
            key = alert["clave"]
            if key in self._seen_alert_keys:
                continue
            self._seen_alert_keys.add(key)
            self.stats["alertas_emitidas"] += 1
            try:
                notify("CookieGuard: " + alert["titulo"], alert["detalle"])
            except Exception as exc:
                log(f"Guardian: no se pudo notificar: {exc}")
            if self.on_alert:
                try:
                    self.on_alert(alert)
                except Exception as exc:
                    log(f"Guardian: callback de alerta falló: {exc}")
        self._save_status()
        return alerts

    def _save_status(self):
        try:
            self._status_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._status_file.with_suffix(".tmp")
            tmp.write_text(json.dumps({"activo": self._running, "intervalo_segundos": self.interval,
                                      "stats": self.stats, "pid": os.getpid()}, indent=2), encoding="utf-8")
            tmp.replace(self._status_file)
        except OSError as exc:
            log(f"Guardian: no se pudo actualizar el estado: {exc}")

    def start(self, blocking: bool = False):
        if self._running:
            return
        self._running = True
        self.stats["estado"] = "vigilando"
        self._stop_event.clear()
        self._save_status()
        log(f"Guardián iniciado; intervalo {self.interval}s.")
        if blocking:
            self._loop()
        else:
            self._thread = threading.Thread(target=self._loop, daemon=True, name="CookieGuardGuardian")
            self._thread.start()

    def _loop(self):
        while self._running and not self._stop_event.is_set():
            self.check_once()
            self._stop_event.wait(self.interval)

    def stop(self):
        self._running = False
        self._stop_event.set()
        self.stats["estado"] = "detenido"
        self._save_status()
        log("Guardián detenido.")


_active_guardian: Optional[GuardianMonitor] = None


def get_guardian(interval_seconds: int = 15) -> GuardianMonitor:
    global _active_guardian
    if _active_guardian is None:
        _active_guardian = GuardianMonitor(interval_seconds=interval_seconds)
    return _active_guardian


def start_guardian_daemon(interval_seconds: int = 15, blocking: bool = False) -> GuardianMonitor:
    guardian = get_guardian(interval_seconds)
    guardian.start(blocking=blocking)
    return guardian
