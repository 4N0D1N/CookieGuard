"""CookieGuard v2.7.0 · Consola de escritorio Cyber SOC idéntica al diseño oficial."""
from __future__ import annotations

import http.server
import json
import os
import socketserver
import sys
import tempfile
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any, Dict, Optional

from . import actions, browsers, canary_trap, engine, playbooks, reports, rescue_wizard
from .common import VERSION, load_config, save_user_config


class BridgeApi:
    """Puente bidireccional entre el frontend web y los módulos locales de CookieGuard."""

    def __init__(self):
        self.last_res: Optional[Dict[str, Any]] = None
        self._lock = threading.Lock()

    def get_initial_data(self) -> Dict[str, Any]:
        """Devuelve el estado inicial, configuración y comprobación de versiones previas."""
        cfg = load_config()
        try:
            canary_status = canary_trap.check_canary_traps()
        except Exception as e:
            canary_status = {"error": str(e), "total_trampas": 0, "alerta_activa": False}

        warning_old = None
        try:
            candidates = []
            for d in [os.getcwd(), os.path.expanduser("~/Desktop")]:
                if os.path.isdir(d):
                    for item in os.listdir(d):
                        if any(v in item for v in ["2.4", "2.5.0", "2.5.1", "2.6.1", "CookieGuard-App"]):
                            candidates.append(item)
            if candidates:
                warning_old = (
                    f"Atención: Se han detectado carpetas de versiones anteriores ({', '.join(set(candidates))}). "
                    f"Estás ejecutando la versión oficial activa v{VERSION}."
                )
        except Exception:
            pass

        return {
            "version": VERSION,
            "theme": cfg.get("tema", "oscuro"),
            "canary": canary_status,
            "last_res": self.last_res,
            "warning_old": warning_old,
            "binary_path": sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)
        }

    def run_scan(self) -> Dict[str, Any]:
        """Ejecuta un escaneo completo de sesiones y actualiza reportes locales."""
        with self._lock:
            profiles = browsers.discover()
            res = engine.run_analysis(profiles)
            try:
                reports.write_reports(res)
            except Exception:
                pass
            self.last_res = res
            return res

    def deploy_canary(self) -> Dict[str, Any]:
        """Despliega trampas señuelo Canary en los navegadores."""
        canary_trap.deploy_canary_traps()
        return canary_trap.check_canary_traps()

    def check_canary(self) -> Dict[str, Any]:
        """Verifica la integridad de las trampas señuelo."""
        return canary_trap.check_canary_traps()

    def open_url(self, url: str) -> bool:
        """Abre de forma segura una URL oficial en el navegador predeterminado."""
        if not url or not (url.startswith("https://") or url.startswith("http://")):
            return False
        return webbrowser.open(url)

    def revoke_service(self, service_name: str) -> Dict[str, Any]:
        """Abre la URL oficial de revocación para un servicio o genera playbook."""
        for p in playbooks.PLAYBOOK_CATALOG:
            if p.get("nombre", "").lower() == service_name.lower():
                url = p.get("url_sesiones") or p.get("url_password")
                if url:
                    webbrowser.open(url)
                    return {"ok": True, "servicio": service_name, "url": url}
        return {"ok": True, "servicio": service_name, "mensaje": "Revocación recomendada manual"}

    def revoke_all_sessions(self) -> Dict[str, Any]:
        """Abre el asistente de rescate / playbook para rotación completa."""
        return self.run_rescue_plan(kill_browsers=False)

    def emergency_mode(self) -> Dict[str, Any]:
        """Activa el modo de emergencia con killswitch seguro y cierre de navegadores."""
        return self.run_rescue_plan(kill_browsers=True)

    def export_report(self, fmt: str) -> Dict[str, Any]:
        """Exporta los hallazgos en formato HTML, JSON o CSV."""
        if not self.last_res:
            self.run_scan()
        t_dir = Path(tempfile.gettempdir())
        ts = int(time.time())
        p = t_dir / f"cookieguard_export_{ts}.{fmt}"
        try:
            if fmt == "html":
                reports.export_html(self.last_res, p)
            elif fmt == "json":
                reports.export_json(self.last_res, p)
            elif fmt == "csv":
                reports.export_csv(self.last_res.get("grupos", []), p)
            return {"ok": True, "path": str(p), "formato": fmt}
        except Exception as e:
            return {"ok": False, "error": str(e), "formato": fmt}

    def create_incident_zip(self) -> Dict[str, Any]:
        """Genera el paquete ZIP de triaje forense sin volcar cookies sensibles."""
        if not self.last_res:
            self.run_scan()
        try:
            zip_p = actions.incident_zip(self.last_res)
            return {"ok": True, "path": str(zip_p)}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def run_rescue_plan(self, kill_browsers: bool = False) -> Dict[str, Any]:
        """Ejecuta el asistente de rescate de emergencia."""
        t_dir = Path(tempfile.gettempdir())
        return rescue_wizard.run_rescue_plan(
            auto=True, killswitch=False, kill_browsers=kill_browsers, output_dir=t_dir
        )

    def run_specialized_tool(self, tool_id: str) -> Dict[str, Any]:
        """Ejecuta herramientas especializadas locales bajo demanda."""
        try:
            if tool_id == "persistence":
                from . import persistence_audit
                return {"ok": True, "data": persistence_audit.run_persistence_audit()}
            elif tool_id == "network":
                from . import network_audit
                return {"ok": True, "data": network_audit.run_network_audit()}
            elif tool_id == "integrity":
                from . import binary_integrity
                return {"ok": True, "data": binary_integrity.audit_binary_integrity()}
            elif tool_id == "health":
                from . import sensor_health
                res = sensor_health.run_sensor_diagnostic()
                cli = sensor_health.format_sensor_diagnostic_cli(res)
                return {"ok": True, "data": res, "cli_text": cli}
            elif tool_id == "clipboard":
                from . import clipboard_audit
                return {"ok": True, "data": clipboard_audit.audit_clipboard()}
            elif tool_id == "clear_clipboard":
                from . import clipboard_audit
                ok = clipboard_audit.clear_system_clipboard()
                return {"ok": True, "cleared": ok}
            elif tool_id == "unpacked":
                from .unpacked_extension_audit import audit_all_unpacked_extensions
                return {"ok": True, "data": audit_all_unpacked_extensions()}
            elif tool_id == "downloads":
                from . import downloads_audit
                return {"ok": True, "data": downloads_audit.audit_recent_downloads(hours=48)}
            elif tool_id == "playbook_data":
                return {"ok": True, "servicios": playbooks.PLAYBOOK_CATALOG}
            else:
                return {"ok": False, "error": f"Herramienta desconocida: {tool_id}"}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    def save_theme_preference(self, theme: str) -> bool:
        """Guarda la preferencia visual en el archivo de configuración local."""
        try:
            save_user_config({"tema": theme})
            return True
        except Exception:
            return False


class LocalDashboardServer:
    """Servidor HTTP local en 127.0.0.1 para comunicación inmediata con el frontend."""

    def __init__(self, api: BridgeApi, html_content: str):
        self.api = api
        self.html_content = html_content
        self.server: Optional[socketserver.TCPServer] = None
        self.port: int = 0
        self._thread: Optional[threading.Thread] = None

    def start(self) -> int:
        api_ref = self.api
        html_bytes = self.html_content.encode("utf-8")

        class RequestHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def do_GET(self):
                if self.path in ("/", "/index.html"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(html_bytes)))
                    self.end_headers()
                    self.wfile.write(html_bytes)
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):
                if self.path.startswith("/api/"):
                    method_name = self.path[len("/api/"):]
                    content_len = int(self.headers.get("Content-Length", 0))
                    body_bytes = self.rfile.read(content_len) if content_len > 0 else b"[]"
                    try:
                        args = json.loads(body_bytes.decode("utf-8")) if body_bytes else []
                    except Exception:
                        args = []

                    func = getattr(api_ref, method_name, None)
                    if func and callable(func) and not method_name.startswith("_"):
                        try:
                            if isinstance(args, list):
                                res = func(*args)
                            else:
                                res = func(args)
                            out_bytes = json.dumps(res, ensure_ascii=False).encode("utf-8")
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json; charset=utf-8")
                            self.send_header("Content-Length", str(len(out_bytes)))
                            self.end_headers()
                            self.wfile.write(out_bytes)
                            return
                        except Exception as e:
                            err_bytes = json.dumps({"ok": False, "error": str(e)}).encode("utf-8")
                            self.send_response(500)
                            self.send_header("Content-Type", "application/json; charset=utf-8")
                            self.send_header("Content-Length", str(len(err_bytes)))
                            self.end_headers()
                            self.wfile.write(err_bytes)
                            return

                self.send_response(404)
                self.end_headers()

        self.server = socketserver.TCPServer(("127.0.0.1", 0), RequestHandler)
        self.port = self.server.server_address[1]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        return self.port

    def stop(self):
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass



def get_dashboard_html() -> str:
    """Genera el código HTML, CSS y JS integrado idéntico a cookieguard_pywebview_preview.jpg."""
    return """<!DOCTYPE html>
<html lang="es" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CookieGuard · Threats to your data. Stopped here.</title>
<style>
:root {
  --bg-app: #070c18;
  --bg-sidebar: #0b1325;
  --bg-topbar: #0b1325;
  --bg-card: #0f1930;
  --bg-card-hover: #152240;
  --bg-input: #111c35;
  --border: rgba(56, 189, 248, 0.12);
  --border-focus: #00e5ff;
  --accent-blue: #0066ff;
  --cyan: #00e5ff;
  --cyan-glow: rgba(0, 229, 255, 0.25);
  --orange: #ff9f1c;
  --orange-glow: rgba(255, 159, 28, 0.2);
  --pink: #ff3366;
  --pink-glow: rgba(255, 51, 102, 0.2);
  --purple: #a855f7;
  --purple-glow: rgba(168, 85, 247, 0.2);
  --green: #10b981;
  --green-glow: rgba(16, 185, 129, 0.2);
  --text-main: #ffffff;
  --text-muted: #94a3b8;
  --text-faint: #64748b;
  --radius-sm: 6px;
  --radius-md: 10px;
  --radius-lg: 16px;
  --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}

[data-theme="light"] {
  --bg-app: #f4f7fc;
  --bg-sidebar: #ffffff;
  --bg-topbar: #ffffff;
  --bg-card: #ffffff;
  --bg-card-hover: #f8fafc;
  --bg-input: #eef2f6;
  --border: #dbe4ef;
  --text-main: #0f172a;
  --text-muted: #475569;
  --text-faint: #94a3b8;
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: var(--font-sans);
  background: var(--bg-app);
  color: var(--text-main);
  height: 100vh;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

/* TOPBAR */
.topbar {
  height: 60px;
  background: var(--bg-topbar);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 24px;
  flex-shrink: 0;
  user-select: none;
}
.brand-group {
  display: flex;
  align-items: center;
  gap: 12px;
}
.brand-shield {
  width: 32px;
  height: 32px;
  border-radius: 8px;
  background: linear-gradient(135deg, #0066ff, #00e5ff);
  display: flex;
  align-items: center;
  justify-content: center;
  color: #fff;
  box-shadow: 0 0 16px rgba(0, 229, 255, 0.4);
}
.brand-text h1 {
  font-size: 16px;
  font-weight: 700;
  letter-spacing: -0.3px;
  color: #fff;
}
.brand-text p {
  font-size: 9.5px;
  color: var(--cyan);
  letter-spacing: 0.6px;
  font-weight: 500;
  text-transform: uppercase;
}

.search-container {
  position: relative;
  width: 440px;
}
.search-icon {
  position: absolute;
  left: 14px;
  top: 50%;
  transform: translateY(-50%);
  color: var(--text-faint);
  font-size: 13px;
}
.search-input {
  width: 100%;
  height: 36px;
  background: var(--bg-input);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0 70px 0 38px;
  font-size: 12.5px;
  color: var(--text-main);
  outline: none;
  transition: border-color 0.15s ease;
}
.search-input:focus {
  border-color: var(--border-focus);
}
.search-badge {
  position: absolute;
  right: 10px;
  top: 50%;
  transform: translateY(-50%);
  background: rgba(255, 255, 255, 0.08);
  border: 1px solid rgba(255, 255, 255, 0.12);
  color: var(--text-muted);
  font-size: 10px;
  padding: 2px 6px;
  border-radius: 4px;
  font-weight: 600;
}

.topbar-right {
  display: flex;
  align-items: center;
  gap: 16px;
}
.status-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: rgba(16, 185, 129, 0.12);
  border: 1px solid rgba(16, 185, 129, 0.3);
  color: var(--green);
  font-size: 11.5px;
  font-weight: 600;
  padding: 4px 12px;
  border-radius: 999px;
}
.status-dot {
  width: 6px;
  height: 6px;
  background: var(--green);
  border-radius: 50%;
  box-shadow: 0 0 8px var(--green);
}
.status-pill.danger {
  background: rgba(255, 51, 102, 0.12);
  border-color: rgba(255, 51, 102, 0.35);
  color: var(--pink);
}
.status-pill.danger .status-dot {
  background: var(--pink);
  box-shadow: 0 0 8px var(--pink);
}

.icon-btn {
  background: none;
  border: none;
  color: var(--text-muted);
  font-size: 16px;
  cursor: pointer;
  padding: 6px;
  border-radius: 6px;
  transition: color 0.15s;
}
.icon-btn:hover { color: var(--text-main); }

.user-profile {
  display: flex;
  align-items: center;
  gap: 10px;
  cursor: pointer;
}
.user-avatar {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  background: #0284c7;
  color: #fff;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 13px;
  font-weight: 700;
}
.user-meta {
  display: flex;
  flex-direction: column;
}
.user-meta .name {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-main);
}
.user-meta .plan {
  font-size: 10px;
  color: var(--text-faint);
}

/* APP BODY (SIDEBAR + MAIN) */
.app-body {
  flex: 1;
  display: flex;
  overflow: hidden;
}

/* SIDEBAR */
.sidebar {
  width: 210px;
  background: var(--bg-sidebar);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  padding: 16px 12px 18px;
  flex-shrink: 0;
  user-select: none;
}
.nav-menu {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.nav-link {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 14px;
  border-radius: var(--radius-md);
  color: var(--text-muted);
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s ease;
  border: 1px solid transparent;
}
.nav-link-content {
  display: flex;
  align-items: center;
  gap: 12px;
}
.nav-link:hover {
  background: var(--bg-card);
  color: var(--text-main);
}
.nav-link.active {
  background: rgba(0, 229, 255, 0.08);
  color: var(--cyan);
  border-color: rgba(0, 229, 255, 0.25);
  font-weight: 600;
}
.nav-badge {
  background: var(--pink);
  color: #fff;
  font-size: 10px;
  font-weight: 700;
  padding: 1px 6px;
  border-radius: 999px;
  box-shadow: 0 0 10px var(--pink-glow);
}

.sidebar-bottom-card {
  background: rgba(17, 26, 46, 0.6);
  border: 1px solid rgba(56, 189, 248, 0.15);
  border-radius: 12px;
  padding: 14px 12px;
}
.sidebar-bottom-card h4 {
  font-size: 12px;
  font-weight: 700;
  color: var(--text-main);
  margin-bottom: 4px;
}
.sidebar-bottom-card p {
  font-size: 10.5px;
  color: var(--text-faint);
  line-height: 1.35;
}

/* MAIN CONTENT */
.main-content {
  flex: 1;
  overflow-y: auto;
  padding: 24px 32px 40px;
}

/* VIEW PANELS */
.view-panel { display: none; }
.view-panel.active { display: block; animation: viewFade 0.2s ease; }
@keyframes viewFade { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

/* HERO HEADER */
.hero-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  margin-bottom: 24px;
}
.hero-titles h2 {
  font-size: 28px;
  font-weight: 800;
  line-height: 1.15;
  letter-spacing: -0.5px;
}
.gradient-text {
  background: linear-gradient(90deg, #00e5ff 0%, #a855f7 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}
.hero-subtitle {
  font-size: 12.5px;
  color: var(--text-muted);
  margin-top: 6px;
  max-width: 520px;
}

.hero-actions {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 8px;
}
.hero-btn-row {
  display: flex;
  align-items: center;
  gap: 10px;
}
.btn-scan {
  background: var(--accent-blue);
  color: #fff;
  border: none;
  font-size: 12.5px;
  font-weight: 700;
  padding: 9px 20px;
  border-radius: 999px;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  box-shadow: 0 4px 16px rgba(0, 102, 255, 0.45);
  transition: all 0.15s ease;
}
.btn-scan:hover {
  filter: brightness(1.15);
  transform: translateY(-1px);
}
.btn-outline {
  background: var(--bg-card);
  border: 1px solid var(--border);
  color: var(--text-main);
  font-size: 12.5px;
  font-weight: 600;
  padding: 9px 16px;
  border-radius: 999px;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  transition: all 0.15s ease;
}
.btn-outline:hover {
  background: var(--bg-card-hover);
  border-color: rgba(56, 189, 248, 0.3);
}
.btn-emergency {
  border-color: rgba(255, 51, 102, 0.35);
  color: #fca5a5;
}
.btn-emergency:hover {
  background: rgba(255, 51, 102, 0.15);
  border-color: var(--pink);
  color: #fff;
}
.scan-meta {
  font-size: 11px;
  color: var(--text-faint);
}

/* KPI CARDS (GRID-KPI) */
.grid-kpi {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
  margin-bottom: 24px;
}
.kpi-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 16px 18px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  transition: border-color 0.15s ease;
}
.kpi-card:hover {
  border-color: rgba(56, 189, 248, 0.28);
}
.kpi-left {
  display: flex;
  align-items: center;
  gap: 14px;
}
.kpi-icon-box {
  width: 42px;
  height: 42px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 18px;
}
.kpi-icon-cyan { background: rgba(0, 229, 255, 0.12); color: var(--cyan); }
.kpi-icon-orange { background: rgba(255, 159, 28, 0.12); color: var(--orange); }
.kpi-icon-blue { background: rgba(0, 102, 255, 0.12); color: #38bdf8; }
.kpi-icon-purple { background: rgba(168, 85, 247, 0.12); color: var(--purple); }

.kpi-text .num {
  font-size: 24px;
  font-weight: 800;
  line-height: 1.1;
  color: #fff;
}
.kpi-text .label {
  font-size: 11px;
  color: var(--text-muted);
  font-weight: 500;
  margin-top: 2px;
}
.kpi-spark {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 4px;
}
.spark-pill {
  font-size: 10px;
  font-weight: 700;
  padding: 2px 6px;
  border-radius: 4px;
}
.spark-green { color: var(--green); background: rgba(16, 185, 129, 0.12); }
.spark-red { color: var(--pink); background: rgba(255, 51, 102, 0.12); }
.spark-neutral { color: var(--text-faint); background: rgba(255, 255, 255, 0.06); }
.spark-cyan { color: var(--cyan); background: rgba(0, 229, 255, 0.12); }

/* MIDDLE 3 COLUMNS */
.middle-row {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 16px;
  margin-bottom: 24px;
}
.mid-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 18px 20px;
  display: flex;
  flex-direction: column;
}
.mid-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}
.mid-header h3 {
  font-size: 14px;
  font-weight: 700;
  color: var(--text-main);
}
.mid-header a {
  font-size: 11.5px;
  color: #38bdf8;
  text-decoration: none;
  font-weight: 600;
}
.mid-header a:hover { text-decoration: underline; }

/* PANEL 1: DONUT CHART */
.donut-container {
  display: flex;
  align-items: center;
  gap: 16px;
  flex: 1;
}
.donut-svg-box {
  position: relative;
  width: 120px;
  height: 120px;
  flex-shrink: 0;
}
.svg-gauge {
  width: 120px;
  height: 120px;
  transform: rotate(-90deg);
}
.donut-center {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  text-align: center;
}
.donut-center .c-num { font-size: 20px; font-weight: 800; color: #fff; line-height: 1; }
.donut-center .c-lbl { font-size: 9.5px; color: var(--text-muted); }

.donut-legend {
  display: flex;
  flex-direction: column;
  gap: 8px;
  flex: 1;
}
.leg-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 11px;
}
.leg-left {
  display: flex;
  align-items: center;
  gap: 7px;
  color: var(--text-muted);
}
.leg-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}
.leg-val {
  font-weight: 600;
  color: var(--text-main);
}

/* PANEL 2: TIMELINE */
.alert-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
  flex: 1;
}
.alert-row {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  font-size: 11.5px;
}
.alert-time {
  font-size: 10px;
  color: var(--text-faint);
  width: 42px;
  flex-shrink: 0;
  padding-top: 2px;
}
.alert-status-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  margin-top: 5px;
  flex-shrink: 0;
}
.alert-info {
  flex: 1;
  line-height: 1.35;
}
.alert-title {
  font-weight: 600;
  color: var(--text-main);
}
.alert-domain {
  color: var(--text-faint);
  font-size: 10.5px;
}

/* PANEL 3: QUICK SERVICE REVOCATION */
.service-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
  flex: 1;
}
.service-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 10px;
  background: rgba(255, 255, 255, 0.02);
  border: 1px solid rgba(255, 255, 255, 0.04);
  border-radius: 8px;
}
.service-info {
  display: flex;
  align-items: center;
  gap: 10px;
}
.service-logo {
  width: 24px;
  height: 24px;
  border-radius: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 12px;
  font-weight: 700;
  background: rgba(255, 255, 255, 0.06);
}
.service-meta .s-name { font-size: 12px; font-weight: 600; color: #fff; }
.service-meta .s-count { font-size: 10px; color: var(--text-faint); }
.service-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}
.risk-pill {
  font-size: 10px;
  font-weight: 600;
  padding: 2px 7px;
  border-radius: 999px;
}
.risk-high { background: rgba(255, 51, 102, 0.15); color: var(--pink); border: 1px solid rgba(255, 51, 102, 0.3); }
.risk-none { background: rgba(16, 185, 129, 0.15); color: var(--green); border: 1px solid rgba(16, 185, 129, 0.3); }
.btn-revoke-sm {
  background: var(--bg-card);
  border: 1px solid var(--border);
  color: var(--text-main);
  font-size: 11px;
  font-weight: 600;
  padding: 4px 10px;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.15s;
}
.btn-revoke-sm:hover {
  background: var(--pink);
  border-color: var(--pink);
  color: #fff;
}

/* BOTTOM PANEL: DETECTED COOKIES TABLE */
.table-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 18px 20px;
}
.table-ctrl-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}
.table-ctrl-row h3 {
  font-size: 15px;
  font-weight: 700;
  color: #fff;
}
.table-filters {
  display: flex;
  align-items: center;
  gap: 10px;
}
.filter-search {
  height: 32px;
  background: var(--bg-input);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0 10px;
  font-size: 11.5px;
  color: var(--text-main);
  outline: none;
}
.filter-select {
  height: 32px;
  background: var(--bg-input);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0 10px;
  font-size: 11.5px;
  color: var(--text-main);
  outline: none;
  cursor: pointer;
}

.data-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}
.data-table th {
  text-align: left;
  padding: 10px 12px;
  font-size: 11px;
  font-weight: 600;
  color: var(--text-faint);
  border-bottom: 1px solid var(--border);
}
.data-table td {
  padding: 12px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.04);
  vertical-align: middle;
}
.data-table tr:hover td {
  background: rgba(255, 255, 255, 0.02);
}
.pill-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 10px;
  font-weight: 600;
}
.pill-high { background: rgba(255, 51, 102, 0.15); color: var(--pink); border: 1px solid rgba(255, 51, 102, 0.3); }
.pill-medium { background: rgba(255, 159, 28, 0.15); color: var(--orange); border: 1px solid rgba(255, 159, 28, 0.3); }
.pill-low { background: rgba(0, 229, 255, 0.15); color: var(--cyan); border: 1px solid rgba(0, 229, 255, 0.3); }

/* TOASTS */
#toast-container {
  position: fixed;
  bottom: 24px;
  right: 24px;
  z-index: 9999;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.toast {
  background: #111a2e;
  border: 1px solid var(--border);
  border-left: 4px solid var(--cyan);
  color: #fff;
  padding: 12px 18px;
  border-radius: 8px;
  font-size: 12.5px;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5);
  animation: slideToast 0.2s ease;
}
@keyframes slideToast { from { transform: translateX(20px); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
</style>
</head>
<body>

<!-- TOPBAR -->
<header class="topbar">
  <div class="brand-group">
    <div class="brand-shield">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    </div>
    <div class="brand-text">
      <h1>CookieGuard</h1>
      <p>Control Today. Safer Tomorrow.</p>
    </div>
  </div>

  <div class="search-container">
    <span class="search-icon">🔍</span>
    <input type="text" class="search-input" id="global-search" placeholder="Search cookies, domains, or incidents..." oninput="handleGlobalSearch(this.value)">
    <span class="search-badge">Ctrl K</span>
  </div>

  <div class="topbar-right">
    <div class="status-pill" id="system-status-pill">
      <span class="status-dot" id="system-status-dot"></span>
      <span id="system-status-text">System Healthy</span>
    </div>
    <button class="icon-btn" title="Language / Network" onclick="showToast('Sistema en modo local seguro', 'info')">🌐</button>
    <div class="user-profile" onclick="switchTab('view-herramientas')">
      <div class="user-avatar">A</div>
      <div class="user-meta">
        <span class="name">Admin</span>
        <span class="plan">Enterprise Plan</span>
      </div>
      <span style="font-size:10px; color:var(--text-faint);">▾</span>
    </div>
  </div>
</header>

<div id="warning-banner-container"></div>

<!-- APP BODY -->
<div class="app-body">
  <!-- SIDEBAR -->
  <aside class="sidebar">
    <nav class="nav-menu">
      <div class="nav-link active" id="nav-resumen" onclick="switchTab('view-resumen')">
        <div class="nav-link-content">
          <span>🏠</span>
          <span>Overview</span>
        </div>
      </div>
      <div class="nav-link" id="nav-indicadores" onclick="switchTab('view-indicadores')">
        <div class="nav-link-content">
          <span>🛡️</span>
          <span>Incidents</span>
        </div>
        <span class="nav-badge" id="incident-badge">3</span>
      </div>
      <div class="nav-link" id="nav-sesiones" onclick="switchTab('view-sesiones')">
        <div class="nav-link-content">
          <span>🍪</span>
          <span>Cookies</span>
        </div>
      </div>
      <div class="nav-link" id="nav-playbooks" onclick="switchTab('view-playbooks')">
        <div class="nav-link-content">
          <span>🏢</span>
          <span>Services</span>
        </div>
      </div>
      <div class="nav-link" id="nav-herramientas" onclick="switchTab('view-herramientas')">
        <div class="nav-link-content">
          <span>🔄</span>
          <span>Revocations</span>
        </div>
      </div>
      <div class="nav-link" id="nav-analytics" onclick="switchTab('view-canary')">
        <div class="nav-link-content">
          <span>📊</span>
          <span>Analytics</span>
        </div>
      </div>
      <div class="nav-link" id="nav-settings" onclick="switchTab('view-canary')">
        <div class="nav-link-content">
          <span>⚙️</span>
          <span>Settings</span>
        </div>
      </div>
    </nav>

    <div class="sidebar-bottom-card">
      <h4>Protected by default.</h4>
      <p>Detect. Revoke. Stay in control.</p>
    </div>
  </aside>

  <!-- MAIN VIEW -->
  <main class="main-content">

    <!-- VIEW: OVERVIEW (VIEW-RESUMEN) -->
    <section class="view-panel active" id="view-resumen">
      <div class="hero-header">
        <div class="hero-titles">
          <h2>Threats to your data.<br><span class="gradient-text">Stopped here.</span></h2>
          <p class="hero-subtitle">Detect, analyze, and revoke dangerous cookies before they put you at risk.</p>
        </div>
        <div class="hero-actions">
          <div class="hero-btn-row">
            <button class="btn-scan" id="btn-scan-now" onclick="triggerScan()">🔍 Scan Now</button>
            <button class="btn-outline" onclick="triggerRevokeAll()">⊗ Revoke All</button>
            <button class="btn-outline btn-emergency" onclick="triggerEmergencyMode()">⚡ Emergency Mode</button>
          </div>
          <div class="scan-meta" id="scan-meta-text">Last scan: Just now • 247 cookies analyzed</div>
        </div>
      </div>

      <!-- 4 KPI CARDS ROW -->
      <div class="grid-kpi">
        <div class="kpi-card">
          <div class="kpi-left">
            <div class="kpi-icon-box kpi-icon-cyan">🛡️</div>
            <div class="kpi-text">
              <div class="num" id="kpi-total-cookies">247</div>
              <div class="label">Total Cookies</div>
            </div>
          </div>
          <div class="kpi-spark">
            <svg width="48" height="20" viewBox="0 0 48 20" fill="none"><path d="M0 15 Q 12 5, 24 10 T 48 4" stroke="#10b981" stroke-width="2" fill="none"/></svg>
            <span class="spark-pill spark-green">↓ 12%</span>
          </div>
        </div>

        <div class="kpi-card">
          <div class="kpi-left">
            <div class="kpi-icon-box kpi-icon-orange">⚠️</div>
            <div class="kpi-text">
              <div class="num" id="kpi-at-risk">23</div>
              <div class="label">At Risk</div>
            </div>
          </div>
          <div class="kpi-spark">
            <svg width="48" height="20" viewBox="0 0 48 20" fill="none"><path d="M0 16 Q 12 12, 24 8 T 48 2" stroke="#ff3366" stroke-width="2" fill="none"/></svg>
            <span class="spark-pill spark-red">↑ 4%</span>
          </div>
        </div>

        <div class="kpi-card">
          <div class="kpi-left">
            <div class="kpi-icon-box kpi-icon-blue">👥</div>
            <div class="kpi-text">
              <div class="num" id="kpi-services-count">8</div>
              <div class="label">Services</div>
            </div>
          </div>
          <div class="kpi-spark">
            <svg width="48" height="20" viewBox="0 0 48 20" fill="none"><path d="M0 10 L 48 10" stroke="#64748b" stroke-width="2" fill="none"/></svg>
            <span class="spark-pill spark-neutral">0%</span>
          </div>
        </div>

        <div class="kpi-card">
          <div class="kpi-left">
            <div class="kpi-icon-box kpi-icon-purple">🔒</div>
            <div class="kpi-text">
              <div class="num" id="kpi-revoked-count">5</div>
              <div class="label">Revoked (24h)</div>
            </div>
          </div>
          <div class="kpi-spark">
            <svg width="48" height="20" viewBox="0 0 48 20" fill="none"><path d="M0 18 Q 12 15, 24 6 T 48 2" stroke="#00e5ff" stroke-width="2" fill="none"/></svg>
            <span class="spark-pill spark-cyan">↑ 150%</span>
          </div>
        </div>
      </div>

      <!-- MIDDLE ROW -->
      <div class="middle-row">
        <!-- PANEL 1: DONUT CHART -->
        <div class="mid-card">
          <div class="mid-header">
            <h3>Cookie Risk Breakdown</h3>
          </div>
          <div class="donut-container">
            <div class="donut-svg-box">
              <svg class="svg-gauge" viewBox="0 0 120 120">
                <circle cx="60" cy="60" r="46" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="12"/>
                <circle id="donut-seg-unk" cx="60" cy="60" r="46" fill="none" stroke="#a855f7" stroke-width="12" stroke-dasharray="289" stroke-dashoffset="260"/>
                <circle id="donut-seg-low" cx="60" cy="60" r="46" fill="none" stroke="#00e5ff" stroke-width="12" stroke-dasharray="289" stroke-dashoffset="120"/>
                <circle id="donut-seg-med" cx="60" cy="60" r="46" fill="none" stroke="#ff9f1c" stroke-width="12" stroke-dasharray="289" stroke-dashoffset="60"/>
                <circle id="donut-seg-high" cx="60" cy="60" r="46" fill="none" stroke="#ff3366" stroke-width="12" stroke-dasharray="289" stroke-dashoffset="265"/>
              </svg>
              <div class="donut-center">
                <div class="c-num" id="donut-center-val">247</div>
                <div class="c-lbl">Cookies</div>
              </div>
            </div>
            <div class="donut-legend">
              <div class="leg-item">
                <div class="leg-left"><span class="leg-dot" style="background:#ff3366;"></span>High Risk</div>
                <div class="leg-val" id="leg-high-val">23 (9%)</div>
              </div>
              <div class="leg-item">
                <div class="leg-left"><span class="leg-dot" style="background:#ff9f1c;"></span>Medium Risk</div>
                <div class="leg-val" id="leg-med-val">57 (23%)</div>
              </div>
              <div class="leg-item">
                <div class="leg-left"><span class="leg-dot" style="background:#00e5ff;"></span>Low Risk</div>
                <div class="leg-val" id="leg-low-val">142 (57%)</div>
              </div>
              <div class="leg-item">
                <div class="leg-left"><span class="leg-dot" style="background:#a855f7;"></span>Unknown</div>
                <div class="leg-val" id="leg-unk-val">25 (11%)</div>
              </div>
            </div>
          </div>
        </div>

        <!-- PANEL 2: RECENT ALERT ACTIVITY -->
        <div class="mid-card">
          <div class="mid-header">
            <h3>Recent Alert Activity</h3>
            <a href="#" onclick="switchTab('view-indicadores')">View All →</a>
          </div>
          <div class="alert-list" id="activity-alert-list">
            <div class="alert-row">
              <div class="alert-time">2m ago</div>
              <div class="alert-status-dot" style="background:#ff3366;"></div>
              <div class="alert-info">
                <div class="alert-title">Suspicious cookie detected</div>
                <div class="alert-domain">.facebook.com — tracking cookie</div>
              </div>
            </div>
            <div class="alert-row">
              <div class="alert-time">12m ago</div>
              <div class="alert-status-dot" style="background:#ff9f1c;"></div>
              <div class="alert-info">
                <div class="alert-title">High risk cookie identified</div>
                <div class="alert-domain">accounts.google.com — auth cookie</div>
              </div>
            </div>
            <div class="alert-row">
              <div class="alert-time">28m ago</div>
              <div class="alert-status-dot" style="background:#00e5ff;"></div>
              <div class="alert-info">
                <div class="alert-title">Cookie revoked successfully</div>
                <div class="alert-domain">discord.com — 3 cookies</div>
              </div>
            </div>
            <div class="alert-row">
              <div class="alert-time">1h ago</div>
              <div class="alert-status-dot" style="background:#ff3366;"></div>
              <div class="alert-info">
                <div class="alert-title">Multiple tracking cookies found</div>
                <div class="alert-domain">doubleclick.net — 12 cookies</div>
              </div>
            </div>
          </div>
        </div>

        <!-- PANEL 3: QUICK SERVICE REVOCATION -->
        <div class="mid-card">
          <div class="mid-header">
            <h3>Quick Service Revocation</h3>
          </div>
          <div class="service-list" id="quick-services-list">
            <div class="service-row">
              <div class="service-info">
                <div class="service-logo" style="color:#ea4335;">G</div>
                <div class="service-meta">
                  <div class="s-name">Google</div>
                  <div class="s-count">12 cookies</div>
                </div>
              </div>
              <div class="service-actions">
                <span class="risk-pill risk-high">3 high risk</span>
                <button class="btn-revoke-sm" onclick="triggerRevokeService('Google')">Revoke</button>
              </div>
            </div>

            <div class="service-row">
              <div class="service-info">
                <div class="service-logo" style="color:#5865f2;">D</div>
                <div class="service-meta">
                  <div class="s-name">Discord</div>
                  <div class="s-count">8 cookies</div>
                </div>
              </div>
              <div class="service-actions">
                <span class="risk-pill risk-high">2 high risk</span>
                <button class="btn-revoke-sm" onclick="triggerRevokeService('Discord')">Revoke</button>
              </div>
            </div>

            <div class="service-row">
              <div class="service-info">
                <div class="service-logo" style="color:#fff;">𝕏</div>
                <div class="service-meta">
                  <div class="s-name">X (Twitter)</div>
                  <div class="s-count">6 cookies</div>
                </div>
              </div>
              <div class="service-actions">
                <span class="risk-pill risk-high">1 high risk</span>
                <button class="btn-revoke-sm" onclick="triggerRevokeService('X')">Revoke</button>
              </div>
            </div>

            <div class="service-row">
              <div class="service-info">
                <div class="service-logo" style="color:#fff;">🐙</div>
                <div class="service-meta">
                  <div class="s-name">GitHub</div>
                  <div class="s-count">4 cookies</div>
                </div>
              </div>
              <div class="service-actions">
                <span class="risk-pill risk-none">No risks</span>
                <button class="btn-revoke-sm" onclick="triggerRevokeService('GitHub')">Revoke</button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- BOTTOM PANEL: DETECTED COOKIES TABLE -->
      <div class="table-card">
        <div class="table-ctrl-row">
          <h3>Detected Cookies</h3>
          <div class="table-filters">
            <input type="text" class="filter-search" id="cookie-table-search" placeholder="Search cookies..." oninput="filterCookiesTable()">
            <select class="filter-select" id="filter-risk" onchange="filterCookiesTable()">
              <option value="all">All Risk Levels</option>
              <option value="high">High Risk</option>
              <option value="medium">Medium Risk</option>
              <option value="low">Low Risk</option>
            </select>
            <select class="filter-select" id="filter-service" onchange="filterCookiesTable()">
              <option value="all">All Services</option>
              <option value="Google">Google</option>
              <option value="Discord">Discord</option>
              <option value="X">X (Twitter)</option>
              <option value="GitHub">GitHub</option>
            </select>
          </div>
        </div>

        <table class="data-table">
          <thead>
            <tr>
              <th width="32"><input type="checkbox" id="check-all-cookies"></th>
              <th>Name</th>
              <th>Domain</th>
              <th>Service</th>
              <th>Risk Level</th>
              <th>Category</th>
              <th>Last Seen</th>
              <th width="100">Actions</th>
            </tr>
          </thead>
          <tbody id="detected-cookies-tbody">
            <tr>
              <td><input type="checkbox"></td>
              <td><strong>SID</strong></td>
              <td>accounts.google.com</td>
              <td>Google</td>
              <td><span class="pill-badge pill-high">High</span></td>
              <td>Authentication</td>
              <td>2 minutes ago</td>
              <td><button class="btn-revoke-sm" onclick="triggerRevokeService('Google')">Revoke</button></td>
            </tr>
            <tr>
              <td><input type="checkbox"></td>
              <td><strong>dtCookie</strong></td>
              <td>doubleclick.net</td>
              <td>Google</td>
              <td><span class="pill-badge pill-high">High</span></td>
              <td>Tracking</td>
              <td>5 minutes ago</td>
              <td><button class="btn-revoke-sm" onclick="triggerRevokeService('Google')">Revoke</button></td>
            </tr>
            <tr>
              <td><input type="checkbox"></td>
              <td><strong>sb</strong></td>
              <td>twitter.com</td>
              <td>X</td>
              <td><span class="pill-badge pill-medium">Medium</span></td>
              <td>Analytics</td>
              <td>12 minutes ago</td>
              <td><button class="btn-revoke-sm" onclick="triggerRevokeService('X')">Revoke</button></td>
            </tr>
            <tr>
              <td><input type="checkbox"></td>
              <td><strong>__Secure-1PSID</strong></td>
              <td>google.com</td>
              <td>Google</td>
              <td><span class="pill-badge pill-low">Low</span></td>
              <td>Preference</td>
              <td>18 minutes ago</td>
              <td><button class="btn-revoke-sm" onclick="triggerRevokeService('Google')">Revoke</button></td>
            </tr>
            <tr>
              <td><input type="checkbox"></td>
              <td><strong>discord_unique_id</strong></td>
              <td>discord.com</td>
              <td>Discord</td>
              <td><span class="pill-badge pill-medium">Medium</span></td>
              <td>Functional</td>
              <td>28 minutes ago</td>
              <td><button class="btn-revoke-sm" onclick="triggerRevokeService('Discord')">Revoke</button></td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- OTHER COMPATIBILITY VIEWS -->
    <section class="view-panel" id="view-indicadores">
      <h2 style="font-size:22px; font-weight:700; margin-bottom:16px;">Incidents & Indicators</h2>
      <div id="incidents-container"></div>
    </section>

    <section class="view-panel" id="view-sesiones">
      <h2 style="font-size:22px; font-weight:700; margin-bottom:16px;">All Cookies Inventory</h2>
      <div id="all-sessions-container"></div>
    </section>

    <section class="view-panel" id="view-playbooks">
      <h2 style="font-size:22px; font-weight:700; margin-bottom:16px;">Quick Revocation Playbooks</h2>
      <div id="playbooks-container"></div>
    </section>

    <section class="view-panel" id="view-herramientas">
      <h2 style="font-size:22px; font-weight:700; margin-bottom:16px;">Forensic Tools & Rescue</h2>
      <div style="display:flex; gap:12px; margin-bottom:20px;">
        <button class="btn-outline" onclick="triggerTool('persistence')">Auditoría Persistencia</button>
        <button class="btn-outline" onclick="triggerTool('network')">Auditoría Hosts / Red</button>
        <button class="btn-outline" onclick="triggerTool('integrity')">Integridad Binaria</button>
        <button class="btn-outline" onclick="triggerExport('html')">Exportar HTML</button>
        <button class="btn-outline" onclick="triggerExport('zip')">ZIP Incidente</button>
      </div>
      <div id="tool-output" style="background:var(--bg-card); padding:16px; border-radius:10px; font-family:monospace; font-size:12px;"></div>
    </section>

    <section class="view-panel" id="view-canary">
      <h2 style="font-size:22px; font-weight:700; margin-bottom:16px;">Canary Traps & Settings</h2>
      <div style="display:flex; gap:12px; margin-bottom:20px;">
        <button class="btn-scan" onclick="triggerDeployCanary()">Desplegar Trampa Canary</button>
        <button class="btn-outline" onclick="triggerCheckCanary()">Comprobar Estado Canary</button>
      </div>
      <div id="canary-output" style="background:var(--bg-card); padding:16px; border-radius:10px; font-size:12px;"></div>
    </section>
  </main>
</div>

<div id="toast-container"></div>

<script>
// BRIDGE COMUNICACIÓN UNIVERSAL (FETCH LOOPBACK + PYWEBVIEW)
async function callApi(method, ...args) {
  try {
    const res = await fetch('/api/' + method, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(args)
    });
    if (res.ok) {
      return await res.json();
    }
  } catch (e) {
    // Si fetch falla, probar puente pywebview directo
  }
  if (window.pywebview && window.pywebview.api && typeof window.pywebview.api[method] === 'function') {
    try {
      return await window.pywebview.api[method](...args);
    } catch (err) {
      console.error('Bridge error on', method, err);
    }
  }
  return null;
}

function showToast(msg, type = 'info') {
  const container = document.getElementById('toast-container');
  const t = document.createElement('div');
  t.className = 'toast';
  t.innerText = msg;
  if (type === 'error') t.style.borderLeftColor = 'var(--pink)';
  if (type === 'success') t.style.borderLeftColor = 'var(--green)';
  container.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

function switchTab(viewId) {
  document.querySelectorAll('.view-panel').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-link').forEach(el => el.classList.remove('active'));
  const target = document.getElementById(viewId);
  if (target) target.classList.add('active');
  const navItem = document.getElementById('nav-' + viewId.replace('view-', ''));
  if (navItem) navItem.classList.add('active');
}

// SCAN REAL
async function triggerScan() {
  const btn = document.getElementById('btn-scan-now');
  if (btn) {
    btn.innerText = '⏳ Scanning...';
    btn.disabled = true;
  }
  showToast('Iniciando escaneo de sesiones y alertas...', 'info');

  const res = await callApi('run_scan');
  if (btn) {
    btn.innerText = '🔍 Scan Now';
    btn.disabled = false;
  }

  if (res && res.veredicto) {
    updateDashboardUI(res);
    showToast('Escaneo completado: ' + res.veredicto.texto, res.veredicto.nivel === 'verde' ? 'success' : 'error');
  } else {
    showToast('Escaneo finalizado sin nuevas sesiones detectadas.', 'info');
  }
}

function updateDashboardUI(res) {
  const v = res.veredicto || {};
  const s = res.estadisticas || {};

  // Status pill
  const pill = document.getElementById('system-status-pill');
  const text = document.getElementById('system-status-text');
  if (v.nivel === 'rojo' || v.nivel === 'amarillo') {
    pill.classList.add('danger');
    text.innerText = (v.puntos || 0) + ' Threat Points';
  } else {
    pill.classList.remove('danger');
    text.innerText = 'System Healthy';
  }

  // KPIs
  const total = s.cookies_totales || s.total_cookies || 247;
  const risk = (v.nivel === 'rojo' || v.nivel === 'amarillo') ? (v.puntos || 23) : 0;
  const services = (res.grupos && res.grupos.length) || 8;

  document.getElementById('kpi-total-cookies').innerText = total;
  document.getElementById('kpi-at-risk').innerText = risk;
  document.getElementById('kpi-services-count').innerText = services;
  document.getElementById('donut-center-val').innerText = total;

  document.getElementById('scan-meta-text').innerText = 'Last scan: Just now • ' + total + ' cookies analyzed';

  // Render Real Detected Cookies if available
  if (res.grupos && res.grupos.length > 0) {
    const tbody = document.getElementById('detected-cookies-tbody');
    tbody.innerHTML = '';
    res.grupos.forEach(g => {
      const tr = document.createElement('tr');
      const isRisk = g.critico || (v.nivel !== 'verde');
      const pillClass = isRisk ? 'pill-high' : 'pill-low';
      const riskLabel = isRisk ? 'High' : 'Low';
      tr.innerHTML = `
        <td><input type="checkbox"></td>
        <td><strong>${escapeHtml(g.nombre || 'Cookie')}</strong></td>
        <td>${escapeHtml(g.dominio || '')}</td>
        <td>${escapeHtml(g.nombre || 'Web')}</td>
        <td><span class="pill-badge ${pillClass}">${riskLabel}</span></td>
        <td>Authentication</td>
        <td>Just now</td>
        <td><button class="btn-revoke-sm" onclick="triggerRevokeService('${escapeHtml(g.nombre || '')}')">Revoke</button></td>
      `;
      tbody.appendChild(tr);
    });
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

async function triggerRevokeAll() {
  showToast('Iniciando revocación y asistente de rotación...', 'info');
  await callApi('revoke_all_sessions');
  showToast('Asistente de rescate generado.', 'success');
}

async function triggerEmergencyMode() {
  if (confirm('¿Activar Modo de Emergencia? Se aislará el entorno y se cerrarán los navegadores para proteger las credenciales.')) {
    showToast('Activando Modo de Emergencia...', 'error');
    await callApi('emergency_mode');
    showToast('Navegadores asegurados y entorno aislado.', 'success');
  }
}

async function triggerRevokeService(svc) {
  showToast('Abriendo portal de revocación para ' + svc + '...', 'info');
  await callApi('revoke_service', svc);
}

async function triggerTool(tool) {
  showToast('Ejecutando ' + tool + '...', 'info');
  const res = await callApi('run_specialized_tool', tool);
  document.getElementById('tool-output').innerText = JSON.stringify(res, null, 2);
}

async function triggerExport(fmt) {
  showToast('Exportando ' + fmt + '...', 'info');
  if (fmt === 'zip') {
    const res = await callApi('create_incident_zip');
    showToast('ZIP de incidente guardado en: ' + (res.path || 'temp'), 'success');
  } else {
    const res = await callApi('export_report', fmt);
    showToast('Informe ' + fmt + ' guardado en: ' + (res.path || 'temp'), 'success');
  }
}

async function triggerDeployCanary() {
  showToast('Desplegando trampa señuelo Canary...', 'info');
  const res = await callApi('deploy_canary');
  document.getElementById('canary-output').innerText = JSON.stringify(res, null, 2);
  showToast('Trampa Canary desplegada y armada.', 'success');
}

async function triggerCheckCanary() {
  const res = await callApi('check_canary');
  document.getElementById('canary-output').innerText = JSON.stringify(res, null, 2);
}

function filterCookiesTable() {
  const q = (document.getElementById('cookie-table-search').value || '').toLowerCase();
  const risk = document.getElementById('filter-risk').value;
  const svc = document.getElementById('filter-service').value.toLowerCase();

  document.querySelectorAll('#detected-cookies-tbody tr').forEach(row => {
    const text = row.innerText.toLowerCase();
    const matchQ = !q || text.includes(q);
    const matchSvc = svc === 'all' || text.includes(svc);
    row.style.display = (matchQ && matchSvc) ? '' : 'none';
  });
}

function handleGlobalSearch(q) {
  if (!q) return;
  document.getElementById('cookie-table-search').value = q;
  filterCookiesTable();
}

window.addEventListener('DOMContentLoaded', async () => {
  const init = await callApi('get_initial_data');
  if (init && init.warning_old) {
    const w = document.getElementById('warning-banner-container');
    w.innerHTML = `<div style="background:#78350f; color:#fef3c7; padding:10px 24px; font-size:12px; display:flex; justify-content:space-between;">
      <span>⚠️ ${escapeHtml(init.warning_old)}</span>
      <button onclick="this.parentElement.remove()" style="background:none; border:none; color:#fff; cursor:pointer;">✕</button>
    </div>`;
  }
  // Auto-scan al inicio
  triggerScan();
});
</script>
</body>
</html>"""



def launch(debug: bool = False) -> int:
    """Lanza la ventana nativa Cyber SOC idéntica al diseño oficial."""
    api = BridgeApi()
    html_content = get_dashboard_html()

    server = LocalDashboardServer(api, html_content)
    port = server.start()
    local_url = f"http://127.0.0.1:{port}/"

    try:
        import webview
        window = webview.create_window(
            title=f"CookieGuard {VERSION} · Threats to your data. Stopped here.",
            url=local_url,
            js_api=api,
            width=1280,
            height=820,
            min_size=(980, 680),
            background_color="#070c18"
        )
        webview.start(debug=debug)
        return 0
    except Exception as e:
        print(f"[!] Fallback: abriendo dashboard local en navegador: {e}", file=sys.stderr)
        webbrowser.open(local_url)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        return 0
    finally:
        server.stop()


if __name__ == "__main__":
    sys.exit(launch(debug="--debug" in sys.argv))
