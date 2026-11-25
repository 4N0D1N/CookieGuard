"""CookieGuard v2.7.3 · Consola de escritorio Cyber SOC idéntica al diseño oficial."""
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
from datetime import datetime, date
from typing import Any, Dict, Optional


def sanitize_for_json(data: Any) -> Any:
    """Convierte datetimes a formato ISO, sets a listas y Paths a strings para garantizar serialización JSON estricta."""
    def default_handler(o):
        if isinstance(o, (datetime, date)):
            return o.isoformat()
        if isinstance(o, (set, frozenset)):
            return sorted(list(o))
        if isinstance(o, Path):
            return str(o)
        return str(o)
    return json.loads(json.dumps(data, default=default_handler))

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

        return sanitize_for_json({
            "version": VERSION,
            "theme": cfg.get("tema", "oscuro"),
            "canary": canary_status,
            "last_res": self.last_res,
            "warning_old": warning_old,
            "playbooks": playbooks.PLAYBOOK_CATALOG,
            "binary_path": sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)
        })

    def run_scan(self) -> Dict[str, Any]:
        """Ejecuta un escaneo completo de sesiones y actualiza reportes locales."""
        with self._lock:
            profiles = browsers.discover()
            res = engine.run_analysis(profiles)
            try:
                reports.write_reports(res)
            except Exception:
                pass
            clean_res = sanitize_for_json(res)
            prev = getattr(self, "_previous_sessions", None)
            curr = set()
            for s in clean_res.get("sesiones", []):
                k = (str(s.get("host") or s.get("dominio") or ""), str(s.get("name") or s.get("nombre") or ""), str(s.get("servicio_id") or ""))
                curr.add(k)
                if prev is not None:
                    s["is_new"] = (k not in prev)
                else:
                    s["is_new"] = False
            self._previous_sessions = curr
            self.last_res = clean_res
            return clean_res

    def deploy_canary(self) -> Dict[str, Any]:
        """Despliega trampas señuelo Canary en los navegadores."""
        canary_trap.deploy_canary_traps()
        return sanitize_for_json(canary_trap.check_canary_traps())

    def check_canary(self) -> Dict[str, Any]:
        """Verifica la integridad de las trampas señuelo."""
        return sanitize_for_json(canary_trap.check_canary_traps())

    def open_url(self, url: str) -> bool:
        """Abre de forma segura una URL oficial en el navegador predeterminado."""
        if not url or not (url.startswith("https://") or url.startswith("http://")):
            return False
        return webbrowser.open(url)

    def get_playbooks(self) -> list:
        """Devuelve el catálogo de playbooks de revocación."""
        return sanitize_for_json(playbooks.PLAYBOOK_CATALOG)

    def revoke_service(self, service_name: str, action_type: str = "sesiones") -> Dict[str, Any]:
        """Abre la URL oficial de revocación para un servicio o genera playbook."""
        s_low = (service_name or "").lower().strip()
        target_p = None
        for p in playbooks.PLAYBOOK_CATALOG:
            pid = p.get("id", "").lower()
            pname = p.get("nombre", "").lower()
            domains = [d.lower() for d in p.get("dominios", [])]
            if (s_low == pid or s_low == pname or s_low in pname or
                pname.startswith(s_low) or any(s_low in d for d in domains)):
                target_p = p
                break

        if target_p:
            url = None
            if action_type == "password":
                url = target_p.get("url_password") or target_p.get("url_sesiones")
            elif action_type == "oauth":
                url = target_p.get("url_oauth") or target_p.get("url_sesiones")
            else:
                url = target_p.get("url_sesiones") or target_p.get("url_password") or target_p.get("url_oauth")

            if url:
                self.open_url(url)
                return {"ok": True, "servicio": target_p.get("nombre", service_name), "url": url, "accion": action_type}

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
        return sanitize_for_json(rescue_wizard.run_rescue_plan(
            auto=True, killswitch=False, kill_browsers=kill_browsers, output_dir=t_dir
        ))

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
                elif self.path in ("/informe", "/informe.html", "/report", "/report.html"):
                    try:
                        from . import reports, engine
                        res = api_ref.last_res or engine.run_analysis()
                        raw_html = reports.build_html(res)
                        print_banner = '''
<div id="cg-print-bar" style="position: sticky; top: 0; z-index: 99999; background: #0b1325; color: #f8fafc; padding: 12px 24px; display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #00e5ff; box-shadow: 0 4px 20px rgba(0,0,0,0.5); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
  <div style="display: flex; align-items: center; gap: 12px;">
    <span style="font-size: 1.4rem;">🛡️</span>
    <div>
      <strong style="color: #00e5ff; font-size: 1.05rem;">CookieGuard · Informe Forense y Metadatos de Sesión</strong>
      <div style="font-size: 0.8rem; color: #94a3b8;">Documento local sin telemetría • Listo para imprimir o guardar en PDF</div>
    </div>
  </div>
  <div style="display: flex; gap: 12px;">
    <button onclick="window.print()" style="background: linear-gradient(135deg, #0066ff, #00e5ff); color: white; border: none; padding: 8px 18px; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 0.9rem; box-shadow: 0 2px 8px rgba(0,229,255,0.3);">
      🖨️ Guardar como PDF / Imprimir
    </button>
    <button onclick="window.close()" style="background: rgba(255,255,255,0.1); color: #cbd5e1; border: 1px solid rgba(255,255,255,0.2); padding: 8px 14px; border-radius: 6px; cursor: pointer; font-size: 0.9rem;">
      Cerrar pestaña
    </button>
  </div>
</div>
<style>
@media print {
  #cg-print-bar { display: none !important; }
  body { background: #ffffff !important; color: #0f172a !important; }
  .card, table, tr { break-inside: avoid; page-break-inside: avoid; }
  @page { margin: 1.5cm; size: A4 portrait; }
}
</style>
'''
                        if "<body>" in raw_html:
                            full_report = raw_html.replace("<body>", "<body>" + print_banner, 1)
                        else:
                            full_report = print_banner + raw_html
                        rep_bytes = full_report.encode("utf-8")
                        self.send_response(200)
                        self.send_header("Content-Type", "text/html; charset=utf-8")
                        self.send_header("Content-Length", str(len(rep_bytes)))
                        self.end_headers()
                        self.wfile.write(rep_bytes)
                    except Exception as e_rep:
                        err_bytes = f"<h3>Error generando informe: {e_rep}</h3>".encode("utf-8")
                        self.send_response(500)
                        self.send_header("Content-Type", "text/html; charset=utf-8")
                        self.send_header("Content-Length", str(len(err_bytes)))
                        self.end_headers()
                        self.wfile.write(err_bytes)
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
                            out_bytes = json.dumps(sanitize_for_json(res), ensure_ascii=False).encode("utf-8")
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

/* QUICK FILTER PILLS & CANARY ANIMATION */
.q-pill {
  background: var(--bg-hover);
  border: 1px solid var(--border);
  color: var(--text-muted);
  padding: 4px 10px;
  border-radius: 6px;
  font-size: 11px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s ease;
}
.q-pill:hover {
  background: var(--bg-card);
  color: var(--text-main);
  border-color: var(--accent);
}
.q-pill.active {
  background: rgba(0, 229, 255, 0.15);
  border-color: var(--cyan);
  color: var(--cyan);
}
@keyframes pulseCanary {
  0% { box-shadow: 0 0 8px rgba(220, 38, 38, 0.4); }
  50% { box-shadow: 0 0 20px rgba(239, 68, 68, 0.8); }
  100% { box-shadow: 0 0 8px rgba(220, 38, 38, 0.4); }
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

/* COOKIE INFO MODAL & BUTTON */
.btn-info-cookie {
  background: transparent;
  border: 1px solid rgba(255, 255, 255, 0.2);
  color: var(--cyan);
  width: 17px;
  height: 17px;
  border-radius: 50%;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 11px;
  font-weight: 700;
  cursor: pointer;
  transition: all 0.2s ease;
  padding: 0;
  margin-left: 6px;
  vertical-align: middle;
}
.btn-info-cookie:hover {
  background: rgba(0, 229, 255, 0.25);
  border-color: var(--cyan);
  color: #fff;
  transform: scale(1.15);
  box-shadow: 0 0 10px rgba(0, 229, 255, 0.4);
}
.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(4, 9, 20, 0.78);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  z-index: 10000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
  opacity: 0;
  pointer-events: none;
  transition: opacity 0.2s cubic-bezier(0.16, 1, 0.3, 1);
}
.modal-overlay.active {
  opacity: 1;
  pointer-events: auto;
}
.cookie-modal-card {
  background: #0c1322;
  border: 1px solid rgba(0, 229, 255, 0.35);
  box-shadow: 0 24px 50px rgba(0, 0, 0, 0.7), 0 0 35px rgba(0, 229, 255, 0.12);
  border-radius: 14px;
  width: 100%;
  max-width: 560px;
  max-height: 85vh;
  overflow-y: auto;
  padding: 24px;
  color: var(--text-main);
  transform: translateY(12px) scale(0.97);
  transition: transform 0.25s cubic-bezier(0.16, 1, 0.3, 1);
}
.modal-overlay.active .cookie-modal-card {
  transform: translateY(0) scale(1);
}

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
<div id="canary-emergency-alert-container"></div>

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
    <button class="icon-btn" id="theme-toggle-btn" title="Alternar tema claro / oscuro" onclick="toggleTheme()">☀️</button>
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
        <span class="nav-badge" id="incident-badge" style="display:none;">0</span>
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
      <div class="nav-link" id="nav-canary" onclick="switchTab('view-canary')">
        <div class="nav-link-content">
          <span>⚙️</span>
          <span>Canary &amp; Settings</span>
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
            <button class="btn-outline" onclick="window.open('/informe', '_blank')" title="Abrir informe forense completo en otra pestaña listo para PDF">📄 Informe PDF</button>
            <button class="btn-outline" onclick="triggerRevokeAll()">⊗ Revoke All</button>
            <button class="btn-outline btn-emergency" onclick="triggerEmergencyMode()">⚡ Emergency Mode</button>
          </div>
          <div class="scan-meta" id="scan-meta-text">Auditoría lista • Presiona "Scan Now"</div>
        </div>
      </div>

      <!-- 4 KPI CARDS ROW -->
      <div class="grid-kpi">
        <div class="kpi-card">
          <div class="kpi-left">
            <div class="kpi-icon-box kpi-icon-cyan">🛡️</div>
            <div class="kpi-text">
              <div class="num" id="kpi-total-cookies">0</div>
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
              <div class="num" id="kpi-at-risk">0</div>
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
              <div class="num" id="kpi-services-count">0</div>
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
              <div class="num" id="kpi-revoked-count">0</div>
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
                <div class="c-num" id="donut-center-val">0</div>
                <div class="c-lbl">Cookies</div>
              </div>
            </div>
            <div class="donut-legend">
              <div class="leg-item">
                <div class="leg-left"><span class="leg-dot" style="background:#ff3366;"></span>High Risk</div>
                <div class="leg-val" id="leg-high-val">0 (0%)</div>
              </div>
              <div class="leg-item">
                <div class="leg-left"><span class="leg-dot" style="background:#ff9f1c;"></span>Medium Risk</div>
                <div class="leg-val" id="leg-med-val">0 (0%)</div>
              </div>
              <div class="leg-item">
                <div class="leg-left"><span class="leg-dot" style="background:#00e5ff;"></span>Low Risk</div>
                <div class="leg-val" id="leg-low-val">0 (0%)</div>
              </div>
              <div class="leg-item">
                <div class="leg-left"><span class="leg-dot" style="background:#a855f7;"></span>Unknown</div>
                <div class="leg-val" id="leg-unk-val">0 (0%)</div>
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
            <div style="padding:24px; color:var(--text-muted); font-size:13px; text-align:center;">
              Sin amenazas detectadas. Todos los sensores están en orden.
            </div>
          </div>
        </div>

        <!-- PANEL 3: QUICK SERVICE REVOCATION -->
        <div class="mid-card">
          <div class="mid-header">
            <h3>Quick Service Revocation</h3>
          </div>
          <div class="service-list" id="quick-services-list">
            <div style="padding:24px; color:var(--text-muted); font-size:13px; text-align:center;">
              Sin sesiones activas de servicios detectadas.
            </div>
          </div>
        </div>
      </div>

      <!-- BOTTOM PANEL: DETECTED COOKIES TABLE -->
      <div class="table-card">
        <div class="table-ctrl-row">
          <div style="display:flex; align-items:center; gap:12px; flex-wrap:wrap;">
            <h3>Detected Cookies</h3>
            <div class="quick-filter-pills" style="display:flex; gap:6px;">
              <button type="button" class="q-pill active" onclick="setQuickFilter('all', this)">Todos</button>
              <button type="button" class="q-pill" onclick="setQuickFilter('high', this)">🔥 Alto Riesgo</button>
              <button type="button" class="q-pill" onclick="setQuickFilter('new', this)">✨ Nuevas</button>
              <button type="button" class="q-pill" onclick="setQuickFilter('google', this)">Google</button>
              <button type="button" class="q-pill" onclick="setQuickFilter('github', this)">GitHub</button>
              <button type="button" class="q-pill" onclick="setQuickFilter('discord', this)">Discord</button>
            </div>
          </div>
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
            <tr id="initial-scan-row">
              <td colspan="8" style="text-align:center; padding:36px; color:var(--text-muted);">
                <div style="font-size:15px; font-weight:600; margin-bottom:6px; color:var(--text-main);">🔍 Auditoría lista</div>
                Haz clic en "Scan Now" para auditar cookies de sesión en Edge, Chrome, Brave o Firefox.
              </td>
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

<!-- MODAL DETALLE DE COOKIE -->
<div id="cookie-info-modal" class="modal-overlay" onclick="closeCookieModal(event)">
  <div class="cookie-modal-card" id="cookie-info-modal-card" onclick="event.stopPropagation()">
    <div id="cookie-info-modal-content"></div>
  </div>
</div>

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

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  const btn = document.getElementById('theme-toggle-btn');
  if (btn) btn.innerText = next === 'dark' ? '☀️' : '🌙';
  callApi('save_theme_preference', next === 'dark' ? 'oscuro' : 'claro');
  showToast('Tema cambiado a ' + (next === 'dark' ? 'Oscuro · SOC' : 'Claro · Fluent'), 'info');
}

function switchTab(viewId) {
  document.querySelectorAll('.view-panel').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-link').forEach(el => el.classList.remove('active'));
  const target = document.getElementById(viewId);
  if (target) target.classList.add('active');
  const navItem = document.getElementById('nav-' + viewId.replace('view-', ''));
  if (navItem) navItem.classList.add('active');
}

async function triggerRevokeServiceAction(svc, actionType) {
  showToast('Abriendo acción ' + actionType + ' para ' + svc + '...', 'info');
  const res = await callApi('revoke_service', svc, actionType);
  if (res && res.url) showToast('Portal oficial abierto en tu navegador.', 'success');
  else showToast('No se encontró un portal para ' + svc + '. Revisa las instrucciones.', 'info');
}

function renderPlaybooks(playbookList) {
  const container = document.getElementById('playbooks-container');
  if (!container || !Array.isArray(playbookList)) return;
  container.innerHTML = '<div style="margin-bottom:16px;"><input type="text" id="playbook-search" style="width:100%;max-width:400px;padding:8px 14px;background:var(--bg-input);border:1px solid var(--border);border-radius:8px;color:var(--text-main);" placeholder="Filtrar servicios (Google, Microsoft, GitHub...)" oninput="filterPlaybooks(this.value)"></div><div id="playbook-cards" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px;"></div>';
  const cards = document.getElementById('playbook-cards');
  playbookList.forEach(p => {
    const card = document.createElement('div');
    card.className = 'playbook-card';
    card.dataset.search = ((p.nombre || '') + ' ' + (p.id || '') + ' ' + (p.categoria || '')).toLowerCase();
    card.style.cssText = 'background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:18px;display:flex;flex-direction:column;justify-content:space-between;';
    const steps = (p.pasos || []).slice(0, 2).map(x => '<li>' + escapeHtml(x) + '</li>').join('');
    card.innerHTML = '<div><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;"><span style="font-size:11px;color:var(--cyan);text-transform:uppercase;font-weight:700;">' + escapeHtml(p.categoria || 'Servicio') + '</span><span class="pill-badge ' + (p.criticidad === 'Crítica' ? 'pill-high' : 'pill-medium') + '">' + escapeHtml(p.criticidad || 'Media') + '</span></div><h3 style="font-size:16px;font-weight:700;color:var(--text-main);margin-bottom:6px;">' + escapeHtml(p.nombre || p.id) + '</h3><ul style="margin:10px 0 14px 18px;font-size:12px;color:var(--text-muted);line-height:1.4;">' + steps + '</ul></div>';
    const actions = document.createElement('div');
    actions.style.cssText = 'display:flex;flex-wrap:wrap;gap:8px;margin-top:12px;padding-top:12px;border-top:1px solid var(--border);';
    [['🔑 Cerrar sesiones', 'sesiones'], ['🛡️ Cambiar clave', 'password'], ['📋 Permisos OAuth', 'oauth']].forEach(([label, action]) => {
      const button = document.createElement('button');
      button.className = action === 'sesiones' ? 'btn-revoke-sm' : 'btn-outline';
      button.textContent = label;
      button.addEventListener('click', () => triggerRevokeServiceAction(p.id, action));
      actions.appendChild(button);
    });
    card.appendChild(actions);
    cards.appendChild(card);
  });
}

function filterPlaybooks(q) {
  const query = (q || '').toLowerCase();
  document.querySelectorAll('#playbook-cards .playbook-card').forEach(el => { el.style.display = (!query || el.dataset.search.includes(query)) ? '' : 'none'; });
}

function renderAllSessions(res) {
  const container = document.getElementById('all-sessions-container');
  if (!container) return;
  const items = (res.sesiones && res.sesiones.length) ? res.sesiones : (res.grupos || []);
  container.innerHTML = '<div style="margin-bottom:16px;display:flex;justify-content:space-between;align-items:center;"><input type="text" id="all-sessions-search" style="width:100%;max-width:400px;padding:8px 14px;background:var(--bg-input);border:1px solid var(--border);border-radius:8px;color:var(--text-main);" placeholder="Buscar nombre, host o servicio..." oninput="filterAllSessions(this.value)"><span style="font-size:13px;color:var(--text-muted);">Metadatos: ' + items.length + '</span></div><div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;overflow:auto;"><table style="width:100%;border-collapse:collapse;"><thead><tr style="border-bottom:1px solid var(--border);"><th>Nombre</th><th>Host</th><th>Servicio</th><th>Riesgo</th><th>Categoría</th><th>Caducidad</th><th>Acción</th></tr></thead><tbody id="all-sessions-tbody"></tbody></table></div>';
  const tbody = document.getElementById('all-sessions-tbody');
  if (!items.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:32px;color:var(--text-muted);">Sin metadatos de cookies de sesión detectados. Cierra y reabre el navegador si esperabas encontrar una sesión activa.</td></tr>';
    return;
  }
  window._detectedCookies = items;
    items.forEach((c, idx) => {
    const name = c.name || c.nombre || 'Cookie';
    const host = c.host || (Array.isArray(c.dominios) ? c.dominios.join(', ') : c.dominio) || '';
    const svc = c.servicio_id || c.servicio || c.nombre || 'Web';
    const high = c.confianza === 'Alta' || c.critico || c.riesgo === 'Alto';
    const med = c.confianza === 'Media' || c.riesgo === 'Medio';
    const risk = high ? 'High' : (med ? 'Medium' : 'Low');
    const pill = high ? 'pill-high' : (med ? 'pill-medium' : 'pill-low');
    const cat = c.categoria || (c.httponly ? 'Protegida' : 'Sesión');
    const exp = c.expires || c.caducidad_max || 'Activa';

    const tr = document.createElement('tr');
    tr.className = 'all-session-row';
    tr.dataset.search = (name + ' ' + host + ' ' + svc).toLowerCase();

    [name, host, svc, risk, cat, String(exp).slice(0, 10)].forEach((val, i) => {
      const td = document.createElement('td');
      if (i === 3) {
        const badge = document.createElement('span');
        badge.className = 'pill-badge ' + pill;
        badge.textContent = val;
        td.appendChild(badge);
      } else {
        td.textContent = val;
      }
      tr.appendChild(td);
    });

    const actionTd = document.createElement('td');
    const btn = document.createElement('button');
    btn.className = 'btn-revoke-sm';
    btn.textContent = 'Portal';
    btn.addEventListener('click', () => triggerRevokeService(svc));
    actionTd.appendChild(btn);
    tr.appendChild(actionTd);

    tbody.appendChild(tr);
  });
}

function filterAllSessions(q) {
  const query = (q || '').toLowerCase();
  document.querySelectorAll('#all-sessions-tbody tr.all-session-row').forEach(row => { row.style.display = (!query || row.dataset.search.includes(query)) ? '' : 'none'; });
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

  // 1. Status pill
  const pill = document.getElementById('system-status-pill');
  const pillText = document.getElementById('system-status-text');
  if (v.nivel === 'rojo') {
    pill.className = 'status-pill danger';
    pillText.innerText = (v.puntos || 0) + ' Threat Points (High)';
  } else if (v.nivel === 'amarillo') {
    pill.className = 'status-pill warning';
    pillText.innerText = (v.puntos || 0) + ' Warning Points';
  } else {
    pill.className = 'status-pill healthy';
    pillText.innerText = 'System Healthy';
  }

  // 2. Real KPIs without fake fallbacks
  const total = s.cookies_totales || (res.sesiones ? res.sesiones.length : (res.grupos ? res.grupos.reduce((acc, g) => acc + (g.cookies || 1), 0) : 0));

  // 3. Donut chart breakdown & real cookie risk counts
  let highCount = 0, medCount = 0, lowCount = 0;
  if (res.sesiones && res.sesiones.length > 0) {
    res.sesiones.forEach(c => {
      if (c.confianza === 'Alta' || c.categoria === 'auth') highCount++;
      else if (c.confianza === 'Media') medCount++;
      else lowCount++;
    });
  } else if (res.grupos && res.grupos.length > 0) {
    res.grupos.forEach(g => {
      if (g.critico || g.riesgo === 'Alto') highCount += (g.cookies || 1);
      else if (g.riesgo === 'Medio') medCount += (g.cookies || 1);
      else lowCount += (g.cookies || 1);
    });
  }

  const riskyCookies = highCount + medCount;
  const services = (res.grupos && res.grupos.length) || 0;

  document.getElementById('kpi-total-cookies').innerText = total;
  document.getElementById('kpi-at-risk').innerText = riskyCookies;
  document.getElementById('kpi-services-count').innerText = services;
  document.getElementById('donut-center-val').innerText = total;

  document.getElementById('scan-meta-text').innerText = 'Last scan: Just now • ' + total + ' cookies analyzed';
  const sum = (highCount + medCount + lowCount) || 1;
  document.getElementById('leg-high-val').innerText = highCount + ' (' + Math.round(highCount * 100 / sum) + '%)';
  document.getElementById('leg-med-val').innerText = medCount + ' (' + Math.round(medCount * 100 / sum) + '%)';
  document.getElementById('leg-low-val').innerText = lowCount + ' (' + Math.round(lowCount * 100 / sum) + '%)';
  document.getElementById('leg-unk-val').innerText = '0 (0%)';

  // 4. Detected Cookies Table
  const tbody = document.getElementById('detected-cookies-tbody');
  tbody.innerHTML = '';
  const items = (res.sesiones && res.sesiones.length > 0) ? res.sesiones : (res.grupos || []);

  if (items.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:32px; color:var(--text-muted);"><div style="font-size:15px; font-weight:600; margin-bottom:6px; color:var(--text-main);">No se detectaron cookies de sesión activas</div>Si abriste una sesión en tu navegador (Edge, Chrome, Firefox), asegúrate de haber iniciado sesión o cierra el navegador si mantiene el archivo de base de datos bloqueado exclusivamente.</td></tr>`;
  } else {
    items.forEach(c => {
      const name = c.name || c.nombre || 'Cookie';
      const host = c.host || (c.dominios ? Array.from(c.dominios).join(', ') : c.dominio) || '';
      const svc = c.servicio_id || c.nombre || 'Web';
      const isHigh = c.confianza === 'Alta' || c.critico || c.riesgo === 'Alto';
      const isMed = c.confianza === 'Media' || c.riesgo === 'Medio';
      const riskLabel = isHigh ? 'High' : (isMed ? 'Medium' : 'Low');
      const pillClass = isHigh ? 'pill-high' : (isMed ? 'pill-medium' : 'pill-low');
      const cat = c.categoria || (c.httponly ? 'Protected' : 'Authentication');
      const exp = c.expires ? String(c.expires).slice(0, 10) : (c.caducidad_max ? String(c.caducidad_max).slice(0, 10) : 'Active');

      const tr = document.createElement('tr');
      const isNew = Boolean(c.is_new);
      tr.className = 'cookie-row';
      tr.dataset.service = svc.toLowerCase();
      tr.dataset.risk = riskLabel.toLowerCase();
      tr.dataset.isNew = isNew ? 'true' : 'false';
      tr.dataset.search = (name + ' ' + host + ' ' + svc).toLowerCase();
      const newBadge = isNew ? '<span class="badge-new-session" style="background:#10b98126; color:#10b981; border:1px solid #10b981; border-radius:4px; font-size:10px; font-weight:700; padding:1px 5px; margin-left:6px;">NUEVA</span>' : '';
      tr.innerHTML = `
        <td><input type="checkbox" class="row-check"></td>
        <td>
          <div style="display:inline-flex; align-items:center; gap:6px;">
            <strong>${escapeHtml(name)}</strong>${newBadge}
            <button class="btn-info-cookie" onclick="openCookieDetailsModal(${idx})" title="Explicación técnica y propósito de ${escapeHtml(name)}" aria-label="Detalles de ${escapeHtml(name)}">ⓘ</button>
          </div>
        </td>
        <td>${escapeHtml(host)}</td>
        <td>${escapeHtml(svc)}</td>
        <td><span class="pill-badge ${pillClass}">${riskLabel}</span></td>
        <td>${escapeHtml(cat)}</td>
        <td>${escapeHtml(exp)}</td>
        <td><button class="btn-revoke-sm" onclick="triggerRevokeService('${escapeHtml(svc)}')">Revoke</button></td>
      `;
      tbody.appendChild(tr);
    });
  }

  // 5. Recent Alert Activity
  const activityList = document.getElementById('activity-alert-list');
  if (activityList) {
    activityList.innerHTML = '';
    const activeAlerts = (res.indicadores || []).filter(i => i.estado === 'alerta');
    if (activeAlerts.length === 0) {
      activityList.innerHTML = `<div style="padding:16px; color:var(--text-muted); font-size:13px;">Sin amenazas detectadas. Todos los sensores están en orden.</div>`;
    } else {
      activeAlerts.slice(0, 5).forEach(a => {
        const row = document.createElement('div');
        row.className = 'alert-row';
        row.innerHTML = `
          <div class="alert-time">Hoy</div>
          <div class="alert-status-dot" style="background:#ff3366;"></div>
          <div class="alert-info">
            <div class="alert-title">${escapeHtml(a.nombre)} (+${a.puntos || 0} pts)</div>
            <div class="alert-domain">${escapeHtml(a.motivo || a.descripcion || 'Alerta activa')}</div>
          </div>
        `;
        activityList.appendChild(row);
      });
    }
  }

  // 6. Quick Service Revocation
  const svcList = document.getElementById('quick-services-list');
  if (svcList) {
    svcList.innerHTML = '';
    if (res.grupos && res.grupos.length > 0) {
      res.grupos.slice(0, 5).forEach(g => {
        const isCrit = g.critico || g.riesgo === 'Alto';
        const row = document.createElement('div');
        row.className = 'service-row';
        row.innerHTML = `
          <div class="service-info">
            <div class="service-logo" style="color:var(--cyan); font-weight:700;">${escapeHtml((g.nombre || 'W')[0].toUpperCase())}</div>
            <div class="service-meta">
              <div class="s-name">${escapeHtml(g.nombre || 'Servicio')}</div>
              <div class="s-count">${g.cookies || 1} cookies (${escapeHtml(g.categoria || 'Auth')})</div>
            </div>
          </div>
          <div class="service-actions">
            <span class="risk-pill ${isCrit ? 'risk-high' : 'risk-none'}">${isCrit ? 'Riesgo alto' : 'Monitoreado'}</span>
            <button class="btn-revoke-sm" onclick="triggerRevokeService('${escapeHtml(g.nombre || '')}')">Revoke</button>
          </div>
        `;
        svcList.appendChild(row);
      });
    } else {
      svcList.innerHTML = '<div style="padding:24px; color:var(--text-muted); font-size:13px; text-align:center;">Sin sesiones de servicios detectadas</div>';
    }
  }

  // 7. Incidents Tab & Badge
  const incContainer = document.getElementById('incidents-container');
  if (incContainer) {
    incContainer.innerHTML = '';
    (res.indicadores || []).forEach(ind => {
      const isAlert = ind.estado === 'alerta';
      const card = document.createElement('div');
      card.style.cssText = `background:var(--bg-card); border:1px solid ${isAlert ? 'rgba(255,51,102,0.35)' : 'var(--border)'}; border-radius:10px; padding:16px; margin-bottom:12px;`;
      card.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
          <span class="pill-badge ${isAlert ? 'pill-high' : 'pill-low'}">${ind.estado.toUpperCase()}</span>
          <span style="font-weight:700; color:${isAlert ? 'var(--pink)' : 'var(--green)'};">+${ind.puntos || 0} pts</span>
        </div>
        <h3 style="font-size:15px; font-weight:700; color:var(--text-main); margin-bottom:6px;">${escapeHtml(ind.nombre)}</h3>
        <p style="font-size:13px; color:var(--text-muted); margin-bottom:6px;">${escapeHtml(ind.motivo || ind.descripcion || 'Sin anomalías.')}</p>
      `;
      incContainer.appendChild(card);
    });
  }

  const badge = document.getElementById('incident-badge');
  if (badge) {
    const alertCount = (res.indicadores || []).filter(i => i.estado === 'alerta').length;
    badge.innerText = alertCount;
    badge.style.display = alertCount > 0 ? 'inline-block' : 'none';
  }
  renderAllSessions(res);
  if (res.playbooks) renderPlaybooks(res.playbooks);
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

window.currentQuickFilter = null;

function setQuickFilter(f, btn) {
  document.querySelectorAll('.q-pill').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  if (f === 'all') {
    document.getElementById('cookie-table-search').value = '';
    document.getElementById('filter-risk').value = 'all';
    document.getElementById('filter-service').value = 'all';
    window.currentQuickFilter = null;
  } else if (f === 'high') {
    document.getElementById('filter-risk').value = 'high';
    window.currentQuickFilter = null;
  } else if (f === 'new') {
    window.currentQuickFilter = 'new';
  } else {
    document.getElementById('cookie-table-search').value = f;
    window.currentQuickFilter = null;
  }
  filterCookiesTable();
}

function filterCookiesTable() {
  const q = (document.getElementById('cookie-table-search').value || '').toLowerCase();
  const risk = document.getElementById('filter-risk').value;
  const svc = document.getElementById('filter-service').value.toLowerCase();
  const onlyNew = window.currentQuickFilter === 'new';

  document.querySelectorAll('#detected-cookies-tbody tr.cookie-row').forEach(row => {
    const text = row.innerText.toLowerCase();
    const matchQ = !q || text.includes(q);
    const matchSvc = svc === 'all' || (row.dataset.service && row.dataset.service.includes(svc)) || text.includes(svc);
    const matchRisk = risk === 'all' || row.dataset.risk === risk;
    const matchNew = !onlyNew || row.dataset.isNew === 'true';

    row.style.display = (matchQ && matchSvc && matchRisk && matchNew) ? '' : 'none';
  });
}

async function checkCanaryAlertRealtime() {
  try {
    const status = await callApi('check_canary');
    const container = document.getElementById('canary-emergency-alert-container');
    if (!container) return;
    if (status && (status.alerta_activa || (status.activadas && status.activadas > 0))) {
      if (!document.getElementById('canary-emergency-banner')) {
        container.innerHTML = `
          <div id="canary-emergency-banner" style="background:linear-gradient(90deg, #991b1b, #dc2626); color:#ffffff; padding:14px 24px; display:flex; justify-content:space-between; align-items:center; box-shadow:0 4px 16px rgba(220,38,38,0.4); border-bottom:2px solid #f87171; animation:pulseCanary 2s infinite;">
            <div style="display:flex; align-items:center; gap:12px;">
              <span style="font-size:24px;">🚨</span>
              <div>
                <div style="font-weight:700; font-size:14px; text-transform:uppercase; letter-spacing:0.5px;">¡Alerta Crítica: Acceso a Trampa Canary Detectado!</div>
                <div style="font-size:12px; opacity:0.95;">Se detectó lectura o apertura en la base de datos trampa. Posible intento de extracción o malware activo.</div>
              </div>
            </div>
            <div style="display:flex; gap:10px;">
              <button class="btn-emergency" onclick="triggerEmergencyMode()" style="background:#ffffff; color:#dc2626; border:none; font-weight:700; padding:8px 16px; border-radius:6px; cursor:pointer;">⚡ Modo Emergencia</button>
              <button onclick="document.getElementById('canary-emergency-banner').remove()" style="background:rgba(0,0,0,0.3); color:#fff; border:none; padding:8px 12px; border-radius:6px; cursor:pointer;">✕</button>
            </div>
          </div>
        `;
      }
    }
  } catch (e) {
    // ignorar fallo de sondeo
  }
}

setInterval(checkCanaryAlertRealtime, 8000);

function handleGlobalSearch(q) {
  if (!q) return;
  document.getElementById('cookie-table-search').value = q;
  filterCookiesTable();
}

window.addEventListener('DOMContentLoaded', async () => {
  const init = await callApi('get_initial_data');
  if (init && init.theme) {
    const t = (init.theme === 'claro' || init.theme === 'light') ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', t);
    const btn = document.getElementById('theme-toggle-btn');
    if (btn) btn.innerText = t === 'dark' ? '☀️' : '🌙';
  }
  if (init && init.playbooks) renderPlaybooks(init.playbooks);
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

// EXPLICACIÓN Y DETALLE DE COOKIES (MODAL ⓘ)
function getCookieExplanation(c) {
  const name = (c.name || c.nombre || '').toLowerCase();
  const host = (c.host || (c.dominios ? Array.from(c.dominios).join(', ') : c.dominio) || '').toLowerCase();
  const svc = (c.servicio_id || c.nombre || '').toLowerCase();
  const motivo = c.motivo || '';
  const isHigh = c.confianza === 'Alta' || c.critico || c.riesgo === 'Alto';
  const isMed = c.confianza === 'Media' || c.riesgo === 'Medio';

  let role = '';
  let riskExplanation = '';
  let impactText = '';
  let isRealAuthToken = false;

  if (name === 'logged_in') {
    role = 'Indicador de estado de navegación (Flag público)';
    riskExplanation = 'GitHub asigna esta cookie a cualquier visitante de github.com. Si no has iniciado sesión vale "no", y al conectarte cambia a "yes".';
    impactText = 'ℹ️ No es una credencial de acceso. Nadie puede suplantar tu cuenta de GitHub únicamente con esta cookie. El token real de sesión es user_session.';
  } else if (name === 'dotcom_user') {
    role = 'Nombre de usuario público en GitHub';
    riskExplanation = 'Almacena el alias público del usuario para personalizar la interfaz.';
    impactText = 'ℹ️ No contiene secretos de sesión ni contraseñas.';
  } else if (name === 'user_session' || name === '__host-user_session_same_site') {
    role = 'Token principal de sesión autenticada de GitHub';
    riskExplanation = 'Cookie crítica de autenticación. Mantiene el acceso a tus repositorios y cuenta.';
    impactText = '🚨 Token crítico activo. Si un atacante roba esta cookie, podría acceder a tu cuenta de GitHub sin contraseña hasta revocarla.';
    isRealAuthToken = true;
  } else if (name === 'buid' && (host.includes('microsoft') || host.includes('live.com'))) {
    role = 'Contexto de cuenta Microsoft / Azure Entra ID';
    riskExplanation = 'Identificador de contexto de inicio de sesión utilizado en login.microsoftonline.com.';
    impactText = '⚠️ Vinculado a flujos de Single Sign-On (SSO). Si sospechas compromiso, revoca sesiones en mysignins.microsoft.com.';
    isRealAuthToken = true;
  } else if (name.startsWith('estsauth') || name === 'msauth' || name === 'rpssecauth') {
    role = 'Token de autenticación federada Microsoft / Office 365';
    riskExplanation = 'Cookie crítica del catálogo oficial de inicio de sesión de Microsoft.';
    impactText = '🚨 Sesión activa. Permite acceso directo al correo, OneDrive y servicios Microsoft sin contraseña.';
    isRealAuthToken = true;
  } else if (name === 'sid' || name === 'hsid' || name === 'ssid' || name.includes('psid')) {
    role = 'Token maestro de sesión Google / Gmail';
    riskExplanation = 'Cookie de catálogo que autoriza las peticiones autenticadas en cuentas Google.';
    impactText = '🚨 Token crítico. Permite suplantar la sesión en Gmail, Drive y YouTube si no se revoca en myaccount.google.com.';
    isRealAuthToken = true;
  } else if (name.includes('session') || name.includes('sess') || name.includes('auth') || name.includes('token') || name.includes('jwt') || name.includes('login')) {
    role = 'Identificador / token de sesión web';
    riskExplanation = motivo ? ('Detectado por regla: ' + motivo) : ('El nombre coincide con patrones de sesión de usuario (' + (c.name || '') + ').');
    if (isHigh || isMed) {
      impactText = '⚠️ Podría conceder acceso autenticado al portal ' + host + '. Revoca la sesión si no reconoces la actividad.';
      isRealAuthToken = true;
    } else {
      impactText = 'ℹ️ Cookie de persistencia o sesión de navegación temporal.';
    }
  } else {
    role = 'Cookie funcional / preferencias web';
    riskExplanation = motivo || ('Registrada durante la navegación en ' + host + '.');
    impactText = 'ℹ️ Utilizada habitualmente para almacenar preferencias, idioma o estado visual.';
  }

  return { role, riskExplanation, impactText, isRealAuthToken };
}

function openCookieDetailsModal(idx) {
  const c = (window._detectedCookies || [])[idx];
  if (!c) return;

  const name = c.name || c.nombre || 'Cookie';
  const host = c.host || (c.dominios ? Array.from(c.dominios).join(', ') : c.dominio) || '';
  const svc = c.servicio_id || c.nombre || 'Web';
  const isHigh = c.confianza === 'Alta' || c.critico || c.riesgo === 'Alto';
  const isMed = c.confianza === 'Media' || c.riesgo === 'Medio';
  const riskLabel = isHigh ? 'High' : (isMed ? 'Medium' : 'Low');
  const pillClass = isHigh ? 'pill-high' : (isMed ? 'pill-medium' : 'pill-low');
  const cat = c.categoria || (c.httponly ? 'Protected' : 'Authentication');
  const exp = c.expires ? String(c.expires).slice(0, 19).replace('T', ' ') : (c.caducidad_max ? String(c.caducidad_max).slice(0, 19).replace('T', ' ') : 'Sesión de navegación');
  const isHttpOnly = Boolean(c.httponly || c.is_httponly);
  const isSecure = Boolean(c.secure || c.is_secure);
  const sameSite = c.samesite || 'Lax';

  const expl = getCookieExplanation(c);

  const modal = document.getElementById('cookie-info-modal');
  const content = document.getElementById('cookie-info-modal-content');

  content.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:16px; border-bottom:1px solid rgba(255,255,255,0.08); padding-bottom:12px;">
      <div>
        <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
          <h3 style="font-size:18px; font-weight:700; color:#fff; margin:0; word-break:break-all;">${escapeHtml(name)}</h3>
          <span class="pill-badge ${pillClass}">${riskLabel}</span>
        </div>
        <div style="font-size:13px; color:var(--text-muted);">${escapeHtml(host)} · Servicio: <strong style="color:var(--text-main);">${escapeHtml(svc)}</strong></div>
      </div>
      <button onclick="closeCookieModal()" style="background:none; border:none; color:var(--text-muted); font-size:22px; cursor:pointer; line-height:1; padding:2px 6px;" title="Cerrar">✕</button>
    </div>

    <div style="display:flex; flex-direction:column; gap:12px; font-size:13px; line-height:1.5;">
      <div style="background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.08); border-radius:8px; padding:12px;">
        <div style="font-size:11px; text-transform:uppercase; font-weight:700; color:var(--cyan); letter-spacing:0.5px; margin-bottom:4px;">Rol y Propósito</div>
        <div style="color:#fff; font-weight:600; margin-bottom:4px;">${escapeHtml(expl.role)}</div>
        <div style="color:var(--text-muted); font-size:12px;">${escapeHtml(expl.riskExplanation)}</div>
      </div>

      <div style="background:${expl.isRealAuthToken ? 'rgba(255,51,102,0.08)' : 'rgba(0,229,255,0.06)'}; border:1px solid ${expl.isRealAuthToken ? 'rgba(255,51,102,0.25)' : 'rgba(0,229,255,0.2)'}; border-radius:8px; padding:12px;">
        <div style="font-size:11px; text-transform:uppercase; font-weight:700; color:${expl.isRealAuthToken ? 'var(--pink)' : 'var(--cyan)'}; letter-spacing:0.5px; margin-bottom:4px;">Impacto en caso de exfiltración</div>
        <div style="color:#f8fafc; font-size:12px;">${escapeHtml(expl.impactText)}</div>
      </div>

      <div style="background:rgba(255,255,255,0.02); border:1px solid rgba(255,255,255,0.06); border-radius:8px; padding:12px;">
        <div style="font-size:11px; text-transform:uppercase; font-weight:700; color:var(--text-muted); letter-spacing:0.5px; margin-bottom:8px;">Protecciones del Navegador</div>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; font-size:12px;">
          <div>
            <span style="color:var(--text-muted);">HttpOnly:</span>
            <strong style="color:${isHttpOnly ? '#10b981' : '#f59e0b'}; margin-left:4px;">${isHttpOnly ? '✓ Inmune a XSS' : '✗ Legible por JS'}</strong>
          </div>
          <div>
            <span style="color:var(--text-muted);">Secure:</span>
            <strong style="color:${isSecure ? '#10b981' : '#f59e0b'}; margin-left:4px;">${isSecure ? '✓ Solo HTTPS' : '✗ Permite HTTP'}</strong>
          </div>
          <div>
            <span style="color:var(--text-muted);">SameSite:</span>
            <strong style="color:var(--text-main); margin-left:4px;">${escapeHtml(String(sameSite))}</strong>
          </div>
          <div>
            <span style="color:var(--text-muted);">Caducidad:</span>
            <strong style="color:var(--text-main); margin-left:4px;">${escapeHtml(String(exp))}</strong>
          </div>
        </div>
      </div>

      <div style="display:flex; justify-content:space-between; align-items:center; margin-top:6px; padding-top:10px; border-top:1px solid rgba(255,255,255,0.08);">
        <button class="btn-outline" style="font-size:12px; padding:6px 14px;" onclick="closeCookieModal()">Entendido</button>
        <button class="btn-revoke-sm" style="font-size:12px; padding:7px 16px;" onclick="triggerRevokeService('${escapeHtml(svc)}'); closeCookieModal();">
          Revocar sesiones en ${escapeHtml(svc)}
        </button>
      </div>
    </div>
  `;

  modal.classList.add('active');
}

function closeCookieModal(e) {
  if (e && e.target && e.target.id !== 'cookie-info-modal' && e.target.tagName !== 'BUTTON' && !e.target.closest('button')) return;
  const modal = document.getElementById('cookie-info-modal');
  if (modal) modal.classList.remove('active');
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeCookieModal();
});

</script>
</body>
</html>"""



def launch(debug: bool = False, browser_mode: bool = False) -> int:
    """Lanza la consola Cyber SOC idéntica al diseño oficial (ventana nativa o navegador)."""
    api = BridgeApi()
    html_content = get_dashboard_html()

    server = LocalDashboardServer(api, html_content)
    port = server.start()
    local_url = f"http://127.0.0.1:{port}/"

    if browser_mode:
        print(f"🛡️  CookieGuard v{VERSION} · Consola Cyber SOC iniciada:")
        print(f"    URL Local: {local_url}")
        print("    Abriendo en tu navegador predeterminado... (Pulsa Ctrl+C para detener)")
        webbrowser.open(local_url)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nDeteniendo servidor local de CookieGuard...")
        finally:
            server.stop()
        return 0

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
        print(f"[!] Aviso: abriendo dashboard local en navegador ({e})", file=sys.stderr)
        webbrowser.open(local_url)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nDeteniendo servidor local...")
        finally:
            server.stop()
        return 0


if __name__ == "__main__":
    sys.exit(launch(debug="--debug" in sys.argv))
