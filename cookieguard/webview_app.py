"""CookieGuard v2.6.1 · Consola de escritorio moderna basada en PyWebView."""
from __future__ import annotations

import json
import os
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
    """Puente bidireccional seguro entre el frontend web y los modulos locales de CookieGuard."""

    def __init__(self):
        self.last_res: Optional[Dict[str, Any]] = None
        self._lock = threading.Lock()

    def get_initial_data(self) -> Dict[str, Any]:
        """Devuelve el estado inicial, configuracion y comprobacion de versiones previas."""
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
                        if any(v in item for v in ["2.4", "2.5.0", "2.5.1", "CookieGuard-App", "CookieGuard-v2.5"]):
                            candidates.append(item)
            if candidates:
                warning_old = (
                    f"Atencion: Se han detectado copias o carpetas de versiones anteriores en este equipo "
                    f"({', '.join(set(candidates))}). Asegurate de utilizar este acceso v{VERSION}."
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
            return {"ok": True, "path": str(p)}
        except Exception as e:
            return {"ok": False, "error": str(e)}

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
                return {"ok": True, "servicios": playbooks.SERVICES_CATALOG}
            else:
                return {"ok": False, "error": f"Herramienta desconocida: {tool_id}"}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    def save_theme_preference(self, theme: str) -> bool:
        """Guarda la preferencia visual en el archivo de configuracion local."""
        try:
            save_user_config({"tema": theme})
            return True
        except Exception:
            return False


def get_dashboard_html() -> str:
    """Genera el código HTML, CSS y JS integrado para el dashboard de PyWebView."""
    # Retorna un HTML autocontenido con diseño moderno Cyber SOC y Fluent
    return """<!DOCTYPE html>
<html lang="es" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CookieGuard · Session Security</title>
<style>
:root {
  --bg-app: #080c14;
  --bg-sidebar: #0c121e;
  --bg-card: #111827;
  --bg-card-hover: #172033;
  --bg-subtle: #1e293b;
  --border: #1f293d;
  --border-focus: #38bdf8;
  --text-main: #f8fafc;
  --text-muted: #94a3b8;
  --text-faint: #64748b;
  --accent: #0284c7;
  --accent-glow: rgba(2, 132, 199, 0.25);
  --green: #10b981;
  --green-glow: rgba(16, 185, 129, 0.2);
  --amber: #f59e0b;
  --amber-glow: rgba(245, 158, 11, 0.2);
  --red: #ef4444;
  --red-glow: rgba(239, 68, 68, 0.2);
  --radius-sm: 8px;
  --radius-md: 12px;
  --radius-lg: 16px;
  --font-family: -apple-system, BlinkMacSystemFont, "Segoe UI Variable", "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}

[data-theme="light"] {
  --bg-app: #f1f5f9;
  --bg-sidebar: #ffffff;
  --bg-card: #ffffff;
  --bg-card-hover: #f8fafc;
  --bg-subtle: #e2e8f0;
  --border: #cbd5e1;
  --border-focus: #0284c7;
  --text-main: #0f172a;
  --text-muted: #475569;
  --text-faint: #94a3b8;
  --accent: #0284c7;
  --accent-glow: rgba(2, 132, 199, 0.15);
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: var(--font-family);
  background: var(--bg-app);
  color: var(--text-main);
  height: 100vh;
  overflow: hidden;
  display: flex;
}

/* Sidebar */
.sidebar {
  width: 250px;
  background: var(--bg-sidebar);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
  user-select: none;
}
.sidebar-header {
  padding: 20px 18px 16px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 12px;
}
.brand-icon {
  width: 38px;
  height: 38px;
  background: linear-gradient(135deg, #0284c7, #38bdf8);
  border-radius: var(--radius-md);
  display: flex;
  align-items: center;
  justify-content: center;
  color: #fff;
  font-size: 20px;
  box-shadow: 0 4px 14px var(--accent-glow);
}
.brand-text h1 { font-size: 16px; font-weight: 700; letter-spacing: -0.3px; }
.brand-text p { font-size: 9.5px; font-weight: 600; color: var(--text-muted); letter-spacing: 0.8px; text-transform: uppercase; }

.nav-list {
  padding: 14px 10px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  flex: 1;
  overflow-y: auto;
}
.nav-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 14px;
  border-radius: var(--radius-sm);
  color: var(--text-muted);
  cursor: pointer;
  font-size: 13.5px;
  font-weight: 500;
  transition: all 0.15s ease;
  border: 1px solid transparent;
}
.nav-item:hover {
  background: var(--bg-subtle);
  color: var(--text-main);
}
.nav-item.active {
  background: var(--bg-subtle);
  color: var(--border-focus);
  font-weight: 600;
  border-color: var(--border);
}
.nav-item .icon { font-size: 16px; width: 20px; text-align: center; }

.sidebar-footer {
  padding: 14px 16px;
  border-top: 1px solid var(--border);
  font-size: 11px;
  color: var(--text-faint);
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.badge-offline {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 8px;
  background: rgba(16, 185, 129, 0.12);
  color: var(--green);
  border-radius: 999px;
  font-size: 10px;
  font-weight: 600;
}
.badge-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--green); }

/* Main layout */
.main {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.topbar {
  height: 64px;
  border-bottom: 1px solid var(--border);
  padding: 0 28px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: var(--bg-sidebar);
}
.topbar-title {
  display: flex;
  align-items: center;
  gap: 10px;
}
.topbar-title h2 { font-size: 18px; font-weight: 600; }
.system-status {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  border-radius: 999px;
  font-size: 11.5px;
  font-weight: 600;
  background: rgba(16, 185, 129, 0.12);
  color: var(--green);
  border: 1px solid rgba(16, 185, 129, 0.25);
}

.topbar-actions {
  display: flex;
  align-items: center;
  gap: 10px;
}
.btn {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  border-radius: var(--radius-sm);
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  border: 1px solid transparent;
  transition: all 0.15s ease;
  user-select: none;
}
.btn-primary {
  background: var(--accent);
  color: #fff;
  box-shadow: 0 2px 8px var(--accent-glow);
}
.btn-primary:hover { filter: brightness(1.1); transform: translateY(-1px); }
.btn-danger {
  background: rgba(239, 68, 68, 0.12);
  color: var(--red);
  border-color: rgba(239, 68, 68, 0.25);
}
.btn-danger:hover { background: var(--red); color: #fff; }
.btn-subtle {
  background: var(--bg-subtle);
  color: var(--text-main);
  border-color: var(--border);
}
.btn-subtle:hover { background: var(--bg-card-hover); border-color: var(--border-focus); }

/* Content Views */
.content-area {
  flex: 1;
  padding: 24px 28px;
  overflow-y: auto;
}
.view-panel { display: none; }
.view-panel.active { display: block; animation: fadeIn 0.2s ease; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(3px); } to { opacity: 1; transform: translateY(0); } }

/* Cards & Grid */
.grid-kpi {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 14px;
  margin-bottom: 22px;
}
.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 18px 20px;
  transition: border-color 0.15s ease;
}
.card:hover { border-color: rgba(56, 189, 248, 0.35); }
.card-kpi .kpi-label { font-size: 12px; color: var(--text-muted); font-weight: 500; }
.card-kpi .kpi-val { font-size: 26px; font-weight: 700; margin: 8px 0 4px; display: flex; align-items: baseline; gap: 8px; }
.card-kpi .kpi-sub { font-size: 11px; color: var(--text-faint); }

.hero-dashboard {
  display: grid;
  grid-template-columns: 340px 1fr;
  gap: 18px;
  margin-bottom: 22px;
}
.gauge-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: 26px 20px;
}
.svg-gauge { width: 140px; height: 140px; transform: rotate(-90deg); }
.gauge-bg { fill: none; stroke: var(--bg-subtle); stroke-width: 10; }
.gauge-arc {
  fill: none;
  stroke: var(--green);
  stroke-width: 10;
  stroke-linecap: round;
  stroke-dasharray: 377;
  stroke-dashoffset: 60;
  transition: stroke-dashoffset 0.8s cubic-bezier(0.4, 0, 0.2, 1), stroke 0.4s ease;
}
.gauge-text {
  position: absolute;
  font-size: 32px;
  font-weight: 800;
  letter-spacing: -1px;
}
.gauge-container {
  position: relative;
  width: 140px;
  height: 140px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 14px;
}
.gauge-title { font-size: 16px; font-weight: 700; margin-bottom: 4px; }
.gauge-desc { font-size: 12px; color: var(--text-muted); max-width: 260px; line-height: 1.4; }

/* Tables */
.table-wrapper {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  overflow: hidden;
}
.table-header-bar {
  padding: 14px 18px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
}
.search-box {
  display: flex;
  align-items: center;
  gap: 8px;
  background: var(--bg-subtle);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 6px 12px;
  width: 280px;
}
.search-box input {
  background: transparent;
  border: none;
  color: var(--text-main);
  outline: none;
  font-size: 12.5px;
  width: 100%;
}
.filter-pills { display: flex; gap: 6px; }
.filter-pill {
  font-size: 11.5px;
  padding: 4px 10px;
  border-radius: 999px;
  background: var(--bg-subtle);
  color: var(--text-muted);
  cursor: pointer;
  user-select: none;
}
.filter-pill.active { background: var(--accent); color: #fff; font-weight: 600; }

table { width: 100%; border-collapse: collapse; text-align: left; font-size: 12.5px; }
th {
  background: var(--bg-sidebar);
  color: var(--text-muted);
  font-weight: 600;
  padding: 10px 16px;
  border-bottom: 1px solid var(--border);
  text-transform: uppercase;
  font-size: 10.5px;
  letter-spacing: 0.5px;
}
td {
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
  color: var(--text-main);
}
tr:hover td { background: var(--bg-card-hover); }
.badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 8px;
  border-radius: var(--radius-sm);
  font-size: 11px;
  font-weight: 600;
}
.badge-crit { background: rgba(239, 68, 68, 0.15); color: var(--red); border: 1px solid rgba(239, 68, 68, 0.3); }
.badge-warn { background: rgba(245, 158, 11, 0.15); color: var(--amber); border: 1px solid rgba(245, 158, 11, 0.3); }
.badge-ok { background: rgba(16, 185, 129, 0.15); color: var(--green); border: 1px solid rgba(16, 185, 129, 0.3); }
.badge-muted { background: var(--bg-subtle); color: var(--text-muted); }

/* Playbook Cards */
.playbook-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 14px;
}
.playbook-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 18px;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
}
.pb-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
.pb-title { font-size: 14px; font-weight: 600; }
.pb-actions { display: flex; flex-direction: column; gap: 6px; margin-top: 14px; }
.pb-btn {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 7px 12px;
  background: var(--bg-subtle);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  font-size: 11.5px;
  color: var(--text-main);
  cursor: pointer;
  text-decoration: none;
}
.pb-btn:hover { background: var(--border); border-color: var(--border-focus); }

/* Terminal Log View */
.terminal-card {
  background: #05080f;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 16px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 12px;
  color: #38bdf8;
  height: 380px;
  overflow-y: auto;
  white-space: pre-wrap;
  line-height: 1.5;
}

/* Spinner */
.spinner {
  display: inline-block;
  width: 14px;
  height: 14px;
  border: 2px solid rgba(255, 255, 255, 0.3);
  border-radius: 50%;
  border-top-color: #fff;
  animation: spin 0.6s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>

<!-- SIDEBAR -->
<aside class="sidebar">
  <div class="sidebar-header">
    <div class="brand-icon">🛡️</div>
    <div class="brand-text">
      <h1>CookieGuard</h1>
      <p>Session Security</p>
    </div>
  </div>

  <nav class="nav-list">
    <div class="nav-item active" onclick="switchTab('resumen')">
      <span class="icon">📊</span>
      <span>Resumen</span>
    </div>
    <div class="nav-item" onclick="switchTab('sesiones')">
      <span class="icon">🍪</span>
      <span>Sesiones Activas</span>
    </div>
    <div class="nav-item" onclick="switchTab('indicadores')">
      <span class="icon">⚠️</span>
      <span>Indicadores MITRE</span>
    </div>
    <div class="nav-item" onclick="switchTab('canary')">
      <span class="icon">🪤</span>
      <span>Trampas Canary</span>
    </div>
    <div class="nav-item" onclick="switchTab('extensiones')">
      <span class="icon">🧩</span>
      <span>Extensiones</span>
    </div>
    <div class="nav-item" onclick="switchTab('playbooks')">
      <span class="icon">🔄</span>
      <span>Playbooks de Rotación</span>
    </div>
    <div class="nav-item" onclick="switchTab('herramientas')">
      <span class="icon">🛠️</span>
      <span>Herramientas & Rescate</span>
    </div>
    <div class="nav-item" onclick="switchTab('ajustes')">
      <span class="icon">⚙️</span>
      <span>Ajustes</span>
    </div>
  </nav>

  <div class="sidebar-footer">
    <div class="badge-offline">
      <div class="badge-dot"></div>
      <span>100% Offline</span>
    </div>
    <span id="txt-version">v2.6.0</span>
  </div>
</aside>

<!-- MAIN CONTENT -->
<main class="main">
  <!-- TOPBAR -->
  <header class="topbar">
    <div class="topbar-left" style="display:flex; align-items:center; gap:14px;">
      <div class="topbar-title">
        <h2 id="page-title" style="font-size:17px; font-weight:700;">Panel de Seguridad de Sesiones</h2>
      </div>
      <div class="badge-version" id="txt-top-version" style="background:rgba(2,132,199,0.15); color:#38bdf8; border:1px solid rgba(56,189,248,0.3); padding:3px 9px; border-radius:999px; font-size:11px; font-weight:600;">v2.6.1 · Oficial Activa</div>
      <div class="system-status" id="system-badge" style="display:flex; align-items:center; gap:6px; font-size:11.5px; color:var(--text-muted);">
        <span class="badge-dot" style="background:var(--green); width:6px; height:6px; border-radius:50%;"></span>
        <span id="system-status-text">Protección Activa</span>
      </div>
    </div>

    <div class="topbar-actions">
      <button class="btn btn-primary" id="btn-scan" onclick="triggerScan()">
        <span id="scan-icon">⌕</span>
        <span id="scan-label">Analizar ahora</span>
      </button>
      <button class="btn btn-danger" onclick="triggerIncidentZip()">
        <span>🚨</span>
        <span>Modo Incidente</span>
      </button>
      <button class="btn btn-subtle" onclick="toggleTheme()">
        <span id="theme-icon">☾</span>
      </button>
    </div>
  </header>
  <!-- WARNING BANNER -->
  <div id="warning-banner-container"></div>

  <!-- CONTENT VIEWS -->
  <div class="content-area">

    <!-- VIEW 1: RESUMEN -->
    <div class="view-panel active" id="view-resumen">
      <div class="grid-kpi">
        <div class="card card-kpi">
          <div class="kpi-label">Cookies de sesión</div>
          <div class="kpi-val"><span id="kpi-cookies">0</span></div>
          <div class="kpi-sub">Almacenadas localmente</div>
        </div>
        <div class="card card-kpi">
          <div class="kpi-label">Servicios activos</div>
          <div class="kpi-val"><span id="kpi-servicios">0</span></div>
          <div class="kpi-sub"><span id="kpi-criticos">0</span> críticos</div>
        </div>
        <div class="card card-kpi">
          <div class="kpi-label">Perfiles de navegador</div>
          <div class="kpi-val"><span id="kpi-perfiles">0</span></div>
          <div class="kpi-sub">Chrome, Edge, Firefox, Brave</div>
        </div>
        <div class="card card-kpi">
          <div class="kpi-label">Trampas Canary</div>
          <div class="kpi-val"><span id="kpi-canary">0</span></div>
          <div class="kpi-sub" id="kpi-canary-sub">Cebo anti-infostealer</div>
        </div>
        <div class="card card-kpi">
          <div class="kpi-label">Alertas de riesgo</div>
          <div class="kpi-val"><span id="kpi-alertas">0</span></div>
          <div class="kpi-sub" id="kpi-alertas-sub">Detecciones heurísticas</div>
        </div>
      </div>

      <div class="hero-dashboard">
        <div class="card gauge-card">
          <div class="gauge-container">
            <svg class="svg-gauge" viewBox="0 0 140 140">
              <circle class="gauge-bg" cx="70" cy="70" r="60" />
              <circle class="gauge-arc" id="gauge-arc" cx="70" cy="70" r="60" />
            </svg>
            <div class="gauge-text" id="gauge-score">0</div>
          </div>
          <div class="gauge-title" id="gauge-level">Sin análisis</div>
          <div class="gauge-desc" id="gauge-summary">Pulsa 'Analizar ahora' para auditar las sesiones locales sin telemetría ni descifrado sensible.</div>
        </div>

        <div class="card" style="display: flex; flex-direction: column; justify-content: space-between;">
          <div>
            <h3 style="font-size: 15px; font-weight: 600; margin-bottom: 8px;">Pistas de Seguridad y Recomendaciones</h3>
            <p id="findings-text" style="font-size: 13px; color: var(--text-muted); line-height: 1.5; margin-bottom: 14px;">
              Ninguna amenaza detectada en los almacenes locales de cookies.
            </p>
          </div>

          <div style="display: flex; gap: 10px;">
            <button class="btn btn-subtle" onclick="exportData('html')">📄 Exportar HTML</button>
            <button class="btn btn-subtle" onclick="exportData('json')">Exportar JSON</button>
            <button class="btn btn-subtle" onclick="exportData('csv')">Exportar CSV</button>
          </div>
        </div>
      </div>

      <!-- Quick Session Preview -->
      <div class="table-wrapper">
        <div class="table-header-bar">
          <strong style="font-size: 13.5px;">Servicios Críticos Detectados</strong>
          <button class="btn btn-subtle" style="padding: 5px 12px; font-size: 12px;" onclick="switchTab('sesiones')">Ver todas las sesiones &rarr;</button>
        </div>
        <table>
          <thead>
            <tr>
              <th>Servicio</th>
              <th>Navegador / Perfil</th>
              <th>Cookies</th>
              <th>Estado</th>
              <th>Acción de Seguridad</th>
            </tr>
          </thead>
          <tbody id="preview-sessions-body">
            <tr><td colspan="5" style="text-align:center; color:var(--text-faint); padding: 24px;">No hay análisis activo. Pulsa 'Analizar ahora'.</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- VIEW 2: SESIONES -->
    <div class="view-panel" id="view-sesiones">
      <div class="table-wrapper">
        <div class="table-header-bar">
          <div class="search-box">
            <span>🔍</span>
            <input type="text" id="search-input" placeholder="Buscar por servicio, dominio o perfil..." oninput="filterSessions()">
          </div>
          <div class="filter-pills">
            <div class="filter-pill active" onclick="setFilter('todos', this)">Todos</div>
            <div class="filter-pill" onclick="setFilter('criticos', this)">Críticos</div>
            <div class="filter-pill" onclick="setFilter('zombie', this)">Sesiones Zombie</div>
            <div class="filter-pill" onclick="setFilter('nuevas', this)">Nuevas</div>
          </div>
        </div>
        <table>
          <thead>
            <tr>
              <th>Servicio / Dominio</th>
              <th>Categoría</th>
              <th>Navegador</th>
              <th>Perfil</th>
              <th>Total Cookies</th>
              <th>Caducidad</th>
              <th>Acciones</th>
            </tr>
          </thead>
          <tbody id="sessions-table-body">
            <tr><td colspan="7" style="text-align:center; color:var(--text-faint); padding: 30px;">Ejecuta un análisis para inspeccionar las sesiones.</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- VIEW 3: INDICADORES -->
    <div class="view-panel" id="view-indicadores">
      <div style="margin-bottom: 16px;">
        <h3 style="font-size: 16px; font-weight: 600;">Indicadores Heurísticos de Exfiltración (MITRE ATT&CK)</h3>
        <p style="font-size: 12.5px; color: var(--text-muted);">Detección pasiva de robos de cookies en frío, accesos no autorizados a bases SQLite y manipulaciones de Local State.</p>
      </div>
      <div id="indicators-container" style="display: flex; flex-direction: column; gap: 10px;">
        <div class="card" style="padding: 20px; color: var(--text-muted);">Sin indicadores calculados todavía.</div>
      </div>
    </div>

    <!-- VIEW 4: CANARY -->
    <div class="view-panel" id="view-canary">
      <div class="card" style="margin-bottom: 18px;">
        <h3 style="font-size: 15px; font-weight: 600; margin-bottom: 6px;">Trampas Canary Señuelo (Canary Vault)</h3>
        <p style="font-size: 12.5px; color: var(--text-muted); line-height: 1.5; margin-bottom: 14px;">
          Despliega archivos de bases de datos de cookies cebo con credenciales falsas en los directorios de los navegadores. Si un infostealer intenta leerlas o copiarlas en masa, CookieGuard detecta el acceso y activa la alerta inmediata.
        </p>
        <div style="display: flex; gap: 10px;">
          <button class="btn btn-primary" onclick="triggerDeployCanary()">🪤 Desplegar / Rearmar Trampas</button>
          <button class="btn btn-subtle" onclick="triggerCheckCanary()">Comprobar Integridad</button>
        </div>
      </div>

      <div class="card">
        <h4 style="font-size: 13.5px; font-weight: 600; margin-bottom: 12px;">Estado Actual de las Trampas</h4>
        <div id="canary-status-details" style="font-size: 13px; color: var(--text-muted);">
          Cargando estado de trampas...
        </div>
      </div>
    </div>

    <!-- VIEW 5: EXTENSIONES -->
    <div class="view-panel" id="view-extensiones">
      <div style="margin-bottom: 16px;">
        <h3 style="font-size: 16px; font-weight: 600;">Auditoría de Extensiones de Navegador</h3>
        <p style="font-size: 12.5px; color: var(--text-muted);">Inspección de complementos instalados con permisos de acceso a cookies, interceptación de tráfico (webRequest) o modo desarrollador.</p>
      </div>
      <div id="extensions-container" class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Extensión</th>
              <th>Navegador</th>
              <th>Modo Desempaquetada</th>
              <th>Permisos Sensibles</th>
              <th>Riesgo</th>
            </tr>
          </thead>
          <tbody id="extensions-table-body">
            <tr><td colspan="5" style="text-align:center; color:var(--text-faint); padding: 30px;">Realiza un análisis para cargar las extensiones.</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- VIEW 6: PLAYBOOKS -->
    <div class="view-panel" id="view-playbooks">
      <div style="margin-bottom: 16px;">
        <h3 style="font-size: 16px; font-weight: 600;">Playbooks de Revocación y Cierre de Sesiones</h3>
        <p style="font-size: 12.5px; color: var(--text-muted);">Acceso directo a las consolas oficiales de seguridad para cerrar sesiones concurrentes y cambiar contraseñas ante sospecha de robo.</p>
      </div>
      <div class="playbook-grid" id="playbooks-container">
        <!-- Rendered dynamically -->
      </div>
    </div>

    <!-- VIEW 7: HERRAMIENTAS -->
    <div class="view-panel" id="view-herramientas">
      <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 14px;">
        <button class="btn btn-subtle" onclick="execTool('persistence')">Persistencia & Tareas</button>
        <button class="btn btn-subtle" onclick="execTool('network')">Red & Hosts</button>
        <button class="btn btn-subtle" onclick="execTool('integrity')">Integridad Binarios</button>
        <button class="btn btn-subtle" onclick="execTool('health')">Doctor de Sensores</button>
        <button class="btn btn-subtle" onclick="execTool('clipboard')">Portapapeles</button>
        <button class="btn btn-subtle" onclick="execTool('clear_clipboard')">Limpiar Portapapeles</button>
        <button class="btn btn-subtle" onclick="execTool('downloads')">Descargas Recientes</button>
        <button class="btn btn-danger" onclick="triggerRescuePlan()">Plan Rescate Zero-Trust</button>
      </div>
      <div class="terminal-card" id="terminal-output">Selecciona una herramienta para ejecutarla en modo local seguro...</div>
    </div>

    <!-- VIEW 8: AJUSTES -->
    <div class="view-panel" id="view-ajustes">
      <div class="card" style="max-width: 600px;">
        <h3 style="font-size: 15px; font-weight: 600; margin-bottom: 14px;">Preferencias de CookieGuard</h3>
        <div style="margin-bottom: 16px;">
          <label style="font-size: 13px; font-weight: 500; display: block; margin-bottom: 6px;">Tema visual de la interfaz</label>
          <div style="display: flex; gap: 10px;">
            <button class="btn btn-subtle" onclick="setTheme('oscuro')">☾ Oscuro (Cyber SOC)</button>
            <button class="btn btn-subtle" onclick="setTheme('claro')">☼ Claro (Fluent)</button>
          </div>
        </div>
        <div style="padding-top: 14px; border-top: 1px solid var(--border); font-size: 12px; color: var(--text-muted); line-height: 1.5;">
          CookieGuard opera en estricta conformidad con las políticas de cero telemetría. Toda la información se procesa en la memoria volátil de tu equipo y nunca se transmiten cookies ni contraseñas.
        </div>
      </div>
    </div>

  </div>
</main>

<script>
// Global state
let appState = {
  theme: "dark",
  lastRes: null,
  activeFilter: "todos"
};

// Robust Promise-based bridge handler
let bridgeReadyPromise = null;

function waitForBridge() {
  if (bridgeReadyPromise) return bridgeReadyPromise;
  bridgeReadyPromise = new Promise((resolve) => {
    if (window.pywebview && window.pywebview.api && Object.keys(window.pywebview.api).length > 0) {
      return resolve(window.pywebview.api);
    }
    const onReady = () => {
      window.removeEventListener("pywebviewready", onReady);
      resolve(window.pywebview ? window.pywebview.api : null);
    };
    window.addEventListener("pywebviewready", onReady);

    let attempts = 0;
    const interval = setInterval(() => {
      attempts++;
      if (window.pywebview && window.pywebview.api && Object.keys(window.pywebview.api).length > 0) {
        clearInterval(interval);
        window.removeEventListener("pywebviewready", onReady);
        resolve(window.pywebview.api);
      } else if (attempts >= 40) {
        clearInterval(interval);
        window.removeEventListener("pywebviewready", onReady);
        resolve(window.pywebview ? window.pywebview.api : null);
      }
    }, 100);
  });
  return bridgeReadyPromise;
}

async function callApi(method, ...args) {
  const api = await waitForBridge();
  if (api && typeof api[method] === "function") {
    try {
      return await api[method](...args);
    } catch (err) {
      console.error(`[CookieGuard Bridge] Error en ${method}:`, err);
      return null;
    }
  }
  console.warn(`[CookieGuard Bridge] Metodo '${method}' no disponible.`);
  return null;
}

// Navigation
function switchTab(tabId) {
  document.querySelectorAll(".nav-item").forEach(item => item.classList.remove("active"));
  document.querySelectorAll(".view-panel").forEach(panel => panel.classList.remove("active"));

  const targetNav = Array.from(document.querySelectorAll(".nav-item")).find(el => el.getAttribute("onclick") && el.getAttribute("onclick").includes(tabId));
  if (targetNav) targetNav.classList.add("active");

  const targetPanel = document.getElementById("view-" + tabId);
  if (targetPanel) targetPanel.classList.add("active");

  const titles = {
    resumen: "Panel de Seguridad de Sesiones",
    sesiones: "Inventario de Sesiones Activas",
    indicadores: "Indicadores de Exfiltración y MITRE ATT&CK",
    canary: "Trampas Canary Anti-Infostealer",
    extensiones: "Auditoría de Extensiones",
    playbooks: "Playbooks y Revocación Rápida",
    herramientas: "Herramientas de Auditoría & Rescate",
    ajustes: "Configuración Local"
  };
  document.getElementById("page-title").textContent = titles[tabId] || "CookieGuard";
}

// Theme
function setTheme(t) {
  appState.theme = t === "claro" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", appState.theme);
  document.getElementById("theme-icon").textContent = appState.theme === "dark" ? "☾" : "☼";
  callApi("save_theme_preference", t);
}

function toggleTheme() {
  setTheme(appState.theme === "dark" ? "claro" : "oscuro");
}

// Scan action
async function triggerScan() {
  const btn = document.getElementById("btn-scan");
  const icon = document.getElementById("scan-icon");
  const label = document.getElementById("scan-label");
  const sysStatus = document.getElementById("system-status-text");

  btn.style.pointerEvents = "none";
  icon.innerHTML = '<span class="spinner"></span>';
  label.textContent = "Analizando...";
  sysStatus.textContent = "Escaneando sesiones...";

  try {
    const res = await callApi("run_scan");
    if (res) {
      updateDashboardWithData(res);
    }
  } catch (e) {
    console.error("Scan error:", e);
  } finally {
    btn.style.pointerEvents = "auto";
    icon.innerHTML = "⌕";
    label.textContent = "Analizar ahora";
    sysStatus.textContent = "Protección Activa";
  }
}

// Update dashboard
function updateDashboardWithData(res) {
  appState.lastRes = res;
  const v = res.veredicto || {};
  const stats = res.estadisticas || {};
  const grupos = res.grupos || [];
  const ind = res.indicadores || [];

  // KPIs
  document.getElementById("kpi-cookies").textContent = stats.total_cookies || 0;
  document.getElementById("kpi-servicios").textContent = stats.servicios_unicos || grupos.length;
  document.getElementById("kpi-criticos").textContent = stats.servicios_criticos || 0;
  document.getElementById("kpi-perfiles").textContent = stats.total_perfiles || 0;
  document.getElementById("kpi-alertas").textContent = stats.alertas_activas || 0;

  // Gauge Score
  const pts = v.puntos || 0;
  const scoreElem = document.getElementById("gauge-score");
  scoreElem.textContent = pts;

  const arc = document.getElementById("gauge-arc");
  const maxPts = 100;
  const ratio = Math.min(pts / maxPts, 1);
  const offset = 377 - (377 * (1 - ratio));
  arc.style.strokeDashoffset = offset;

  const nivel = v.nivel || "verde";
  const colors = { verde: "#10b981", amarillo: "#f59e0b", rojo: "#ef4444", gris: "#94a3b8" };
  arc.style.stroke = colors[nivel] || "#10b981";

  const levelElem = document.getElementById("gauge-level");
  levelElem.textContent = "Nivel: " + (v.nombre || "Verde").toUpperCase();
  levelElem.style.color = colors[nivel] || "#10b981";

  document.getElementById("gauge-summary").textContent = v.texto || "Sin anomalías detectadas en sesiones activas.";
  document.getElementById("findings-text").textContent = (v.principales && v.principales.length)
    ? v.principales.join(" · ")
    : "Sin indicios de exfiltración en frío ni manipulación de DPAPI.";

  // Render tables
  renderSessionTables(grupos);
  renderIndicators(ind);
  renderExtensions(res.extensiones || []);
}

function renderSessionTables(grupos) {
  const pBody = document.getElementById("preview-sessions-body");
  const fullBody = document.getElementById("sessions-table-body");

  if (!grupos.length) {
    pBody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 20px; color:var(--text-faint);">No se encontraron cookies de sesión.</td></tr>';
    fullBody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding: 30px; color:var(--text-faint);">No se encontraron cookies de sesión.</td></tr>';
    return;
  }

  // Preview table (top 5 critical)
  const sortedCrit = [...grupos].sort((a,b) => (b.critico ? 1 : 0) - (a.critico ? 1 : 0));
  pBody.innerHTML = sortedCrit.slice(0, 5).map(g => `
    <tr>
      <td><strong>${escapeHtml(g.nombre || g.dominio)}</strong><br><small style="color:var(--text-faint)">${escapeHtml(g.dominio)}</small></td>
      <td>${escapeHtml(g.navegador || '-')} (${escapeHtml(g.perfil || 'Default')})</td>
      <td>${g.total_cookies || 0}</td>
      <td>${g.critico ? '<span class="badge badge-crit">Crítico</span>' : '<span class="badge badge-ok">Normal</span>'}</td>
      <td><button class="btn btn-subtle" style="padding:4px 8px; font-size:11px;" onclick="openRevoke('${escapeHtml(g.dominio)}')">Revocar</button></td>
    </tr>
  `).join("");

  renderFilteredSessions(grupos);
}

function renderFilteredSessions(grupos) {
  const fullBody = document.getElementById("sessions-table-body");
  const search = (document.getElementById("search-input").value || "").toLowerCase();
  const filter = appState.activeFilter;

  const filtered = grupos.filter(g => {
    const textMatch = (g.nombre || "").toLowerCase().includes(search) || (g.dominio || "").toLowerCase().includes(search);
    if (!textMatch) return false;
    if (filter === "criticos") return g.critico;
    if (filter === "zombie") return g.zombie;
    if (filter === "nuevas") return g.nuevas;
    return true;
  });

  if (!filtered.length) {
    fullBody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding: 24px; color:var(--text-faint);">No hay sesiones que coincidan con la búsqueda.</td></tr>';
    return;
  }

  fullBody.innerHTML = filtered.map(g => `
    <tr>
      <td><strong>${escapeHtml(g.nombre || g.dominio)}</strong><br><small style="color:var(--text-faint)">${escapeHtml(g.dominio)}</small></td>
      <td><span class="badge badge-muted">${escapeHtml(g.categoria || 'Otros')}</span></td>
      <td>${escapeHtml(g.navegador || '-')}</td>
      <td>${escapeHtml(g.perfil || 'Default')}</td>
      <td><strong>${g.total_cookies || 0}</strong></td>
      <td>${escapeHtml(g.caduca_max || '-')}</td>
      <td><button class="btn btn-subtle" style="padding:4px 8px; font-size:11px;" onclick="openRevoke('${escapeHtml(g.dominio)}')">Revocar</button></td>
    </tr>
  `).join("");
}

function filterSessions() {
  if (appState.lastRes && appState.lastRes.grupos) {
    renderFilteredSessions(appState.lastRes.grupos);
  }
}

function setFilter(f, btn) {
  appState.activeFilter = f;
  document.querySelectorAll(".filter-pill").forEach(p => p.classList.remove("active"));
  btn.classList.add("active");
  filterSessions();
}

function renderIndicators(ind) {
  const container = document.getElementById("indicators-container");
  if (!ind.length) {
    container.innerHTML = '<div class="card" style="padding: 20px; color:var(--text-muted);">Sin indicadores calculados.</div>';
    return;
  }
  container.innerHTML = ind.map(i => `
    <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
      <div>
        <div style="font-weight:600; font-size:13.5px; margin-bottom:4px;">${escapeHtml(i.nombre || i.id)}</div>
        <div style="font-size:12px; color:var(--text-muted);">${escapeHtml(i.descripcion || '-')}</div>
      </div>
      <div>
        ${i.estado === "alerta" ? '<span class="badge badge-crit">ALERTA</span>' : '<span class="badge badge-ok">NORMAL</span>'}
      </div>
    </div>
  `).join("");
}

function renderExtensions(ext) {
  const tbody = document.getElementById("extensions-table-body");
  if (!ext.length) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 24px; color:var(--text-faint);">No se detectaron extensiones instaladas.</td></tr>';
    return;
  }
  tbody.innerHTML = ext.map(e => `
    <tr>
      <td><strong>${escapeHtml(e.nombre || e.id)}</strong></td>
      <td>${escapeHtml(e.navegador || '-')}</td>
      <td>${e.desempaquetada ? '<span class="badge badge-warn">SÍ</span>' : '<span class="badge badge-muted">NO</span>'}</td>
      <td>${(e.permisos_sensibles || []).map(p => `<span class="badge badge-muted" style="margin-right:3px;">${escapeHtml(p)}</span>`).join("")}</td>
      <td>${e.critico ? '<span class="badge badge-crit">ALTO</span>' : '<span class="badge badge-ok">BAJO</span>'}</td>
    </tr>
  `).join("");
}

// Canary
async function triggerDeployCanary() {
  const res = await callApi("deploy_canary");
  updateCanaryDetails(res);
}

async function triggerCheckCanary() {
  const res = await callApi("check_canary");
  updateCanaryDetails(res);
}

function updateCanaryDetails(status) {
  if (!status) return;
  document.getElementById("kpi-canary").textContent = status.total_trampas || 0;
  const det = document.getElementById("canary-status-details");
  det.innerHTML = `
    <p><strong>Total trampas armadas:</strong> ${status.total_trampas || 0}</p>
    <p><strong>Intactas:</strong> ${status.intactas || 0} | <strong>Activadas:</strong> ${status.activadas || 0}</p>
    <p><strong>Estado:</strong> ${status.alerta_activa ? '<span class="badge badge-crit">¡ALERTA DE ACCESO DETECTADO!</span>' : '<span class="badge badge-ok">SEÑUELOS INTACTOS</span>'}</p>
  `;
}

// Playbooks & Actions
async function loadPlaybooks() {
  const res = await callApi("run_specialized_tool", "playbook_data");
  const container = document.getElementById("playbooks-container");
  if (res && res.servicios) {
    container.innerHTML = Object.entries(res.servicios).map(([k, s]) => `
      <div class="playbook-card">
        <div>
          <div class="pb-header">
            <span class="pb-title">${escapeHtml(s.nombre || k)}</span>
            <span class="badge badge-muted">${escapeHtml(s.categoria || 'Servicio')}</span>
          </div>
          <p style="font-size:11.5px; color:var(--text-muted); line-height:1.4;">${escapeHtml(s.descripcion || '')}</p>
        </div>
        <div class="pb-actions">
          ${s.url_cierre ? `<a class="pb-btn" href="#" onclick="openExternalUrl('${s.url_cierre}'); return false;"><span>🚪 Cerrar sesiones activas</span><span>&rarr;</span></a>` : ''}
          ${s.url_clave ? `<a class="pb-btn" href="#" onclick="openExternalUrl('${s.url_clave}'); return false;"><span>🔑 Rotar contraseña</span><span>&rarr;</span></a>` : ''}
        </div>
      </div>
    `).join("");
  }
}

function openExternalUrl(url) {
  callApi("open_url", url);
}

function openRevoke(dominio) {
  switchTab("playbooks");
}

// Tool runner
async function execTool(toolId) {
  const out = document.getElementById("terminal-output");
  out.textContent = `[CookieGuard] Ejecutando '${toolId}' en el sistema local...`;
  const res = await callApi("run_specialized_tool", toolId);
  if (res) {
    if (res.cli_text) {
      out.textContent = res.cli_text;
    } else {
      out.textContent = JSON.stringify(res.data || res, null, 2);
    }
  } else {
    out.textContent = `[Error] No se pudo ejecutar la herramienta ${toolId}.`;
  }
}

async function triggerRescuePlan() {
  const out = document.getElementById("terminal-output");
  out.textContent = "[CookieGuard] Ejecutando plan de rescate Zero-Trust (sin cerrar navegadores)...";
  const res = await callApi("run_rescue_plan", false);
  out.textContent = JSON.stringify(res, null, 2);
}

async function triggerIncidentZip() {
  const res = await callApi("create_incident_zip");
  if (res && res.path) {
    alert("Paquete de incidente forense ZIP generado con éxito:\n" + res.path);
  }
}

async function exportData(fmt) {
  const res = await callApi("export_report", fmt);
  if (res && res.path) {
    alert("Reporte exportado con éxito:\n" + res.path);
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Init on load
window.addEventListener("DOMContentLoaded", async () => {
  const init = await callApi("get_initial_data");
  if (init) {
    if (init.version) {
      document.getElementById("txt-version").textContent = "v" + init.version;
      const vBadge = document.getElementById("txt-top-version");
      if (vBadge) vBadge.textContent = "v" + init.version + " · Oficial Activa";
    }
    if (init.theme) setTheme(init.theme);
    if (init.canary) updateCanaryDetails(init.canary);
    if (init.warning_old) {
      const banner = document.getElementById("warning-banner-container");
      if (banner) {
        banner.innerHTML = `
          <div class="alert-banner" style="background:#78350f; color:#fef3c7; padding:10px 24px; display:flex; align-items:center; justify-content:space-between; font-size:12px; border-bottom:1px solid #92400e;">
            <div>⚠️ <strong>Aviso de version:</strong> ${escapeHtml(init.warning_old)}</div>
            <button onclick="this.parentElement.remove()" style="background:none; border:none; color:#fef3c7; cursor:pointer; font-size:16px; padding:0 6px;">✕</button>
          </div>
        `;
      }
    }
  }
  loadPlaybooks();
  // Disparar escaneo automatico con feedback inmediato
  triggerScan();
});
</script>
</body>
</html>
"""


def launch(debug: bool = False) -> int:
    """Lanza la ventana de escritorio nativa de CookieGuard con PyWebView."""
    try:
        import webview
    except ImportError as e:
        print(f"[!] pywebview no está instalado: {e}", file=sys.stderr)
        return 1

    api = BridgeApi()
    html_content = get_dashboard_html()

    window = webview.create_window(
        title=f"CookieGuard {VERSION} · Session Security Dashboard",
        html=html_content,
        js_api=api,
        width=1240,
        height=820,
        min_size=(960, 640),
        background_color="#080c14"
    )

    webview.start(debug=debug)
    return 0


if __name__ == "__main__":
    sys.exit(launch(debug="--debug" in sys.argv))
