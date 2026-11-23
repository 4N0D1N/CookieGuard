"""Informes HTML / CSV / JSON de CookieGuard.
Solo metadatos: nunca se leen ni exportan secretos ni contenidos protegidos.
Diseño moderno, responsivo y 100 % autónomo (offline, sin dependencias externas)."""
from __future__ import annotations

import csv
import html
import json
import os
import webbrowser
from datetime import datetime
from pathlib import Path

from .common import VERSION, data_dir
from .inventory import to_serializable

COLORS = {"verde": "#10b981", "amarillo": "#f59e0b", "rojo": "#ef4444"}
BG_COLORS = {"verde": "rgba(16, 185, 129, 0.12)", "amarillo": "rgba(245, 158, 11, 0.12)", "rojo": "rgba(239, 68, 68, 0.12)"}
BORDER_COLORS = {"verde": "rgba(16, 185, 129, 0.35)", "amarillo": "rgba(245, 158, 11, 0.35)", "rojo": "rgba(239, 68, 68, 0.35)"}

ESTADO_TXT = {
    "ok": "Sin indicios",
    "alerta": "ALERTA",
    "sin_datos": "Sin datos",
    "no_aplica": "No aplica",
    "error": "Error"
}

ESTADO_BADGE_CLASS = {
    "ok": "badge-ok",
    "alerta": "badge-alerta",
    "sin_datos": "badge-sindatos",
    "no_aplica": "badge-noaplica",
    "error": "badge-alerta"
}

CATEGORIA_BADGES = {
    "correo": ("Correo", "#3b82f6"),
    "gestor": ("Gestor Claves", "#8b5cf6"),
    "sso": ("SSO / Identidad", "#ec4899"),
    "banca": ("Banca", "#10b981"),
    "cripto": ("Cripto", "#f59e0b"),
    "trabajo": ("Trabajo", "#06b6d4"),
    "nube": ("Nube", "#6366f1"),
    "desarrollo": ("Desarrollo", "#14b8a6"),
    "redes": ("Redes Sociales", "#f97316"),
    "compras": ("Compras", "#84cc16"),
    "ocio": ("Ocio", "#a855f7"),
    "otros": ("Otros", "#64748b")
}


def _e(x) -> str:
    return html.escape("" if x is None else str(x))


def _d(x) -> str:
    return x.strftime("%Y-%m-%d %H:%M") if isinstance(x, datetime) else ("-" if x is None else str(x))


CSS_STYLES = """
:root {
    --bg: #0b1120;
    --card-bg: #111827;
    --card-border: #1f2937;
    --text-primary: #f9fafb;
    --text-secondary: #9ca3af;
    --text-muted: #6b7280;
    --accent: #3b82f6;
    --accent-hover: #2563eb;
    --success: #10b981;
    --warning: #f59e0b;
    --danger: #ef4444;
    --border-radius: 12px;
    --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
}
[data-theme="light"] {
    --bg: #f3f4f6;
    --card-bg: #ffffff;
    --card-border: #e5e7eb;
    --text-primary: #111827;
    --text-secondary: #4b5563;
    --text-muted: #9ca3af;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: var(--font);
    background: var(--bg);
    color: var(--text-primary);
    line-height: 1.5;
    padding-bottom: 60px;
    transition: background 0.2s, color 0.2s;
}
.navbar {
    background: var(--card-bg);
    border-bottom: 1px solid var(--card-border);
    padding: 16px 28px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    position: sticky;
    top: 0;
    z-index: 100;
}
.nav-brand {
    display: flex;
    align-items: center;
    gap: 12px;
}
.logo-icon {
    width: 38px;
    height: 38px;
    background: linear-gradient(135deg, #3b82f6, #10b981);
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
}
.brand-title {
    font-size: 20px;
    font-weight: 800;
    letter-spacing: -0.5px;
}
.brand-sub {
    font-size: 12px;
    color: var(--text-secondary);
}
.nav-actions {
    display: flex;
    align-items: center;
    gap: 12px;
}
.theme-toggle {
    background: var(--card-border);
    border: none;
    color: var(--text-primary);
    padding: 7px 14px;
    border-radius: 20px;
    font-size: 13px;
    cursor: pointer;
    font-weight: 600;
}
.container {
    max-width: 1280px;
    margin: 24px auto;
    padding: 0 20px;
}
.hero-card {
    border-radius: var(--border-radius);
    padding: 24px 28px;
    margin-bottom: 24px;
    border: 1px solid;
}
.hero-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    flex-wrap: wrap;
    gap: 16px;
}
.hero-status {
    display: flex;
    align-items: center;
    gap: 16px;
}
.status-indicator {
    font-size: 40px;
}
.status-title {
    font-size: 26px;
    font-weight: 800;
    letter-spacing: -0.5px;
}
.status-badge-score {
    display: inline-block;
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 14px;
    font-weight: 700;
    color: #fff;
    margin-left: 8px;
}
.status-text {
    font-size: 15px;
    color: var(--text-secondary);
    margin-top: 4px;
}
.hero-honestidad {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 8px;
    padding: 12px 16px;
    margin-top: 16px;
    font-size: 13px;
    color: var(--text-secondary);
}
.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 16px;
    margin-bottom: 28px;
}
.stat-card {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: var(--border-radius);
    padding: 18px 20px;
    display: flex;
    flex-direction: column;
}
.stat-num {
    font-size: 32px;
    font-weight: 800;
    letter-spacing: -1px;
    line-height: 1.1;
}
.stat-label {
    font-size: 13px;
    color: var(--text-secondary);
    margin-top: 4px;
}
.stat-sub {
    font-size: 11px;
    color: var(--text-muted);
    margin-top: 4px;
}
.tabs-nav {
    display: flex;
    gap: 8px;
    border-bottom: 1px solid var(--card-border);
    margin-bottom: 24px;
    overflow-x: auto;
}
.tab-btn {
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--text-secondary);
    padding: 12px 18px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
    transition: all 0.2s;
}
.tab-btn:hover {
    color: var(--text-primary);
}
.tab-btn.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
}
.tab-content {
    display: none;
}
.tab-content.active {
    display: block;
}
.banner-reminder {
    background: rgba(239, 68, 68, 0.1);
    border-left: 4px solid var(--danger);
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 20px;
    font-size: 14px;
}
.banner-reminder b {
    color: var(--danger);
}
.banner-aviso-lectura {
    background: rgba(245, 158, 11, 0.1);
    border-left: 4px solid var(--warning);
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 20px;
    font-size: 13px;
}
.rot-progress-bar-container {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: var(--border-radius);
    padding: 18px 22px;
    margin-bottom: 20px;
}
.rot-prog-head {
    display: flex;
    justify-content: space-between;
    margin-bottom: 8px;
    font-size: 14px;
    font-weight: 600;
}
.progress-outer {
    background: var(--card-border);
    height: 10px;
    border-radius: 5px;
    overflow: hidden;
}
.progress-inner {
    background: var(--success);
    height: 100%;
    width: 0%;
    transition: width 0.3s ease;
}
.rot-card {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: var(--border-radius);
    padding: 18px 22px;
    margin-bottom: 14px;
    transition: all 0.2s;
}
.rot-card.rotado {
    border-color: var(--success);
    background: rgba(16, 185, 129, 0.05);
    opacity: 0.85;
}
.rot-card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;
    margin-bottom: 10px;
}
.rot-card-title {
    font-size: 18px;
    font-weight: 700;
    margin-right: 8px;
}
.rot-check-label {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    cursor: pointer;
    user-select: none;
}
.rot-checkbox {
    width: 18px;
    height: 18px;
    cursor: pointer;
}
.rot-card-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
    font-size: 13px;
    color: var(--text-secondary);
    margin-bottom: 14px;
}
.rot-nota {
    background: rgba(59, 130, 246, 0.08);
    border-left: 3px solid var(--accent);
    padding: 8px 12px;
    border-radius: 4px;
    font-size: 13px;
    margin-bottom: 14px;
    color: var(--text-secondary);
}
.rot-card-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
}
.btn-rot {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 8px 14px;
    border-radius: 8px;
    font-size: 13px;
    font-weight: 600;
    text-decoration: none;
    transition: all 0.2s;
}
.btn-rot span {
    opacity: 0.6;
    font-size: 11px;
}
.btn-rot-ses {
    background: #ef444422;
    color: #ef4444;
    border: 1px solid #ef444455;
}
.btn-rot-ses:hover {
    background: #ef4444;
    color: #fff;
}
.btn-rot-pwd {
    background: #f59e0b22;
    color: #f59e0b;
    border: 1px solid #f59e0b55;
}
.btn-rot-pwd:hover {
    background: #f59e0b;
    color: #fff;
}
.btn-rot-sec {
    background: #3b82f622;
    color: #3b82f6;
    border: 1px solid #3b82f655;
}
.btn-rot-sec:hover {
    background: #3b82f6;
    color: #fff;
}
.table-controls {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 12px;
    margin-bottom: 16px;
}
.search-input {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    color: var(--text-primary);
    padding: 10px 16px;
    border-radius: 8px;
    font-size: 14px;
    min-width: 280px;
}
.filter-pills {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
}
.pill-btn {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    color: var(--text-secondary);
    padding: 6px 14px;
    border-radius: 20px;
    font-size: 13px;
    cursor: pointer;
    font-weight: 500;
}
.pill-btn.active {
    background: var(--accent);
    color: #fff;
    border-color: var(--accent);
}
.table-container {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: var(--border-radius);
    overflow-x: auto;
}
table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    text-align: left;
}
th {
    background: rgba(255, 255, 255, 0.03);
    color: var(--text-secondary);
    font-weight: 600;
    padding: 12px 14px;
    border-bottom: 1px solid var(--card-border);
}
td {
    padding: 12px 14px;
    border-bottom: 1px solid var(--card-border);
    vertical-align: middle;
}
tr:last-child td {
    border-bottom: none;
}
.svc-cell {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
}
.svc-name {
    font-weight: 700;
    font-size: 14px;
}
.svc-domains {
    font-size: 11px;
    color: var(--text-muted);
    margin-top: 2px;
}
.date-chip {
    font-family: monospace;
    font-size: 12px;
}
.col-actions {
    display: flex;
    gap: 6px;
}
.btn-action {
    font-size: 11px;
    font-weight: 600;
    padding: 4px 8px;
    border-radius: 4px;
    text-decoration: none;
    white-space: nowrap;
}
.btn-ses { background: #ef444422; color: #ef4444; border: 1px solid #ef444455; }
.btn-pwd { background: #f59e0b22; color: #f59e0b; border: 1px solid #f59e0b55; }
.badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
}
.badge-cat {
    font-size: 11px;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 12px;
}
.tag {
    display: inline-block;
    font-size: 10px;
    font-weight: 700;
    padding: 2px 6px;
    border-radius: 4px;
}
.tag-critico { background: #ef444433; color: #ef4444; border: 1px solid #ef444466; }
.tag-zombie { background: #f59e0b33; color: #f59e0b; border: 1px solid #f59e0b66; }
.tag-nuevo { background: #10b98133; color: #10b981; border: 1px solid #10b98166; }
.tag-alerta { background: #ef444433; color: #ef4444; }
.perm-badge {
    display: inline-block;
    font-family: monospace;
    font-size: 11px;
    background: rgba(239, 68, 68, 0.15);
    color: #ef4444;
    border: 1px solid rgba(239, 68, 68, 0.3);
    padding: 2px 6px;
    border-radius: 4px;
    margin: 2px;
}
.badge-ok { background: #10b98122; color: #10b981; border: 1px solid #10b98144; }
.badge-alerta { background: #ef444422; color: #ef4444; border: 1px solid #ef444444; }
.badge-sindatos { background: #64748b22; color: #94a3b8; border: 1px solid #64748b44; }
.badge-noaplica { background: #64748b11; color: #64748b; border: 1px solid #64748b33; }
.r-Alto { background: #ef444422; color: #ef4444; }
.r-Medio { background: #f59e0b22; color: #f59e0b; }
.r-Bajo { background: #10b98122; color: #10b981; }
.ind-card {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: var(--border-radius);
    padding: 18px 22px;
    margin-bottom: 14px;
}
.card-st-alerta {
    border-color: #ef444466;
    background: rgba(239, 68, 68, 0.04);
}
.ind-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 8px;
}
.ind-mitre {
    font-family: monospace;
    font-size: 11px;
    color: var(--text-muted);
    background: rgba(255, 255, 255, 0.05);
    padding: 2px 6px;
    border-radius: 4px;
}
.ind-name {
    font-size: 16px;
    font-weight: 700;
    margin-top: 4px;
}
.ind-status-col {
    display: flex;
    align-items: center;
    gap: 8px;
}
.pts-tag {
    font-size: 12px;
    font-weight: 700;
    color: #ef4444;
    background: #ef444422;
    padding: 2px 8px;
    border-radius: 12px;
}
.pts-zero {
    font-size: 12px;
    color: var(--text-muted);
}
.ind-resumen {
    font-size: 14px;
    color: var(--text-secondary);
    margin-bottom: 10px;
}
.ind-details summary {
    font-size: 13px;
    color: var(--accent);
    cursor: pointer;
    user-select: none;
}
.ind-detail-body {
    margin-top: 10px;
    padding-top: 10px;
    border-top: 1px solid var(--card-border);
    font-size: 13px;
}
.ind-desc {
    color: var(--text-secondary);
    margin-bottom: 10px;
}
.ind-hallazgos {
    background: rgba(239, 68, 68, 0.08);
    border-left: 3px solid var(--danger);
    padding: 10px 14px;
    border-radius: 4px;
    margin: 10px 0;
}
.ind-hallazgos ul {
    margin-left: 20px;
    margin-top: 6px;
}
.ind-falta {
    color: var(--warning);
    margin-top: 8px;
    font-size: 12px;
}
.playbook-step {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: var(--border-radius);
    padding: 20px 24px;
    margin-bottom: 16px;
}
.step-num {
    display: inline-block;
    width: 28px;
    height: 28px;
    background: var(--accent);
    color: #fff;
    border-radius: 50%;
    text-align: center;
    line-height: 28px;
    font-weight: 700;
    font-size: 14px;
    margin-right: 10px;
}
.step-title {
    font-size: 17px;
    font-weight: 700;
    display: inline-block;
    vertical-align: middle;
}
.step-body {
    margin-top: 10px;
    font-size: 14px;
    color: var(--text-secondary);
    padding-left: 38px;
}
footer {
    margin-top: 40px;
    text-align: center;
    font-size: 12px;
    color: var(--text-muted);
    border-top: 1px solid var(--card-border);
    padding-top: 20px;
}
@media (max-width: 768px) {
    .stats-grid { grid-template-columns: 1fr 1fr; }
    .rot-card-actions { flex-direction: column; }
    .table-controls { flex-direction: column; align-items: stretch; }
}
"""

JS_SCRIPTS = """
function toggleTheme() {
    var html = document.documentElement;
    var current = html.getAttribute('data-theme');
    var next = current === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', next);
    var tText = document.getElementById('theme-text');
    if (tText) { tText.textContent = next === 'dark' ? 'Modo Claro' : 'Modo Oscuro'; }
    try { localStorage.setItem('cookieguard_theme', next); } catch(e) {}
}

try {
    var savedTheme = localStorage.getItem('cookieguard_theme');
    if (savedTheme) {
        document.documentElement.setAttribute('data-theme', savedTheme);
        var tText = document.getElementById('theme-text');
        if (tText) { tText.textContent = savedTheme === 'dark' ? 'Modo Claro' : 'Modo Oscuro'; }
    }
} catch(e) {}

function showTab(name) {
    var btns = document.querySelectorAll('.tab-btn');
    for (var i = 0; i < btns.length; i++) { btns[i].classList.remove('active'); }
    var contents = document.querySelectorAll('.tab-content');
    for (var j = 0; j < contents.length; j++) { contents[j].classList.remove('active'); }
    if (event && event.target) { event.target.classList.add('active'); }
    var target = document.getElementById('tab-' + name);
    if (target) { target.classList.add('active'); }
}

var currentFilter = 'all';

function setFilter(filter, btn) {
    currentFilter = filter;
    var btns = document.querySelectorAll('.pill-btn');
    for (var i = 0; i < btns.length; i++) { btns[i].classList.remove('active'); }
    if (btn) { btn.classList.add('active'); }
    filterTable();
}

function filterTable() {
    var input = document.getElementById('search-input');
    var query = input ? input.value.toLowerCase().trim() : '';
    var rows = document.querySelectorAll('#sesiones-tbody tr.row-sesion');
    for (var i = 0; i < rows.length; i++) {
        var r = rows[i];
        var text = r.getAttribute('data-search') || '';
        var matchesQuery = !query || text.indexOf(query) !== -1;
        var matchesFilter = (currentFilter === 'all') || r.classList.contains(currentFilter);
        r.style.display = (matchesQuery && matchesFilter) ? '' : 'none';
    }
}

function toggleRotado(svcId) {
    var cb = document.querySelector('.rot-checkbox[data-id="' + svcId + '"]');
    var card = document.getElementById('rot-card-' + svcId);
    if (!cb || !card) { return; }
    if (cb.checked) {
        card.classList.add('rotado');
        try { localStorage.setItem('cg_rot_' + svcId, '1'); } catch(e) {}
    } else {
        card.classList.remove('rotado');
        try { localStorage.removeItem('cg_rot_' + svcId); } catch(e) {}
    }
    updateProgress();
}

function updateProgress() {
    var all = document.querySelectorAll('.rot-checkbox');
    var total = all.length;
    if (total === 0) { return; }
    var done = 0;
    for (var i = 0; i < all.length; i++) {
        if (all[i].checked) { done++; }
    }
    var pct = Math.round((done / total) * 100);
    var fill = document.getElementById('rot-prog-fill');
    if (fill) { fill.style.width = pct + '%'; }
    var txt = document.getElementById('rot-prog-text');
    if (txt) { txt.textContent = 'Progreso de rotacion: ' + done + ' de ' + total + ' servicios'; }
    var pctEl = document.getElementById('rot-prog-pct');
    if (pctEl) { pctEl.textContent = pct + '%'; }
}

window.addEventListener('DOMContentLoaded', function() {
    var cbs = document.querySelectorAll('.rot-checkbox');
    for (var i = 0; i < cbs.length; i++) {
        var cb = cbs[i];
        var id = cb.getAttribute('data-id');
        try {
            if (localStorage.getItem('cg_rot_' + id) === '1') {
                cb.checked = true;
                var card = document.getElementById('rot-card-' + id);
                if (card) { card.classList.add('rotado'); }
            }
        } catch(e) {}
    }
    updateProgress();
});
"""


def _render_rot_card(g: dict, actions_mod) -> str:
    cat_key = g.get("categoria", "otros")
    cat_label, cat_color = CATEGORIA_BADGES.get(cat_key, (cat_key.capitalize(), "#64748b"))
    url_ses, nota_ses, _ = actions_mod.url_for(g, "sesiones")
    url_pwd, _, _ = actions_mod.url_for(g, "password")
    url_2fa, _, _ = actions_mod.url_for(g, "seguridad")

    crit_tag = "<span class='tag tag-critico'>ALTA PRIORIDAD</span>" if g.get("critico") else ""
    nota_html = f"<div class='rot-nota'>Info: {_e(nota_ses)}</div>" if nota_ses else ""
    gid = _e(g["id"])
    gnom = _e(g["nombre"])
    gcook = g["cookies"]
    gnav = _e(", ".join(g.get("navegadores", [])))
    gcad = _d(g.get("caducidad_max"))

    return f"""
    <div class="rot-card" id="rot-card-{gid}" data-svc="{gid}">
        <div class="rot-card-header">
            <div>
                <span class="rot-card-title">{gnom}</span>
                <span class="badge-cat" style="background:{cat_color}22; color:{cat_color}; border:1px solid {cat_color}55;">{_e(cat_label)}</span>
                {crit_tag}
            </div>
            <label class="rot-check-label">
                <input type="checkbox" class="rot-checkbox" data-id="{gid}" onchange="toggleRotado('{gid}')">
                <span>He completado la rotacion</span>
            </label>
        </div>
        <div class="rot-card-meta">
            <span>Cookies: <b>{gcook}</b></span>
            <span>Navegadores: <b>{gnav}</b></span>
            <span>Caducidad max: <b>{gcad}</b></span>
        </div>
        {nota_html}
        <div class="rot-card-actions">
            <a href="{_e(url_ses)}" target="_blank" rel="noopener" class="btn-rot btn-rot-ses"><span>1.</span> Cerrar sesiones activas</a>
            <a href="{_e(url_pwd)}" target="_blank" rel="noopener" class="btn-rot btn-rot-pwd"><span>2.</span> Cambiar contrasena</a>
            <a href="{_e(url_2fa)}" target="_blank" rel="noopener" class="btn-rot btn-rot-sec"><span>3.</span> Revisar 2FA / Passkeys</a>
        </div>
    </div>"""


def _render_sesion_row(g: dict, actions_mod) -> str:
    cat_key = g.get("categoria", "otros")
    cat_label, cat_color = CATEGORIA_BADGES.get(cat_key, (cat_key.capitalize(), "#64748b"))
    critico_tag = "<span class='tag tag-critico'>CRITICO</span>" if g.get("critico") else ""
    zombie_tag = "<span class='tag tag-zombie'>ZOMBIE</span>" if g.get("zombie") else ""
    nuevas_tag = f"<span class='tag tag-nuevo'>+{g['nuevas']} nueva</span>" if g.get("nuevas") else ""

    url_ses, _, _ = actions_mod.url_for(g, "sesiones")
    url_pwd, _, _ = actions_mod.url_for(g, "password")

    classes = ["row-sesion"]
    if g.get("critico"):
        classes.append("filter-critico")
    if g.get("zombie"):
        classes.append("filter-zombie")
    if g.get("nuevas"):
        classes.append("filter-nuevo")
    if g.get("caducidad_max") and isinstance(g["caducidad_max"], datetime):
        if (g["caducidad_max"] - datetime.now()).days > 365:
            classes.append("filter-larga")

    search_text = f"{g['nombre']} {cat_label} {' '.join(g.get('dominios', []))} {' '.join(g.get('navegadores', []))}".lower()
    riesgo_cls = f"r-{_e(g.get('riesgo', 'Bajo'))}"

    return f"""
    <tr class="{' '.join(classes)}" data-search="{_e(search_text)}">
        <td>
            <div class="svc-cell">
                <span class="svc-name">{_e(g['nombre'])}</span>
                <span class="badge-cat" style="background:{cat_color}22; color:{cat_color}; border:1px solid {cat_color}55;">{_e(cat_label)}</span>
                {critico_tag} {zombie_tag} {nuevas_tag}
            </div>
            <div class="svc-domains">{_e(', '.join(g.get('dominios', [])[:3]))}</div>
        </td>
        <td style="text-align:center;"><b>{g['cookies']}</b></td>
        <td>{_e(', '.join(g.get('navegadores', [])))}</td>
        <td><span class="date-chip">{_d(g.get('caducidad_max'))}</span></td>
        <td><span class="date-chip">{_d(g.get('ultimo_uso'))}</span></td>
        <td><span class="badge {riesgo_cls}">{_e(g.get('riesgo', '-'))}</span></td>
        <td class="col-actions">
            <a href="{_e(url_ses)}" target="_blank" rel="noopener" class="btn-action btn-ses">Cerrar Sesiones</a>
            <a href="{_e(url_pwd)}" target="_blank" rel="noopener" class="btn-action btn-pwd">Cambiar Clave</a>
        </td>
    </tr>"""


def _render_indicador_card(i: dict) -> str:
    st_badge = ESTADO_BADGE_CLASS.get(i.get("estado"), "badge-noaplica")
    st_texto = ESTADO_TXT.get(i.get("estado"), i.get("estado"))
    puntos_tag = f"<span class='pts-tag'>+{i['puntos']} pts</span>" if i.get("puntos", 0) > 0 else "<span class='pts-zero'>0 pts</span>"

    hallazgos_html = ""
    if i.get("hallazgos"):
        items = "".join(f"<li>{_e(h)}</li>" for h in i["hallazgos"])
        hallazgos_html = f"<div class='ind-hallazgos'><b>Hallazgos detectados:</b><ul>{items}</ul></div>"

    falta_html = f"<div class='ind-falta'>Aviso: {_e(i['falta'])}</div>" if i.get("falta") else ""

    return f"""
    <div class="ind-card card-st-{_e(i.get('estado', 'ok'))}">
        <div class="ind-header">
            <div class="ind-title-col">
                <span class="ind-mitre">{_e(i.get('mitre', '-'))}</span>
                <h3 class="ind-name">{_e(i['nombre'])}</h3>
            </div>
            <div class="ind-status-col">
                {puntos_tag}
                <span class="badge {st_badge}">{_e(st_texto)}</span>
            </div>
        </div>
        <p class="ind-resumen">{_e(i.get('resumen', ''))}</p>
        <details class="ind-details">
            <summary>Ver explicacion y detalles tecnicos</summary>
            <div class="ind-detail-body">
                <p class="ind-desc">{_e(i.get('explicacion', ''))}</p>
                {hallazgos_html}
                {falta_html}
            </div>
        </details>
    </div>"""


def build_html(res: dict) -> str:
    from . import actions

    v = res["veredicto"]
    nivel = v.get("nivel", "verde")
    main_col = COLORS.get(nivel, "#10b981")
    main_bg = BG_COLORS.get(nivel, "rgba(16,185,129,0.12)")
    main_border = BORDER_COLORS.get(nivel, "rgba(16,185,129,0.35)")
    st = res["estadisticas"]
    grupos = res.get("grupos", [])
    indicadores = res.get("indicadores", [])
    extensiones = res.get("extensiones", [])
    errores = res.get("errores", [])
    principales = v.get("principales", [])

    total_servicios = len(grupos)
    servicios_criticos = sum(1 for g in grupos if g.get("critico"))
    servicios_zombie = sum(1 for g in grupos if g.get("zombie"))
    servicios_nuevos = sum(1 for g in grupos if g.get("nuevas"))
    alertas_count = sum(1 for i in indicadores if i.get("estado") == "alerta")

    rows_sesiones = [_render_sesion_row(g, actions) for g in grupos]

    grupos_ordenados = sorted(grupos, key=lambda x: (not x.get("critico", False), actions.classifier.categoria_orden(x.get("categoria", "otros"))))
    cards_rotacion = [_render_rot_card(g, actions) for g in grupos_ordenados]

    cards_indicadores = [_render_indicador_card(i) for i in indicadores]

    rows_extensiones = []
    ext_peligrosas = [e for e in extensiones if e.get("peligrosos") or e.get("nueva") or e.get("modo_dev") or e.get("fuera_tienda")]
    for e in (ext_peligrosas if ext_peligrosas else extensiones):
        marcas = []
        if e.get("nueva"):
            marcas.append("<span class='tag tag-nuevo'>NUEVA</span>")
        if e.get("modo_dev"):
            marcas.append("<span class='tag tag-alerta'>MODO DEV</span>")
        if e.get("fuera_tienda"):
            marcas.append("<span class='tag tag-alerta'>FUERA TIENDA</span>")
        if e.get("forzada"):
            marcas.append("<span class='tag tag-critico'>POLITICA</span>")

        perm_badges = " ".join(f"<span class='perm-badge'>{_e(p)}</span>" for p in e.get("peligrosos", [])) or "<span style='color:var(--text-muted);'>Sin permisos criticos</span>"

        rows_extensiones.append(
            f"<tr><td><b>{_e(e.get('nombre', '-'))}</b></td>"
            f"<td>{_e(e.get('browser', ''))} / {_e(e.get('profile', ''))}</td>"
            f"<td>{_e(e.get('version', '-'))}</td>"
            f"<td>{perm_badges}</td>"
            f"<td>{' '.join(marcas) or '-'}</td></tr>"
        )

    avisos_html = ""
    if errores:
        items = "".join(f"<li>{_e(err)}</li>" for err in errores)
        avisos_html = (
            f"<div class='banner-aviso-lectura'><h4>Avisos durante la lectura del sistema:</h4>"
            f"<ul>{items}</ul>"
            f"<p><small>Si tienes el navegador abierto, Chrome/Edge bloquean su base de cookies. Ejecuta CookieGuard al iniciar sesion o con el navegador cerrado.</small></p></div>"
        )

    icono_semaforo = {"verde": "[OK]", "amarillo": "[!]", "rojo": "[ALERTA]"}.get(nivel, "[OK]")
    principales_html = ""
    if principales:
        items = "".join(f"<li>{_e(p)}</li>" for p in principales)
        principales_html = f"<div style='margin-top:14px; font-size:13px; color:#ef4444;'><b>Indicios principales detectados:</b><ul>{items}</ul></div>"

    rot_cards_html = "".join(cards_rotacion) if cards_rotacion else "<div class='stat-card' style='padding:40px; text-align:center;'>No se encontraron sesiones de servicios conocidas para rotar.</div>"
    ses_rows_html = "".join(rows_sesiones) if rows_sesiones else "<tr><td colspan='7' style='text-align:center; padding:30px;'>No hay sesiones registradas.</td></tr>"
    ind_cards_html = "".join(cards_indicadores)
    ext_rows_html = "".join(rows_extensiones) if rows_extensiones else "<tr><td colspan='5' style='text-align:center; padding:30px;'>No se encontraron extensiones sospechosas.</td></tr>"

    html_out = f"""<!doctype html>
<html lang="es" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CookieGuard - Auditor y Vigilante de Sesiones</title>
<style>/*__CSS__*/</style>
</head>
<body>

<nav class="navbar">
    <div class="nav-brand">
        <div class="logo-icon">&#x1F6E1;</div>
        <div>
            <div class="brand-title">CookieGuard</div>
            <div class="brand-sub">Auditor y Vigilante de Sesiones &middot; v{VERSION}</div>
        </div>
    </div>
    <div class="nav-actions">
        <span class="badge badge-ok">100% LOCAL & OFFLINE</span>
        <button class="theme-toggle" onclick="toggleTheme()">Tema: <span id="theme-text">Modo Claro</span></button>
    </div>
</nav>

<div class="container">

    <div class="hero-card" style="background:{main_bg}; border-color:{main_border};">
        <div class="hero-header">
            <div class="hero-status">
                <span class="status-indicator">{icono_semaforo}</span>
                <div>
                    <div class="status-title">
                        Semaforo: {_e(v.get('nombre', 'Verde')).upper()}
                        <span class="status-badge-score" style="background:{main_col};">{v.get('puntos', 0)} puntos de riesgo</span>
                    </div>
                    <div class="status-text">{_e(v.get('texto', 'Sin indicios detectados'))}</div>
                </div>
            </div>
            <div>
                <small style="color:var(--text-muted)">Analisis generado: {_e(res.get('generado', ''))} ({res.get('duracion_s', 0)} s)</small>
            </div>
        </div>
        <div class="hero-honestidad">
            <b>Principio de honestidad DFIR:</b> {_e(v.get('aviso', 'CookieGuard evalua indicios locales. Un malware que opere en memoria o un phishing AiTM no deja rastro en disco.'))}
        </div>
        {principales_html}
    </div>

    {avisos_html}

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-num" style="color:var(--accent);">{st.get('cookies_sesion', 0)}</div>
            <div class="stat-label">Cookies de Sesion Activas</div>
            <div class="stat-sub">En {st.get('perfiles', 0)} perfiles de navegador</div>
        </div>
        <div class="stat-card">
            <div class="stat-num" style="color:var(--success);">{total_servicios}</div>
            <div class="stat-label">Servicios Identificados</div>
            <div class="stat-sub">{servicios_criticos} marcados como alta prioridad</div>
        </div>
        <div class="stat-card">
            <div class="stat-num" style="color:{'var(--danger)' if alertas_count > 0 else 'var(--text-muted)'};">{alertas_count}</div>
            <div class="stat-label">Alertas de Exfiltracion</div>
            <div class="stat-sub">De 12 controles MITRE ATT&CK analizados</div>
        </div>
        <div class="stat-card">
            <div class="stat-num" style="color:{'var(--warning)' if servicios_zombie > 0 else 'var(--text-muted)'};">{servicios_zombie}</div>
            <div class="stat-label">Sesiones Zombie</div>
            <div class="stat-sub">&gt;90 dias sin uso con caducidad lejana</div>
        </div>
    </div>

    <div class="tabs-nav">
        <button class="tab-btn active" onclick="showTab('rotacion')">Asistente de Rotacion ({total_servicios})</button>
        <button class="tab-btn" onclick="showTab('sesiones')">Sesiones Activas ({total_servicios})</button>
        <button class="tab-btn" onclick="showTab('indicadores')">Indicadores MITRE ({len(indicadores)})</button>
        <button class="tab-btn" onclick="showTab('extensiones')">Extensiones ({len(extensiones)})</button>
        <button class="tab-btn" onclick="showTab('playbook')">Playbook de Respuesta</button>
    </div>

    <div id="tab-rotacion" class="tab-content active">
        <div class="banner-reminder">
            <b>REGLA DE ORO DE ROTACION:</b> Cambiar la contrasena a menudo <b>NO invalida</b> la cookie de sesion ya robada. Debes pulsar <b>"Cerrar todas las sesiones / Cerrar otros dispositivos"</b> en cada servicio para revocar el acceso a cualquier atacante.
        </div>

        <div class="rot-progress-bar-container">
            <div class="rot-prog-head">
                <span id="rot-prog-text">Progreso de rotacion: 0 de {len(grupos_ordenados)} servicios</span>
                <span id="rot-prog-pct">0%</span>
            </div>
            <div class="progress-outer">
                <div class="progress-inner" id="rot-prog-fill"></div>
            </div>
        </div>

        <div class="rot-cards-list">
            {rot_cards_html}
        </div>
    </div>

    <div id="tab-sesiones" class="tab-content">
        <div class="table-controls">
            <input type="text" id="search-input" class="search-input" placeholder="Buscar servicio, dominio o navegador..." onkeyup="filterTable()">
            <div class="filter-pills">
                <button class="pill-btn active" onclick="setFilter('all', this)">Todos ({total_servicios})</button>
                <button class="pill-btn" onclick="setFilter('filter-critico', this)">Criticos ({servicios_criticos})</button>
                <button class="pill-btn" onclick="setFilter('filter-zombie', this)">Zombies ({servicios_zombie})</button>
                <button class="pill-btn" onclick="setFilter('filter-nuevo', this)">Nuevas ({servicios_nuevos})</button>
                <button class="pill-btn" onclick="setFilter('filter-larga', this)">Caducan &gt; 1 ano</button>
            </div>
        </div>

        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Servicio / Dominios</th>
                        <th style="text-align:center;">Cookies</th>
                        <th>Navegadores</th>
                        <th>Caducidad Max</th>
                        <th>Ultimo Uso</th>
                        <th>Riesgo</th>
                        <th>Accion Rapida</th>
                    </tr>
                </thead>
                <tbody id="sesiones-tbody">
                    {ses_rows_html}
                </tbody>
            </table>
        </div>
    </div>

    <div id="tab-indicadores" class="tab-content">
        <div style="margin-bottom:16px; font-size:14px; color:var(--text-secondary);">
            Los 12 controles examinan indicios directos de robo de credenciales, procesos sospechosos, persistencia y abuso de navegadores segun la matriz <b>MITRE ATT&CK</b>.
        </div>
        <div class="ind-list">
            {ind_cards_html}
        </div>
    </div>

    <div id="tab-extensiones" class="tab-content">
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Extension</th>
                        <th>Navegador / Perfil</th>
                        <th>Version</th>
                        <th>Permisos Peligrosos</th>
                        <th>Marcas</th>
                    </tr>
                </thead>
                <tbody>
                    {ext_rows_html}
                </tbody>
            </table>
        </div>
    </div>

    <div id="tab-playbook" class="tab-content">
        <div class="playbook-step">
            <span class="step-num">1</span>
            <span class="step-title">Aislar el equipo comprometido</span>
            <div class="step-body">
                Desconecta el cable Ethernet y apaga la red Wi-Fi para cortar cualquier canal de comando y control (C2) o exfiltracion activa. Realiza los siguientes pasos de rotacion <b>desde otro dispositivo limpio y confiable</b> (movil, otra tablet o portatil).
            </div>
        </div>

        <div class="playbook-step">
            <span class="step-num">2</span>
            <span class="step-title">Revocar sesiones y rotar contrasenas (en este orden)</span>
            <div class="step-body">
                Usa el <b>Asistente de Rotacion</b> de este informe por orden de criticidad:<br>
                1. <b>Gestor de contrasenas</b> (Bitwarden, 1Password, etc.) &rarr; Cerrar sesiones en todos los dispositivos + cambiar contrasena maestra.<br>
                2. <b>Cuentas de correo principal y SSO</b> (Google, Microsoft, Apple, Proton) &rarr; Cerrar todas las sesiones remotas + cambiar contrasena.<br>
                3. <b>Banca, Cripto y Servicios de Pago</b> (PayPal, bancos, exchanges).<br>
                4. <b>Trabajo y Codigo</b> (GitHub, GitLab, Slack, Notion, VPNs).<br>
                5. <b>Redes Sociales y Mensajeria</b> (Meta, X, LinkedIn, Telegram, Discord).
            </div>
        </div>

        <div class="playbook-step">
            <span class="step-num">3</span>
            <span class="step-title">Revisar 2FA, Passkeys y Metodos de Recuperacion</span>
            <div class="step-body">
                Verifica que el atacante no haya registrado llaves de seguridad adicionales, numeros de telefono extra o correos de recuperacion desconocidos en tus cuentas principales.
            </div>
        </div>

        <div class="playbook-step">
            <span class="step-num">4</span>
            <span class="step-title">Comprobar reglas de reenvio de correo y OAuth</span>
            <div class="step-body">
                Los infostealers frecuentemente configuran reglas ocultas en Gmail/Outlook para reenviar o borrar correos con palabras como "seguridad", "codigo" o "alerta". Revisa en Ajustes de Correo &rarr; Filtros y Reenvio, y en Aplicaciones con acceso a tu cuenta.
            </div>
        </div>

        <div class="playbook-step">
            <span class="step-num">5</span>
            <span class="step-title">Limpieza forense o reinstalacion de Windows</span>
            <div class="step-body">
                Si confirmas ejecucion de malware (Semaforo Rojo con alertas de procesos ajenos o ejecutables sin firmar), la unica garantia absoluta para un equipo de trabajo es hacer backup de documentos personales y <b>reinstalar el sistema operativo limpiamente</b>.
            </div>
        </div>
    </div>

    <footer>
        <p>CookieGuard v{VERSION} &middot; Analisis 100% local &middot; Metadatos de sesion exclusivamente</p>
        <p style="margin-top:4px;">Nunca se leen, descifran ni exportan valores de cookies ni contrasenas almacenadas.</p>
    </footer>

</div>

<script>/*__JS__*/</script>
</body>
</html>"""
    return html_out.replace("/*__CSS__*/", CSS_STYLES).replace("/*__JS__*/", JS_SCRIPTS)


def write_reports(res: dict, open_browser: bool = False) -> Path:
    out = data_dir() / "informes"
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    p = out / f"informe_{stamp}.html"
    content = build_html(res)
    p.write_text(content, encoding="utf-8")
    (out / "ultimo.html").write_text(content, encoding="utf-8")
    (out / f"informe_{stamp}.json").write_text(to_json(res), encoding="utf-8")
    for old in sorted(out.glob("informe_*.html"))[:-30] + sorted(out.glob("informe_*.json"))[:-30]:
        try:
            old.unlink()
        except OSError:
            pass
    if open_browser:
        webbrowser.open(p.as_uri())
    return p


def to_json(res: dict) -> str:
    return json.dumps(res, indent=1, ensure_ascii=False, default=to_serializable)


def export_csv(grupos: list[dict], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["servicio", "categoria", "cookies_sesion", "navegadores", "perfiles", "caducidad_max",
                    "ultimo_uso", "estado", "riesgo", "critico", "zombie", "nuevas"])
        for g in grupos:
            w.writerow([g["nombre"], g["categoria"], g["cookies"], "|".join(g.get("navegadores", [])), "|".join(g.get("perfiles", [])),
                        _d(g.get("caducidad_max")), _d(g.get("ultimo_uso")), g.get("estado"), g.get("riesgo"), g.get("critico"),
                        g.get("zombie"), g.get("nuevas")])


def export_sessions_csv(sessions: list[dict], path: Path) -> None:
    cols = ["browser", "profile", "host", "name", "path", "created", "expires", "last_access", "secure", "httponly",
            "samesite", "persistent", "confianza"]
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(cols)
        for s in sessions:
            w.writerow([_d(s[c]) if isinstance(s[c], datetime) else s[c] for c in cols])


def export_html(res: dict, path: Path) -> None:
    Path(path).write_text(build_html(res), encoding="utf-8")


def export_json(res: dict, path: Path) -> None:
    Path(path).write_text(to_json(res), encoding="utf-8")
