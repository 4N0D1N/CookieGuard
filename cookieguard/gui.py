"""Interfaz grafica de CookieGuard (tkinter, funciona en Windows y Linux)."""
from __future__ import annotations

import queue
import sys
import threading
import tkinter as tk
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import actions, engine, reports
from .browsers import discover
from .common import APP_ROOT, VERSION, data_dir, is_admin, load_config, load_state, save_user_config
from .notify import notify
from .risk import LEVELS

DOCS = {"Manual": "docs/Manual.md", "Playbook (me han robado las cookies)": "docs/Playbook.md",
        "Limitaciones": "docs/Limitaciones.md", "Documento tecnico": "docs/Tecnico.md",
        "Investigacion": "docs/Investigacion.md", "README": "README.md"}
SESS_COLS = [("nombre", "Servicio", 190), ("categoria", "Categoria", 90), ("cookies", "Cookies", 60),
             ("navegadores", "Navegadores", 130), ("perfiles", "Perfiles", 160), ("caducidad_max", "Caducidad", 120),
             ("ultimo_uso", "Ultimo uso", 120), ("estado", "Estado", 190), ("riesgo", "Riesgo", 60)]


def _fmt(v):
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d %H:%M")
    if isinstance(v, list):
        return ", ".join(v)
    return "-" if v is None else str(v)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"CookieGuard {VERSION}")
        self.geometry("1180x720")
        self.res = None
        self.q: queue.Queue = queue.Queue()
        self.sort_col, self.sort_rev = "nombre", False
        self.profiles = []
        self._build()
        self.after(150, self._poll)
        self.after(300, self.analizar)

    # ---------------------------------------------------------------- construccion
    def _build(self):
        try:
            style = ttk.Style(self)
            if "clam" in style.theme_names():
                style.theme_use("clam")
            style.configure("Treeview", rowheight=24)
            style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
            style.configure("TButton", padding=4)
        except Exception:
            pass
        top = ttk.Frame(self)
        top.pack(fill="x", padx=8, pady=6)
        self.btn = ttk.Button(top, text="Analizar ahora", command=self.analizar)
        self.btn.pack(side="left")
        self.status = ttk.Label(top, text="Listo")
        self.status.pack(side="left", padx=12)
        self.btn_web = ttk.Button(top, text="🌐 Abrir Dashboard Web (HTML)", command=self.abrir_informe)
        self.btn_web.pack(side="right", padx=6)
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.tabs = {}
        for n in ("Resumen", "Sesiones activas", "Indicadores", "Extensiones", "Acciones / Rotacion", "Herramientas", "Historial",
                  "Ajustes", "Ayuda"):
            f = ttk.Frame(self.nb)
            self.nb.add(f, text=n)
            self.tabs[n] = f
        self._tab_resumen()
        self._tab_sesiones()
        self._tab_indicadores()
        self._tab_extensiones()
        self._tab_acciones()
        self._tab_herramientas()
        self._tab_historial()
        self._tab_ajustes()
        self._tab_ayuda()

    def _tree(self, parent, cols, height=None):
        fr = ttk.Frame(parent)
        t = ttk.Treeview(fr, columns=[c[0] for c in cols], show="headings", height=height or 15)
        for cid, txt, w in cols:
            t.heading(cid, text=txt)
            t.column(cid, width=w, anchor="w")
        sb = ttk.Scrollbar(fr, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=sb.set)
        t.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        return fr, t

    # ---------------------------------------------------------------- Resumen
    def _tab_resumen(self):
        f = self.tabs["Resumen"]
        self.canvas = tk.Canvas(f, width=140, height=140, highlightthickness=0)
        self.canvas.pack(pady=(20, 6))
        self.dot = self.canvas.create_oval(10, 10, 130, 130, fill="#999", outline="")
        self.lbl_nivel = ttk.Label(f, text="Analizando...", font=("Segoe UI", 20, "bold"))
        self.lbl_nivel.pack()
        self.lbl_texto = ttk.Label(f, text="", font=("Segoe UI", 11))
        self.lbl_texto.pack(pady=4)
        self.lbl_stats = ttk.Label(f, text="", justify="center")
        self.lbl_stats.pack(pady=6)
        self.lbl_aviso = ttk.Label(f, text="", wraplength=900, foreground="#666", justify="center")
        self.lbl_aviso.pack(pady=8)
        bar = ttk.Frame(f)
        bar.pack(pady=8)
        for txt, cmd in (("Abrir informe", self.abrir_informe), ("Exportar HTML", lambda: self.exportar("html")),
                         ("Exportar CSV", lambda: self.exportar("csv")), ("Exportar JSON", lambda: self.exportar("json")),
                         ("Modo incidente (ZIP)", self.incidente)):
            ttk.Button(bar, text=txt, command=cmd).pack(side="left", padx=4)
        self.lbl_errores = ttk.Label(f, text="", foreground="#8a5a00", wraplength=900, justify="center")
        self.lbl_errores.pack(pady=4)
        self.btn_admin = ttk.Button(f, text="Reintentar como administrador (copia VSS de bases bloqueadas)",
                                    command=self.elevar)
        self.lbl_ultima = ttk.Label(f, text="")
        self.lbl_ultima.pack(side="bottom", pady=6)

    # ---------------------------------------------------------------- Sesiones
    def _tab_sesiones(self):
        f = self.tabs["Sesiones activas"]
        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=4)
        ttk.Label(bar, text="Buscar:").pack(side="left")
        self.search = tk.StringVar()
        self.search.trace_add("write", lambda *_: self.fill_sesiones())
        ttk.Entry(bar, textvariable=self.search, width=28).pack(side="left", padx=6)
        self.flt = {k: tk.BooleanVar() for k in ("criticos", "largas", "nuevas", "sinuso", "zombie")}
        for k, t in (("criticos", "Solo criticos"), ("largas", "Caducan en mas de 1 ano"), ("nuevas", "Nuevas"),
                     ("sinuso", "Sin uso > 90 dias"), ("zombie", "Zombie")):
            ttk.Checkbutton(bar, text=t, variable=self.flt[k], command=self.fill_sesiones).pack(side="left", padx=4)
        fr, self.t_ses = self._tree(f, SESS_COLS, 22)
        fr.pack(fill="both", expand=True)
        for cid, _, _ in SESS_COLS:
            self.t_ses.heading(cid, command=lambda c=cid: self.sort_by(c))
        self.t_ses.bind("<Double-1>", lambda e: self.ir_a_accion())
        self.lbl_count = ttk.Label(f, text="")
        self.lbl_count.pack(anchor="w")

    def sort_by(self, col):
        self.sort_rev = (not self.sort_rev) if self.sort_col == col else False
        self.sort_col = col
        self.fill_sesiones()

    def _filtered(self):
        if not self.res:
            return []
        now, q = datetime.now(), self.search.get().lower().strip()
        out = []
        for g in self.res["grupos"]:
            if q and q not in (g["nombre"] + " " + " ".join(g["dominios"]) + " " + " ".join(g["navegadores"])).lower():
                continue
            if self.flt["criticos"].get() and not g["critico"]:
                continue
            if self.flt["largas"].get() and not (g["caducidad_max"] and (g["caducidad_max"] - now).days > 365):
                continue
            if self.flt["nuevas"].get() and not g["nuevas"]:
                continue
            if self.flt["sinuso"].get() and not (g["dias_sin_uso"] and g["dias_sin_uso"] > 90):
                continue
            if self.flt["zombie"].get() and not g["zombie"]:
                continue
            out.append(g)
        key = self.sort_col
        out.sort(key=lambda g: (g.get(key) is None, str(g.get(key)) if key in ("nombre", "categoria", "estado", "riesgo")
                                else (g.get(key) or 0) if not isinstance(g.get(key), list) else ",".join(g[key])),
                 reverse=self.sort_rev)
        return out

    def fill_sesiones(self):
        t = self.t_ses
        t.delete(*t.get_children())
        rows = self._filtered()
        for g in rows:
            t.insert("", "end", iid=g["id"], values=[_fmt(g[c]) for c, _, _ in SESS_COLS])
        total = len(self.res["grupos"]) if self.res else 0
        self.lbl_count.config(text=f"{len(rows)} de {total} servicios (doble clic: ir a acciones)")

    # ---------------------------------------------------------------- Indicadores
    def _tab_indicadores(self):
        f = self.tabs["Indicadores"]
        pw = ttk.PanedWindow(f, orient="horizontal")
        pw.pack(fill="both", expand=True)
        fr, self.t_ind = self._tree(pw, [("nombre", "Indicador", 330), ("estado", "Estado", 80), ("pts", "Pts", 40)])
        pw.add(fr, weight=1)
        self.txt_ind = tk.Text(pw, wrap="word", width=60)
        pw.add(self.txt_ind, weight=1)
        self.t_ind.bind("<<TreeviewSelect>>", self.show_ind)

    def show_ind(self, _=None):
        sel = self.t_ind.selection()
        if not sel or not self.res:
            return
        i = next(x for x in self.res["indicadores"] if x["id"] == sel[0])
        s = (f"{i['nombre']}\nTecnica MITRE: {i['mitre']}\nEstado: {i['estado']}  Puntos: {i['puntos']}  "
             f"({i.get('segundos', '?')} s)\n\nQue significa:\n{i['explicacion']}\n\nResultado:\n{i['resumen']}\n")
        if i["hallazgos"]:
            s += "\nHallazgos:\n" + "\n".join(f" - {h}" for h in i["hallazgos"])
        if i.get("falta"):
            s += f"\n\nQue falta para ver mas: {i['falta']}"
        self.txt_ind.config(state="normal")
        self.txt_ind.delete("1.0", "end")
        self.txt_ind.insert("1.0", s)
        self.txt_ind.config(state="disabled")

    # ---------------------------------------------------------------- Extensiones
    def _tab_extensiones(self):
        fr, self.t_ext = self._tree(self.tabs["Extensiones"], [
            ("nombre", "Extension", 220), ("perfil", "Navegador/Perfil", 160), ("version", "Version", 70),
            ("peligrosos", "Permisos peligrosos", 280), ("marcas", "Marcas", 220)], 22)
        fr.pack(fill="both", expand=True)

    # ---------------------------------------------------------------- Acciones / Rotacion
    def _tab_acciones(self):
        nb = ttk.Notebook(self.tabs["Acciones / Rotacion"])
        nb.pack(fill="both", expand=True)
        self.nb_acc = nb
        a = ttk.Frame(nb)
        nb.add(a, text="Por servicio")
        self.cb_serv = ttk.Combobox(a, state="readonly", width=60)
        self.cb_serv.pack(anchor="w", padx=8, pady=8)
        self.lbl_nota = ttk.Label(a, text="", wraplength=900, foreground="#555", justify="left")
        grid = ttk.Frame(a)
        grid.pack(anchor="w", padx=8)
        for i, k in enumerate(("sesiones", "password", "seguridad", "historial")):
            ttk.Button(grid, text=actions.KIND_LABEL[k], width=38, command=lambda k=k: self.abrir_accion(k)).grid(
                row=i // 2, column=i % 2, padx=4, pady=3)
        ttk.Button(grid, text="Borrar cookies locales de este servicio...", width=38, command=self.borrar_servicio).grid(
            row=2, column=0, padx=4, pady=3)
        ttk.Button(grid, text="Marcar como revisado", width=38, command=self.marcar_revisado).grid(row=2, column=1, padx=4)
        self.lbl_nota.pack(anchor="w", padx=8, pady=8)
        ttk.Label(a, text=actions.REMINDER, foreground="#c62828", wraplength=900).pack(anchor="w", padx=8, pady=4)
        ttk.Separator(a).pack(fill="x", pady=8)
        gl = ttk.Frame(a)
        gl.pack(anchor="w", padx=8)
        ttk.Button(gl, text="Cerrar navegadores y borrar TODAS las cookies...", command=self.borrar_todo).pack(side="left", padx=4)
        ttk.Button(gl, text="Modo incidente (ZIP forense)", command=self.incidente).pack(side="left", padx=4)
        ttk.Button(gl, text="Restaurar copia de seguridad...", command=self.restaurar).pack(side="left", padx=4)
        # asistente de rotacion
        r = ttk.Frame(nb)
        nb.add(r, text="Asistente de rotacion")
        ttk.Label(r, text=actions.REMINDER, foreground="#c62828", wraplength=1000).pack(anchor="w", padx=8, pady=6)
        self.pb = ttk.Progressbar(r, length=500)
        self.pb.pack(anchor="w", padx=8)
        self.lbl_pb = ttk.Label(r, text="")
        self.lbl_pb.pack(anchor="w", padx=8)
        fr, self.t_rot = self._tree(r, [("nombre", "Servicio (por criticidad)", 240), ("categoria", "Categoria", 90),
                                         ("sesiones", "1 Sesiones", 80), ("password", "2 Contrasena", 90),
                                         ("seguridad", "3 2FA", 60), ("historial", "4 Actividad", 80)], 14)
        fr.pack(fill="both", expand=True, padx=8, pady=6)
        bb = ttk.Frame(r)
        bb.pack(anchor="w", padx=8, pady=4)
        for k, t in (("sesiones", "Abrir y marcar: sesiones"), ("password", "contrasena"), ("seguridad", "2FA"),
                     ("historial", "actividad")):
            ttk.Button(bb, text=t, command=lambda k=k: self.rot_step(k)).pack(side="left", padx=3)
        ttk.Button(bb, text="Desmarcar paso (ultimo)", command=lambda: self.rot_step(None)).pack(side="left", padx=3)
        # hardening
        h = ttk.Frame(nb)
        nb.add(h, text="Seguridad (hardening)")
        fr, self.t_hard = self._tree(h, [("titulo", "Comprobacion", 380), ("estado", "Estado", 90), ("rec", "Recomendacion", 520)], 16)
        fr.pack(fill="both", expand=True, padx=8, pady=6)
        hb = ttk.Frame(h)
        hb.pack(anchor="w", padx=8)
        ttk.Button(hb, text="Comprobar", command=self.fill_hard).pack(side="left", padx=3)
        ttk.Button(hb, text="Aplicar seleccionado", command=lambda: self.apply_hard(False)).pack(side="left", padx=3)
        ttk.Button(hb, text="Deshacer seleccionado", command=lambda: self.apply_hard(True)).pack(side="left", padx=3)
        # copias
        b = ttk.Frame(nb)
        nb.add(b, text="Copias de seguridad")
        fr, self.t_bk = self._tree(b, [("id", "Copia", 160), ("fecha", "Fecha", 160), ("filas", "Cookies", 80), ("dom", "Dominios", 400)], 12)
        fr.pack(fill="both", expand=True, padx=8, pady=6)
        ttk.Button(b, text="Restaurar la seleccionada", command=self.restaurar).pack(anchor="w", padx=8)

    # ---------------------------------------------------------------- Historial / Ajustes / Ayuda
    def _tab_herramientas(self):
        f = self.tabs["Herramientas"]
        top_lbl = ttk.Label(f, text="Herramientas Avanzadas de Auditoria, Deteccion y Respuesta a Incidentes", font=("Segoe UI", 11, "bold"))
        top_lbl.pack(anchor="w", padx=10, pady=(10, 4))
        sub_lbl = ttk.Label(f, text="Ejecuta modulos de analisis en tiempo real (100% offline, compatibles con Windows y Linux).", foreground="#555")
        sub_lbl.pack(anchor="w", padx=10, pady=(0, 8))

        btn_grid = ttk.Frame(f)
        btn_grid.pack(fill="x", padx=10, pady=4)

        # Fila 1: Resumen y Portapapeles
        ttk.Button(btn_grid, text="Semaforo de Estado (Dummy)", command=self._tool_dummy).grid(row=0, column=0, padx=4, pady=3, sticky="ew")
        ttk.Button(btn_grid, text="Auditar Portapapeles (Clipper)", command=self._tool_clipboard).grid(row=0, column=1, padx=4, pady=3, sticky="ew")
        ttk.Button(btn_grid, text="Purgar Portapapeles Seguro", command=self._tool_clear_clipboard).grid(row=0, column=2, padx=4, pady=3, sticky="ew")

        # Fila 2: Persistencia, Red e Integridad
        ttk.Button(btn_grid, text="Auditar Persistencia (Registro / Tareas)", command=self._tool_persistence).grid(row=1, column=0, padx=4, pady=3, sticky="ew")
        ttk.Button(btn_grid, text="Auditar Archivo Hosts y DNS", command=self._tool_network).grid(row=1, column=1, padx=4, pady=3, sticky="ew")
        ttk.Button(btn_grid, text="Integridad de Binarios de Navegador", command=self._tool_integrity).grid(row=1, column=2, padx=4, pady=3, sticky="ew")

        # Fila 3: Simulacro, Dossier MITRE y Playbook
        ttk.Button(btn_grid, text="Ejecutar Simulacro (Drill Seguro)", command=self._tool_drill).grid(row=2, column=0, padx=4, pady=3, sticky="ew")
        ttk.Button(btn_grid, text="Generar Dossier MITRE (HTML)", command=self._tool_dossier).grid(row=2, column=1, padx=4, pady=3, sticky="ew")
        ttk.Button(btn_grid, text="Abrir Playbook de Revocacion", command=self._tool_playbook).grid(row=2, column=2, padx=4, pady=3, sticky="ew")

        btn_grid.columnconfigure(0, weight=1)
        btn_grid.columnconfigure(1, weight=1)
        btn_grid.columnconfigure(2, weight=1)

        out_frame = ttk.LabelFrame(f, text="Resultado de la Herramienta Seleccionada")
        out_frame.pack(fill="both", expand=True, padx=10, pady=(8, 10))

        self.txt_herramientas = tk.Text(out_frame, wrap="word", font=("Consolas", 9))
        self.txt_herramientas.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        scrl = ttk.Scrollbar(out_frame, command=self.txt_herramientas.yview)
        scrl.pack(side="right", fill="y")
        self.txt_herramientas.config(yscrollcommand=scrl.set)
        self._set_tool_text("Selecciona una herramienta superior para ejecutarla y visualizar aqui sus resultados detallados.")

    def _set_tool_text(self, text: str):
        self.txt_herramientas.config(state="normal")
        self.txt_herramientas.delete("1.0", "end")
        self.txt_herramientas.insert("1.0", text)
        self.txt_herramientas.config(state="disabled")

    def _tool_dummy(self):
        from . import dummy_summary
        crit_count = sum(1 for g in (self.res.get("grupos", []) if self.res else []) if g.get("critico"))
        has_crit = bool(self.res and self.res.get("veredicto", {}).get("nombre") == "rojo")
        sum_data = dummy_summary.compute_traffic_light(
            has_critical_detections=has_crit,
            active_critical_sessions=crit_count,
            has_persistence_alerts=False,
            has_hosts_hijack=False
        )
        cli_view = dummy_summary.format_dummy_summary_cli(sum_data)
        self._set_tool_text(cli_view)

    def _tool_clipboard(self):
        from . import clipboard_audit
        res = clipboard_audit.audit_clipboard()
        lines = [
            "=" * 60,
            "AUDITORIA DE PORTAPAPELES (MITRE ATT&CK T1115 - CLIPPER MALWARE)",
            "=" * 60,
            "Accesible: " + ("Si" if res.get("accesible") else "No / Vacio"),
            "Total de alertas: " + str(res.get("total_alertas", 0)),
            "Alerta critica: " + ("SI" if res.get("has_critical") else "No"),
            "Recomendacion: " + str(res.get("recomendacion", "-")),
            ""
        ]
        if res.get("alertas"):
            lines.append("HALLAZGOS REGISTRADOS:")
            for a in res["alertas"]:
                lines.append("  * [" + str(a.get("severidad")) + "] " + str(a.get("tipo")) + ": " + str(a.get("descripcion")))
        if res.get("cripto_detectadas"):
            lines.append("")
            lines.append("DIRECCIONES CRIPTO DETECTADAS (Objetivos potenciales de suplantacion):")
            for c in res["cripto_detectadas"]:
                lines.append("  * " + str(c.get("moneda")) + ": " + str(c.get("direccion_anonimizada")))
        self._set_tool_text("\n".join(lines))

    def _tool_clear_clipboard(self):
        from . import clipboard_audit
        ok = clipboard_audit.clear_system_clipboard()
        if ok:
            msg = "PORTAPAPELES PURGADO EXITOSAMENTE.\nEl contenido previo ha sido borrado de la memoria volatil del sistema para impedir su exfiltracion."
            self._set_tool_text(msg)
            messagebox.showinfo("CookieGuard", "El portapapeles ha sido vaciado correctamente.")
        else:
            self._set_tool_text("Aviso: No se pudo purgar el portapapeles automaticamente (herramienta no disponible o sin sesion grafica).")

    def _tool_persistence(self):
        from . import persistence_audit
        res = persistence_audit.run_persistence_audit()
        lines = [
            "=" * 60,
            "AUDITORIA DE PERSISTENCIA Y TAREAS PROGRAMADAS",
            "=" * 60,
            "Plataforma: " + str(res.get("plataforma")),
            "Total de entradas analizadas: " + str(res.get("total_audited")),
            "Entradas sospechosas: " + str(res.get("suspicious_count")),
            ""
        ]
        if res.get("suspicious_items"):
            lines.append("ALERTAS DETECTADAS:")
            for item in res["suspicious_items"]:
                lines.append("  * Tipo: " + str(item.get("tipo")))
                lines.append("    Comando: " + str(item.get("comando")))
                for alt in item.get("alertas", []):
                    lines.append("    -> [" + str(alt.get("severidad")) + "] " + str(alt.get("descripcion")))
                lines.append("")
        else:
            lines.append("Estado: Limpio. No se detectaron comandos de persistencia anomalos o de evasion conocidos.")
        self._set_tool_text("\n".join(lines))

    def _tool_network(self):
        from . import network_audit
        res = network_audit.run_network_audit()
        dns_nameservers = res.get("dns_info", {}).get("nameservers", [])
        lines = [
            "=" * 60,
            "AUDITORIA DE RED LOCAL, ARCHIVO HOSTS Y RESOLUCION DNS",
            "=" * 60,
            "Ruta analizada: " + str(res.get("hosts_path")),
            "Total de entradas hosts: " + str(res.get("total_hosts_entries")),
            "Anomalias detectadas: " + str(res.get("anomalies_count")),
            "Servidores DNS activos: " + (", ".join(dns_nameservers) if dns_nameservers else "Por defecto"),
            ""
        ]
        if res.get("anomalies"):
            lines.append("ALERTAS ENCONTRADAS:")
            for a in res["anomalies"]:
                lines.append("  * [" + str(a.get("severidad")) + "] Linea " + str(a.get("linea")) + ": " + str(a.get("dominio")) + " -> " + str(a.get("ip")))
                lines.append("    Detalle: " + str(a.get("detalle")))
        else:
            lines.append("Estado: Limpio. El archivo hosts no contiene redirecciones de seguridad ni secuestro de portales de autenticacion.")
        self._set_tool_text("\n".join(lines))

    def _tool_integrity(self):
        from . import binary_integrity
        res = binary_integrity.audit_binary_integrity()
        lines = [
            "=" * 60,
            "VERIFICACION DE INTEGRIDAD Y FIRMAS DE BINARIOS DE NAVEGADORES",
            "=" * 60,
            "Navegadores auditados: " + str(res.get("total_audited")),
            "Binarios en riesgo/alterados: " + str(res.get("tampered_count")),
            ""
        ]
        for b in res.get("results", []):
            lines.append("* Navegador: " + str(b.get("browser")))
            lines.append("  Ruta: " + str(b.get("path")))
            v = b.get("verification", {})
            lines.append("  Estado de firma/integridad: " + str(v.get("status", "DESCONOCIDO")))
            if v.get("subject"):
                lines.append("  Firmante: " + str(v.get("subject")))
            lines.append("  Riesgo de alteracion: " + ("SI (ALERTA)" if b.get("is_tampered_risk") else "No (Valido)"))
            lines.append("")
        self._set_tool_text("\n".join(lines))

    def _tool_drill(self):
        from . import simulator
        if not messagebox.askyesno("CookieGuard", "¿Deseas ejecutar un simulacro de incidente seguro?\nSe creara un entorno temporal aislado con cookies senuelo para probar la contencion y generar un reporte."):
            return
        res = simulator.run_incident_drill(interactive=False)
        lines = [
            "=" * 60,
            "SIMULACRO DE INCIDENTE COMPLETADO CON EXITO",
            "=" * 60,
            "Familia simulada: " + str(res.get("familia_stealer_simulada")),
            "Estado del semaforo: " + str(res.get("estado_semaforo")),
            "Listo para contencion: " + ("Si" if res.get("listo_para_contencion") else "No"),
            "",
            "Pasos ejecutados en sandbox:"
        ]
        for p in res.get("pasos_completados", []):
            lines.append("  * " + str(p.get("nombre")) + ": " + str(p.get("detalle")))
        lines.append("")
        lines.append("Reporte generado: " + str(res.get("reporte_html")))
        self._set_tool_text("\n".join(lines))
        if res.get("reporte_html"):
            try:
                webbrowser.open(Path(res["reporte_html"]).as_uri())
            except Exception:
                pass

    def _tool_dossier(self):
        from . import incident_report
        if not self.res:
            messagebox.showwarning("CookieGuard", "Ejecuta primero un analisis antes de generar el dossier.")
            return
        p_html = incident_report.generate_incident_dossier(self.res, formato="html")
        self._set_tool_text("Dossier formal de incidente MITRE ATT&CK generado con exito:\n\nArchivo HTML: " + str(p_html) + "\nSe ha abierto en tu navegador para visualizacion o impresion/guardar como PDF.")
        try:
            webbrowser.open(Path(p_html).as_uri())
        except Exception:
            pass

    def _tool_playbook(self):
        from . import playbooks
        p_html = playbooks.generate_playbook_html()
        self._set_tool_text("Playbook interactivo de respuesta rapida generado con exito:\n\nArchivo HTML: " + str(p_html) + "\nIncluye la checklist y guias de revocacion de sesiones para mas de 35 servicios.")
        try:
            webbrowser.open(Path(p_html).as_uri())
        except Exception:
            pass

    def _tab_historial(self):
        fr, self.t_his = self._tree(self.tabs["Historial"], [("fecha", "Fecha", 160), ("nivel", "Semaforo", 90),
                                                              ("puntos", "Puntos", 70), ("sesiones", "Sesiones", 80),
                                                              ("servicios", "Servicios", 80), ("segundos", "Seg.", 60)], 22)
        fr.pack(fill="both", expand=True)

    def _tab_ajustes(self):
        f = self.tabs["Ajustes"]
        cfg = load_config()
        self.var = {k: tk.BooleanVar(value=cfg.get(k, False)) for k in ("silencioso", "notificar_verde", "vigilante_activo", "canary_activo")}
        lab = {"silencioso": "Modo silencioso (solo avisar en Amarillo/Rojo)", "notificar_verde": "Avisar tambien cuando esta Verde",
               "vigilante_activo": "Vigilancia en tiempo real (arranca con la sesion)", "canary_activo": "Cookies canary (opcional)"}
        for k, v in self.var.items():
            ttk.Checkbutton(f, text=lab[k], variable=v).pack(anchor="w", padx=12, pady=3)
        row = ttk.Frame(f)
        row.pack(anchor="w", padx=12, pady=6)
        self.e_am = tk.StringVar(value=cfg["umbrales"]["amarillo"])
        self.e_ro = tk.StringVar(value=cfg["umbrales"]["rojo"])
        for t, v in (("Umbral Amarillo:", self.e_am), ("Umbral Rojo:", self.e_ro)):
            ttk.Label(row, text=t).pack(side="left")
            ttk.Entry(row, textvariable=v, width=6).pack(side="left", padx=6)
        ttk.Label(f, text="Procesos de confianza (uno por linea; el vigilante y el indicador 1 los ignoran):").pack(anchor="w", padx=12)
        self.txt_wl = tk.Text(f, height=10, width=50)
        self.txt_wl.insert("1.0", "\n".join(cfg["whitelist_procesos"]))
        self.txt_wl.pack(anchor="w", padx=12)
        bb = ttk.Frame(f)
        bb.pack(anchor="w", padx=12, pady=8)
        ttk.Button(bb, text="Guardar ajustes", command=self.guardar_ajustes).pack(side="left", padx=3)
        ttk.Button(bb, text="Probar notificacion", command=lambda: messagebox.showinfo(
            "CookieGuard", "Metodo: " + notify("CookieGuard", "Notificacion de prueba", None))).pack(side="left", padx=3)
        ttk.Button(bb, text="Aceptar cambios pendientes como linea base", command=self.aceptar_base).pack(side="left", padx=3)
        ttk.Label(f, text=f"Datos: {data_dir()}  |  Administrador: {'si' if is_admin() else 'no'}", foreground="#666").pack(anchor="w", padx=12)

    def _tab_ayuda(self):
        f = self.tabs["Ayuda"]
        self.cb_doc = ttk.Combobox(f, values=list(DOCS), state="readonly", width=50)
        self.cb_doc.current(0)
        self.cb_doc.pack(anchor="w", padx=8, pady=6)
        self.cb_doc.bind("<<ComboboxSelected>>", lambda e: self.show_doc())
        self.txt_doc = tk.Text(f, wrap="word")
        self.txt_doc.pack(fill="both", expand=True, padx=8, pady=4)
        self.show_doc()

    def show_doc(self):
        p = APP_ROOT / DOCS[self.cb_doc.get()]
        try:
            txt = p.read_text(encoding="utf-8")
        except OSError:
            txt = f"No se encuentra {p}"
        self.txt_doc.config(state="normal")
        self.txt_doc.delete("1.0", "end")
        self.txt_doc.insert("1.0", txt)
        self.txt_doc.config(state="disabled")

    # ---------------------------------------------------------------- analisis en segundo plano
    def analizar(self):
        self.btn.config(state="disabled")
        self.status.config(text="Analizando (puede tardar hasta un minuto)...")

        def work():
            try:
                self.profiles = discover()
                res = engine.run_analysis(self.profiles, progress=lambda r: self.q.put(("p", r["nombre"])))
                reports.write_reports(res)
                self.q.put(("ok", res))
            except Exception as e:  # noqa: BLE001
                self.q.put(("err", f"{type(e).__name__}: {e}"))

        threading.Thread(target=work, daemon=True).start()

    def _poll(self):
        try:
            while True:
                k, v = self.q.get_nowait()
                if k == "p":
                    self.status.config(text=f"Hecho: {v}")
                elif k == "ok":
                    self.res = v
                    self.refresh()
                    self.btn.config(state="normal")
                    self.status.config(text=f"Analisis terminado en {v['duracion_s']} s")
                else:
                    self.btn.config(state="normal")
                    self.status.config(text="Error en el analisis")
                    messagebox.showerror("CookieGuard", v)
        except queue.Empty:
            pass
        self.after(150, self._poll)

    def refresh(self):
        r = self.res
        v = r["veredicto"]
        self.canvas.itemconfig(self.dot, fill=LEVELS[v["nivel"]]["color"])
        self.lbl_nivel.config(text=f"{v['nombre']} - {v['puntos']} puntos")
        texto_resumen = v["texto"]
        if v.get("principales"):
            texto_resumen += "\n\n⚠️ Pistas principales:\n • " + "\n • ".join(v["principales"])
        self.lbl_texto.config(text=texto_resumen)
        st = r["estadisticas"]
        self.lbl_stats.config(text=f"{st['cookies_sesion']} cookies de sesion  |  {len(r['grupos'])} servicios  |  "
                                   f"{st['perfiles']} perfiles  |  {sum(1 for i in r['indicadores'] if i['estado'] == 'alerta')} indicadores en alerta  |  "
                                   f"{sum(1 for g in r['grupos'] if g['zombie'])} sesiones zombie")
        self.lbl_aviso.config(text=v["aviso"])
        blocked = [e for e in r["errores"] if "bloqueada" in e]
        self.lbl_errores.config(text="\n".join(r["errores"][:6]) + ("\nCierra el navegador o reintenta como administrador." if blocked else ""))
        if blocked and not is_admin():
            self.btn_admin.pack(pady=4)
        else:
            self.btn_admin.pack_forget()
        self.lbl_ultima.config(text=f"Ultima ejecucion: {r['generado']}")
        self.fill_sesiones()
        self.t_ind.delete(*self.t_ind.get_children())
        for i in r["indicadores"]:
            self.t_ind.insert("", "end", iid=i["id"], values=(i["nombre"], i["estado"], i["puntos"]))
        self.t_ext.delete(*self.t_ext.get_children())
        for n, e in enumerate(r["extensiones"]):
            marks = " ".join(m for m, c in (("nueva", e["nueva"]), ("dev", e["modo_dev"]), ("fuera-tienda", e["fuera_tienda"]),
                                            ("forzada", e["forzada"])) if c)
            self.t_ext.insert("", "end", iid=str(n), values=(e["nombre"], f"{e['browser']}/{e['profile']}", e["version"],
                                                              ", ".join(e["peligrosos"]) or "-", marks))
        self.cb_serv["values"] = [f"{g['nombre']}  [{g['id']}]" for g in r["grupos"]]
        if r["grupos"] and not self.cb_serv.get():
            self.cb_serv.current(0)
        self.fill_rot()
        self.fill_hist()
        self.fill_backups()

    def fill_hist(self):
        self.t_his.delete(*self.t_his.get_children())
        for h in reversed(load_state().get("historial", [])):
            self.t_his.insert("", "end", values=(h["fecha"], h["nivel"], h["puntos"], h["sesiones"], h["servicios"], h["segundos"]))

    def fill_backups(self):
        self.t_bk.delete(*self.t_bk.get_children())
        for b in actions.list_backups():
            self.t_bk.insert("", "end", iid=b["id"], values=(b["id"], b["fecha"], b["filas"], ", ".join(b["dominios"] or ["(todas)"])))

    def fill_hard(self):
        self.t_hard.delete(*self.t_hard.get_children())
        for c in actions.hardening_checks(self.profiles or discover()):
            self.t_hard.insert("", "end", iid=c["id"], values=(c["titulo"], c["estado"] + (" *" if c["aplicable"] else ""), c["recomendacion"]))

    def apply_hard(self, undo):
        sel = self.t_hard.selection()
        if not sel:
            return
        if messagebox.askyesno("Confirmar", f"{'Deshacer' if undo else 'Aplicar'} '{sel[0]}'? (requiere administrador)"):
            ok, msg = actions.apply_hardening(sel[0], undo)
            messagebox.showinfo("CookieGuard", ("OK: " if ok else "No se pudo: ") + msg)
            self.fill_hard()

    # ---------------------------------------------------------------- acciones
    def _group(self):
        if not self.res:
            return None
        sel = self.cb_serv.get()
        gid = sel.rsplit("[", 1)[-1].rstrip("]") if sel else None
        return next((g for g in self.res["grupos"] if g["id"] == gid), None)

    def ir_a_accion(self):
        sel = self.t_ses.selection()
        if sel:
            g = next(g for g in self.res["grupos"] if g["id"] == sel[0])
            self.cb_serv.set(f"{g['nombre']}  [{g['id']}]")
            self.nb.select(self.tabs["Acciones / Rotacion"])
            self.nb_acc.select(0)

    def abrir_accion(self, kind):
        g = self._group()
        if not g:
            return
        url, nota, search = actions.url_for(g, kind)
        self.lbl_nota.config(text=(nota + "\n" if nota else "") + f"Abre: {url}")
        actions.open_url(url)

    def marcar_revisado(self):
        g = self._group()
        if g:
            actions.mark_reviewed(g["id"])
            self.fill_rot()
            messagebox.showinfo("CookieGuard", f"{g['nombre']} marcado como revisado ({datetime.now():%d/%m/%Y})")

    def _preparar_cierre(self):
        b = actions.running_browsers()
        if b:
            if not messagebox.askyesno("Navegadores abiertos", "Hay navegadores abiertos: " + ", ".join(b) +
                                       "\n\nPara borrar cookies hay que cerrarlos (se pierden pestanas sin guardar).\n"
                                       "Cerrarlos ahora?"):
                return False
            actions.close_browsers()
        return True

    def borrar_servicio(self):
        g = self._group()
        if not g or not messagebox.askyesno("Confirmar", f"Borrar las cookies locales de {g['nombre']} en TODOS los navegadores?\n"
                                                         "Se hace antes una copia de seguridad que puedes restaurar."):
            return
        if not self._preparar_cierre():
            return
        r = actions.delete_local(self.profiles or discover(), g["dominios"])
        messagebox.showinfo("CookieGuard", f"Borradas: {r['borradas']}. Copia: {r.get('copia') or '-'}. {r.get('motivo', '')}")
        self.fill_backups()

    def borrar_todo(self):
        if not messagebox.askyesno("Confirmacion 1/2", "Se cerraran todos los navegadores y se borraran TODAS sus cookies "
                                                       "(cerraras sesion en todas partes). Continuar?"):
            return
        if not messagebox.askyesno("Confirmacion 2/2", "Seguro? Se hace una copia de seguridad, pero tendras que volver a "
                                                       "iniciar sesion en todos los servicios."):
            return
        if not self._preparar_cierre():
            return
        r = actions.delete_local(self.profiles or discover(), None)
        messagebox.showinfo("CookieGuard", f"Borradas: {r['borradas']}. Copia: {r.get('copia') or '-'}. {r.get('motivo', '')}")
        self.fill_backups()

    def restaurar(self):
        sel = self.t_bk.selection()
        if not sel:
            messagebox.showinfo("CookieGuard", "Elige una copia en 'Copias de seguridad'.")
            self.nb_acc.select(3)
            return
        if not self._preparar_cierre():
            return
        r = actions.restore_backup(sel[0])
        messagebox.showinfo("CookieGuard", str(r))

    def fill_rot(self):
        self.plan = actions.rotation_plan(self.res["grupos"]) if self.res else []
        self.t_rot.delete(*self.t_rot.get_children())
        for p in self.plan:
            self.t_rot.insert("", "end", iid=p["id"], values=[p["nombre"], p["categoria"]] + [
                "[x]" if p["pasos"][k] else "[ ]" for k, _ in actions.STEPS])
        d, t = actions.rotation_progress(self.plan)
        self.pb.config(maximum=max(t, 1), value=d)
        self.lbl_pb.config(text=f"{d} de {t} pasos completados")

    def rot_step(self, step):
        sel = self.t_rot.selection()
        if not sel:
            return
        g = next(g for g in self.res["grupos"] if g["id"] == sel[0])
        if step is None:
            p = next(p for p in self.plan if p["id"] == sel[0])
            done = [k for k, _ in actions.STEPS if p["pasos"][k]]
            if done:
                actions.mark_step(g["id"], done[-1], False)
        else:
            url, nota, _ = actions.url_for(g, step)
            actions.open_url(url)
            if messagebox.askyesno("Paso", f"{g['nombre']}: {dict(actions.STEPS)[step]}\n{nota}\n\nLo has completado?"):
                actions.mark_step(g["id"], step, True)
        self.fill_rot()

    def abrir_informe(self):
        p = data_dir() / "informes" / "ultimo.html"
        if p.exists():
            webbrowser.open(p.as_uri())

    def exportar(self, kind):
        if not self.res:
            return
        p = filedialog.asksaveasfilename(defaultextension="." + kind, initialfile=f"cookieguard.{kind}")
        if not p:
            return
        {"html": lambda: reports.export_html(self.res, p), "json": lambda: reports.export_json(self.res, p),
         "csv": lambda: reports.export_csv(self.res["grupos"], Path(p))}[kind]()
        messagebox.showinfo("CookieGuard", f"Exportado (solo metadatos): {p}")

    def incidente(self):
        if self.res:
            messagebox.showinfo("Modo incidente", f"ZIP creado (sin valores de cookies):\n{actions.incident_zip(self.res)}")

    def guardar_ajustes(self):
        try:
            am, ro = int(self.e_am.get()), int(self.e_ro.get())
            assert 0 < am < ro
        except (ValueError, AssertionError):
            messagebox.showerror("CookieGuard", "Los umbrales deben ser numeros: Amarillo < Rojo")
            return
        save_user_config({**{k: v.get() for k, v in self.var.items()}, "umbrales": {"amarillo": am, "rojo": ro},
                          "whitelist_procesos": [l.strip().lower() for l in self.txt_wl.get("1.0", "end").splitlines() if l.strip()]})
        messagebox.showinfo("CookieGuard", "Ajustes guardados. El vigilante se activa/desactiva con la instalacion o 'python -m cookieguard vigilar'.")

    def aceptar_base(self):
        n = engine.accept_baseline()
        messagebox.showinfo("CookieGuard", f"{n} grupo(s) de cambios aceptado(s) como nueva linea base.")

    def elevar(self):
        from . import installer
        messagebox.showinfo("CookieGuard", "Se abrira un analisis con permisos de administrador (UAC). El informe quedara en 'Ultimo informe'.")
        installer.elevate(["analizar", "--no-abrir"])
        self.analizar()


def main():
    app = App()
    if "--smoke" in sys.argv:
        app.after(4000, app.destroy)
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
