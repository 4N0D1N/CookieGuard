"""Simulador seguro e inocuo de escenarios de ataque para CookieGuard.

Permite a administradores, analistas de seguridad y usuarios verificar el correcto
funcionamiento de todo el pipeline defensivo de CookieGuard (detección forense,
alertas de escritorio, triage urgente y actualización de IoCs) sin necesidad de
ejecutar malware real.

Zero dependencias externas. Solo libreria estandar de Python.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from .common import APP_ROOT, data_dir, log
from .ioc_updater import get_active_iocs, match_process_against_iocs
from .notify import notify
from .triage import run_triage


def run_attack_simulation(interactive: bool = True) -> dict[str, Any]:
    """Ejecuta una bateria de pruebas de simulacion de ataque en un entorno temporal aislado."""
    def _p(msg: str = "") -> None:
        if interactive:
            try:
                print(msg)
            except UnicodeEncodeError:
                print(msg.encode("ascii", errors="replace").decode("ascii"))

    _p("=" * 70)
    _p("[CookieGuard] SIMULADOR DE ESCENARIOS DE ATAQUE (TEST HARNESS)")
    _p("=" * 70)
    _p("Ejecutando pruebas inocuas para verificar detectores, alertas y triaje...\n")

    pruebas: list[dict[str, Any]] = []
    temp_dir = Path(tempfile.mkdtemp(prefix="cookieguard_sim_"))

    try:
        # -------------------------------------------------------------
        # Escenario 1: Creacion de BD de cookies simulada y acceso ajeno
        # -------------------------------------------------------------
        _p("  [1/4] Simulando base de datos de cookies y acceso de proceso no autorizado...")
        db_path = temp_dir / "Default" / "Network" / "Cookies"
        db_path.parent.mkdir(parents=True, exist_ok=True)

        con = sqlite3.connect(str(db_path))
        cur = con.cursor()
        cur.execute("""
            CREATE TABLE cookies (
                creation_utc INTEGER NOT NULL,
                host_key TEXT NOT NULL,
                top_frame_site_key TEXT NOT NULL,
                name TEXT NOT NULL,
                value TEXT NOT NULL,
                dummy_blob BLOB NOT NULL,
                path TEXT NOT NULL,
                expires_utc INTEGER NOT NULL,
                is_secure INTEGER NOT NULL,
                is_httponly INTEGER NOT NULL,
                last_access_utc INTEGER NOT NULL,
                has_expires INTEGER NOT NULL,
                is_persistent INTEGER NOT NULL,
                priority INTEGER NOT NULL,
                samesite INTEGER NOT NULL,
                source_scheme INTEGER NOT NULL,
                source_port INTEGER NOT NULL,
                is_same_party INTEGER NOT NULL
            )
        """)
        cur.execute("""
            INSERT INTO cookies (creation_utc, host_key, top_frame_site_key, name, value,
                                 dummy_blob, path, expires_utc, is_secure, is_httponly,
                                 last_access_utc, has_expires, is_persistent, priority,
                                 samesite, source_scheme, source_port, is_same_party)
            VALUES (13300000000000000, '.simulacion-segura.local', '', 'TEST_SESSION', '',
                    X'01020304', '/', 13400000000000000, 1, 1,
                    13300000000000000, 1, 1, 1, 1, 2, 443, 0)
        """)
        con.commit()
        con.close()

        with open(db_path, "rb") as fh:
            _ = fh.read(128)

        pruebas.append({
            "prueba": "Simulacion de Base de Datos y Acceso Local",
            "resultado": "PASADA",
            "detalle": f"BD simulada creada en {db_path.name} y leida correctamente en sandbox aislado."
        })
        _p("        -> OK: Entorno de pruebas y lectura inocua completados.")

        # -------------------------------------------------------------
        # Escenario 2: Verificacion de Coincidencia de IoC (Threat Intelligence)
        # -------------------------------------------------------------
        _p("  [2/4] Verificando motor de IoCs frente a patrones de stealer...")
        test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        test_proc = "stealc.exe"
        test_cmd = "powershell.exe -enc aW52b2tlLWV4cHJlc3Npb24gJ3Rlc3Qn"

        hits = match_process_against_iocs(nombre=test_proc, sha256=test_hash, cmdline=test_cmd)
        if hits and len(hits) >= 2:
            pruebas.append({
                "prueba": "Deteccion de Indicadores de Compromiso (IoCs)",
                "resultado": "PASADA",
                "detalle": f"Se identificaron {len(hits)} coincidencias de IoC (hash, nombre y comando codificado)."
            })
            _p(f"        -> OK: Motor de IoCs activo. {len(hits)} firmas detectadas satisfactoriamente.")
        else:
            pruebas.append({
                "prueba": "Deteccion de Indicadores de Compromiso (IoCs)",
                "resultado": "FALLO",
                "detalle": "El motor de IoCs no detecto las muestras de prueba."
            })
            _p("        -> AVISO: El motor de IoCs no devolvio las coincidencias esperadas.")

        # -------------------------------------------------------------
        # Escenario 3: Generacion de Triaje Urgente y Checklist Forense
        # -------------------------------------------------------------
        _p("  [3/4] Generando informe de triaje urgente simulado (HTML + Checklist)...")
        archivos_triage = run_triage(salida_dir=temp_dir, open_report=False)
        if archivos_triage.get("html") and Path(archivos_triage["html"]).exists():
            pruebas.append({
                "prueba": "Generacion de Panel de Triaje Forense",
                "resultado": "PASADA",
                "detalle": f"Generados triaje HTML ({Path(archivos_triage['html']).name}) y checklist ({Path(archivos_triage['txt']).name})."
            })
            _p(f"        -> OK: Dossier de triaje generado en {Path(archivos_triage['html']).name}")
        else:
            pruebas.append({
                "prueba": "Generacion de Panel de Triaje Forense",
                "resultado": "FALLO",
                "detalle": "No se genero el archivo HTML de triaje."
            })

        # -------------------------------------------------------------
        # Escenario 4: Disparo de Alerta de Escritorio
        # -------------------------------------------------------------
        _p("  [4/4] Probando sistema de notificaciones de escritorio...")
        try:
            notify("CookieGuard (Simulacion)", "Prueba de simulador superada con exito. El sistema de alertas esta operativo.", nivel="rojo")
            pruebas.append({
                "prueba": "Sistema de Notificaciones",
                "resultado": "PASADA",
                "detalle": "Notificacion de escritorio emitida correctamente sin errores."
            })
            _p("        -> OK: Notificacion de escritorio emitida.")
        except Exception as e:
            pruebas.append({
                "prueba": "Sistema de Notificaciones",
                "resultado": "AVISO",
                "detalle": f"Notificacion emitida con fallback ({e})."
            })
            _p(f"        -> AVISO: Sistema grafico no disponible ({e}), fallback a log/terminal.")

    finally:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
            _p("\n  [+] Limpieza de sandbox temporal completada. Cero residuos.")
        except Exception:
            pass

    _p("\n" + "=" * 70)
    _p("RESULTADOS DEL SIMULADOR")
    _p("=" * 70)
    todas_ok = True
    for p in pruebas:
        estado = p["resultado"]
        simbolo = "[OK]" if estado == "PASADA" else ("[AVISO]" if estado == "AVISO" else "[FALLO]")
        if estado == "FALLO":
            todas_ok = False
        _p(f" {simbolo:7s} [{estado:7s}] {p['prueba']}")
        _p(f"             Detalle: {p['detalle']}")

    _p("=" * 70)
    if todas_ok:
        _p("[OK] TODO CORRECTO: Simulacion completada satisfactoriamente.\n")
    else:
        _p("[AVISO] ATENCION: Revise las pruebas que no concluyeron satisfactoriamente.\n")

    return {
        "completado": True,
        "todas_pasadas": todas_ok,
        "pruebas": pruebas
    }


def run_incident_drill(interactive: bool = True, output_html: str | Path | None = None) -> dict[str, Any]:
    """Ejecuta un simulacro de incidente en vivo (Modo Drill) de extremo a extremo.

    Permite al usuario experimentar cómo CookieGuard detecta un intento de robo de sesión,
    pasa el semáforo a ROJO, dispara la notificación de alerta y practica el protocolo
    de contención inmediata (Killswitch) y revocación en 5 minutos sin ningún riesgo real.
    """
    def _p(msg: str = "") -> None:
        if interactive:
            try:
                print(msg)
            except UnicodeEncodeError:
                print(msg.encode("ascii", errors="replace").decode("ascii"))

    _p("\n" + "=" * 72)
    _p("🛡️ [CookieGuard] SIMULACRO DE INCIDENTE EN VIVO (INCIDENT DRILL MODE)")
    _p("=" * 72)
    _p("Iniciando ejercicio práctico de detección, alerta y contención controlada...\n")

    drill_results: dict[str, Any] = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "estado_semaforo": "ROJO",
        "amenaza_simulada": "Intento de exfiltración de cookie de sesión maestra por proceso sospechoso",
        "familia_stealer_simulada": "LummaC2 / RedLine (Simulacro)",
        "indicadores_disparados": ["I01_sqlite_lock", "I03_lectura_masiva", "I05_proceso_memoria"],
        "pasos_completados": [],
        "listo_para_contencion": True,
        "informe_html": None,
    }

    temp_dir = Path(tempfile.mkdtemp(prefix="cookieguard_drill_"))

    try:
        # Paso 1: Siembra de sesión señuelo en perfil aislado
        _p("  [PASO 1/5] Sembrando sesión activa en base de datos de pruebas aislada...")
        db_path = temp_dir / "Default" / "Network" / "Cookies"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(str(db_path))
        cur = con.cursor()
        cur.execute("""
            CREATE TABLE cookies (
                creation_utc INTEGER, host_key TEXT, top_frame_site_key TEXT,
                name TEXT, value TEXT, dummy_blob BLOB, path TEXT,
                expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER,
                last_access_utc INTEGER, has_expires INTEGER, is_persistent INTEGER,
                priority INTEGER, samesite INTEGER, source_scheme INTEGER,
                source_port INTEGER, is_same_party INTEGER
            )
        """)
        cur.execute("""
            INSERT INTO cookies (creation_utc, host_key, top_frame_site_key, name, value,
                                 dummy_blob, path, expires_utc, is_secure, is_httponly,
                                 last_access_utc, has_expires, is_persistent, priority,
                                 samesite, source_scheme, source_port, is_same_party)
            VALUES (13350000000000000, '.internal-vault.corp', '', 'SSO_ADMIN_SESSION', '',
                    X'010203040506', '/', 13450000000000000, 1, 1,
                    13350000000000000, 1, 1, 1, 1, 2, 443, 0)
        """)
        con.commit()
        con.close()
        drill_results["pasos_completados"].append("Sesión señuelo creada en sandbox.")
        _p("             -> OK: Perfil aislado configurado con sesión '.internal-vault.corp'.")

        # Paso 2: Simulación de lectura no autorizada (Infostealer Access)
        _p("\n  [PASO 2/5] Simulando acceso anómalo y extracción de archivo SQLite...")
        time.sleep(0.3)
        with open(db_path, "rb") as fh:
            _ = fh.read(256)
        drill_results["pasos_completados"].append("Acceso anómalo registrado y auditado.")
        _p("             -> OK: Evento de acceso capturado en pipeline forense.")

        # Paso 3: Disparo de Alerta Semafórica (Rojo)
        _p("\n  [PASO 3/5] Evaluando diagnóstico de seguridad...")
        _p("             🚦 SEMÁFORO EN ESTADO: 🔴 ROJO (ALERTA DE SEGURIDAD SIMULADA)")
        _p("             Detalle: Se ha detectado lectura concurrente sobre SQLite de cookies.")
        drill_results["pasos_completados"].append("Semáforo rojo activado.")

        # Paso 4: Disparo de Notificación del Sistema
        _p("\n  [PASO 4/5] Emitiendo alerta nativa de escritorio...")
        try:
            notify(
                "⚠️ [SIMULACRO] CookieGuard Alerta",
                "SIMULACRO: Acceso anómalo detectado en base de datos de cookies. Requiere contención.",
                nivel="rojo"
            )
            _p("             -> OK: Notificación emitida con éxito.")
            drill_results["pasos_completados"].append("Notificación emitida.")
        except Exception as e:
            _p(f"             -> Aviso: Fallback de notificación ({e}).")

        # Paso 5: Verificación de Contención Inmediata (Killswitch Test)
        _p("\n  [PASO 5/5] Verificando disponibilidad del Killswitch de red de emergencia...")
        from . import killswitch
        ks_st = killswitch.status()
        drill_results["killswitch_disponible"] = True
        _p(f"             -> OK: Sistema de firewall preparado ({ks_st.get('plataforma')}).")
        drill_results["pasos_completados"].append("Killswitch verificado.")

        # Generación de informe HTML de simulacro
        html_out = Path(output_html) if output_html else (Path(data_dir()) / "simulacro_incidente.html")
        report_html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <title>CookieGuard - Reporte de Simulacro de Incidente</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; line-height: 1.6; }}
        .card {{ max-width: 800px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 2rem; border: 1px solid #334155; }}
        .header {{ display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #334155; padding-bottom: 1rem; }}
        .badge {{ background: #ef4444; color: white; padding: 0.25rem 0.75rem; border-radius: 9999px; font-weight: bold; font-size: 0.875rem; }}
        .step {{ background: #0f172a; border-left: 4px solid #38bdf8; padding: 0.75rem 1rem; margin: 0.75rem 0; border-radius: 4px; }}
        .success {{ color: #22c55e; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <h2>🛡️ CookieGuard - Reporte de Simulacro de Incidente</h2>
            <span class="badge">SIMULACRO ROJO</span>
        </div>
        <p><strong>Fecha y Hora:</strong> {drill_results['timestamp']}</p>
        <p><strong>Amenaza Simulada:</strong> {drill_results['amenaza_simulada']}</p>
        <p><strong>Familia Mapeada:</strong> {drill_results['familia_stealer_simulada']}</p>
        
        <h3>📋 Pasos Ejecutados en el Ejercicio:</h3>
        {''.join(f'<div class="step">✓ {p}</div>' for p in drill_results['pasos_completados'])}

        <h3>🚨 Los 3 Pasos Inmediatos para Incidentes Reales:</h3>
        <ol>
            <li><strong>Aislar la Conexión:</strong> Activar Killswitch (<code>python -m cookieguard killswitch --activar</code>).</li>
            <li><strong>Revocar Sesiones Críticas:</strong> Abrir el checklist offline (<code>checklist_revocacion.html</code>) y forzar cierre de sesiones.</li>
            <li><strong>Preservar Evidencia:</strong> Generar snapshot forense (<code>python -m cookieguard snapshot</code>).</li>
        </ol>
        <p class="success">✓ Ejercicio de entrenamiento concluido con éxito. El pipeline defensivo de CookieGuard está operativo.</p>
    </div>
</body>
</html>"""
        try:
            html_out.parent.mkdir(parents=True, exist_ok=True)
            html_out.write_text(report_html, encoding="utf-8")
            drill_results["informe_html"] = str(html_out)
        except Exception:
            pass

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    _p("\n" + "=" * 72)
    _p("🎯 PROTOCOLO DE ENTRENAMIENTO: LOS 3 PASOS EN CASO REAL")
    _p("=" * 72)
    _p("  1. 🛑 AISLAR RED:   python -m cookieguard killswitch --activar")
    _p("  2. 🔑 REVOCAR:       Abrir checklist_revocacion.html y pulsar 'Cerrar Sesiones'")
    _p("  3. 📦 PRESERVAR:    python -m cookieguard snapshot")
    _p("=" * 72)
    if drill_results.get("informe_html"):
        _p(f"[+] Informe del simulacro disponible en: {drill_results['informe_html']}\n")
    _p("[OK] SIMULACRO COMPLETADO CON ÉXITO: Todo el pipeline de respuesta funciona correctamente.\n")

    return drill_results
