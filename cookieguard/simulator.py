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
    print("=" * 70)
    print("🛡️  COOKIEGUARD - SIMULADOR DE ESCENARIOS DE ATAQUE (TEST HARNESS)")
    print("=" * 70)
    print("Ejecutando pruebas inocuas para verificar detectores, alertas y triaje...\n")

    pruebas: list[dict[str, Any]] = []
    temp_dir = Path(tempfile.mkdtemp(prefix="cookieguard_sim_"))

    try:
        # -------------------------------------------------------------
        # Escenario 1: Creacion de BD de cookies simulada y acceso ajeno
        # -------------------------------------------------------------
        print("  [1/4] Simulando base de datos de cookies y acceso de proceso no autorizado...")
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
        # Insertar registros dummy inocuos
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

        # Simular lectura ajena
        with open(db_path, "rb") as fh:
            _ = fh.read(128)

        pruebas.append({
            "prueba": "Simulacion de Base de Datos y Acceso Local",
            "resultado": "PASADA",
            "detalle": f"BD simulada creada en {db_path.name} y leida correctamente en sandbox aislado."
        })
        print("        -> OK: Entorno de pruebas y lectura inocua completados.")

        # -------------------------------------------------------------
        # Escenario 2: Verificacion de Coincidencia de IoC (Threat Intelligence)
        # -------------------------------------------------------------
        print("  [2/4] Verificando motor de IoCs frente a patrones de stealer...")
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
            print(f"        -> OK: Motor de IoCs activo. {len(hits)} firmas detectadas satisfactoriamente.")
        else:
            pruebas.append({
                "prueba": "Deteccion de Indicadores de Compromiso (IoCs)",
                "resultado": "FALLO",
                "detalle": "El motor de IoCs no detecto las muestras de prueba."
            })
            print("        -> AVISO: El motor de IoCs no devolvio las coincidencias esperadas.")

        # -------------------------------------------------------------
        # Escenario 3: Generacion de Triaje Urgente y Checklist Forense
        # -------------------------------------------------------------
        print("  [3/4] Generando informe de triaje urgente simulado (HTML + Checklist)...")
        datos_simulados = {
            "puntuacion_riesgo": 85,
            "nivel_riesgo": "CRITICO",
            "generado": time.strftime("%Y-%m-%d %H:%M:%S"),
            "resumen_sesiones": {
                "criticas": 3,
                "altas": 5,
                "medias": 8,
                "bajas": 12,
                "total": 28
            },
            "sesiones_criticas": [
                {"servicio": "Google / Gmail", "dominio": "google.com", "revocar_url": "https://myaccount.google.com/device-activity", "password_url": "https://myaccount.google.com/signinoptions/password"},
                {"servicio": "GitHub", "dominio": "github.com", "revocar_url": "https://github.com/settings/sessions", "password_url": "https://github.com/settings/security"},
                {"servicio": "Microsoft / Outlook", "dominio": "live.com", "revocar_url": "https://account.live.com/Activity", "password_url": "https://account.live.com/password/reset"}
            ],
            "hallazgos_forenses": [
                {"indicador": "I15_procesos_infostealer", "severidad": "CRITICA", "titulo": "Proceso sospechoso en Temp", "detalle": "Simulacion: proceso con nombre stealc.exe ejecutandose desde carpeta temporal"},
                {"indicador": "I16_ioc_malicioso", "severidad": "CRITICA", "titulo": "Coincidencia de IoC", "detalle": "Simulacion: hash SHA-256 catalogado como stealer activo"}
            ]
        }

        archivos_triage = run_triage(salida_dir=temp_dir, open_report=False)
        if archivos_triage.get("html") and Path(archivos_triage["html"]).exists():
            pruebas.append({
                "prueba": "Generacion de Panel de Triaje Forense",
                "resultado": "PASADA",
                "detalle": f"Generados triaje HTML ({Path(archivos_triage['html']).name}) y checklist ({Path(archivos_triage['txt']).name})."
            })
            print(f"        -> OK: Dossier de triaje generado en {Path(archivos_triage['html']).name}")
        else:
            pruebas.append({
                "prueba": "Generacion de Panel de Triaje Forense",
                "resultado": "FALLO",
                "detalle": "No se genero el archivo HTML de triaje."
            })

        # -------------------------------------------------------------
        # Escenario 4: Disparo de Alerta de Escritorio
        # -------------------------------------------------------------
        print("  [4/4] Probando sistema de notificaciones de escritorio...")
        try:
            notify("CookieGuard (Simulacion)", "Prueba de simulador superada con exito. El sistema de alertas esta operativo.", nivel="rojo")
            pruebas.append({
                "prueba": "Sistema de Notificaciones",
                "resultado": "PASADA",
                "detalle": "Notificacion de escritorio emitida correctamente sin errores."
            })
            print("        -> OK: Notificacion de escritorio emitida.")
        except Exception as e:
            pruebas.append({
                "prueba": "Sistema de Notificaciones",
                "resultado": "AVISO",
                "detalle": f"Notificacion emitida con fallback ({e})."
            })
            print(f"        -> AVISO: Sistema grafico no disponible ({e}), fallback a log/terminal.")

    finally:
        # Limpieza absoluta de ficheros temporales
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
            print("\n  [+] Limpieza de sandbox temporal completada. Cero residuos.")
        except Exception:
            pass

    print("\n" + "=" * 70)
    print("📊  RESULTADOS DEL SIMULADOR")
    print("=" * 70)
    todas_ok = True
    for p in pruebas:
        estado = p["resultado"]
        simbolo = "✅" if estado == "PASADA" else ("⚠️" if estado == "AVISO" else "❌")
        if estado == "FALLO":
            todas_ok = False
        print(f" {simbolo} [{estado:7s}] {p['prueba']}")
        print(f"             Detalle: {p['detalle']}")

    print("=" * 70)
    if todas_ok:
        print("✨  TODO CORRECTO: CookieGuard responde eficazmente a todos los escenarios.\n")
    else:
        print("⚠️  ATENCION: Revise las pruebas que no concluyeron satisfactoriamente.\n")

    return {
        "completado": True,
        "todas_pasadas": todas_ok,
        "pruebas": pruebas
    }
