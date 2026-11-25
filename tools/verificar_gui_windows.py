"""Comprobación visual y arquitectónica de la GUI de CookieGuard en Windows.

Detecta si la GUI regresa a los controles clásicos de Tkinter (como ttk.Notebook
como navegador principal o marcos con bordes duros relief="solid") y, cuando
hay un entorno gráfico (como en Windows Runner), captura un screenshot de la ventana
para auditoría visual en el flujo de CI / compilación.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def verificar_codigo_estatico() -> list[str]:
    """Valida que el código fuente de gui.py no contenga regresiones a controles arcaicos."""
    errores = []
    gui_file = ROOT / "cookieguard" / "gui.py"
    if not gui_file.exists():
        return ["No se encontró cookieguard/gui.py"]

    content = gui_file.read_text(encoding="utf-8")

    # Invariante 1: No debe instanciar ttk.Notebook en la ventana principal
    if "self.nb = ttk.Notebook" in content:
        errores.append("Regresión detectada: 'self.nb = ttk.Notebook' encontrado. La navegación principal debe ser propia y moderna.")

    # Invariante 2: Debe contar con la navegación propia _select_tab y _update_nav_styles
    if "def _select_tab(" not in content:
        errores.append("Falta el método de navegación propia '_select_tab'.")
    if "def _update_nav_styles(" not in content:
        errores.append("Falta el método de actualización de estilos de navegación '_update_nav_styles'.")

    # Invariante 3: Las tarjetas de resumen no deben usar relief="solid" con bd=1
    if 'relief="solid", bd=1' in content:
        errores.append("Regresión visual: Se detectó relief='solid', bd=1 en gui.py. Las tarjetas deben tener acabado plano moderno.")

    # Invariante 4: Debe soportar selector y temas claro y oscuro
    if '"claro"' not in content or '"oscuro"' not in content:
        errores.append("Falta la definición de los temas 'claro' y 'oscuro'.")

    return errores


def verificar_en_vivo() -> int:
    """Ejecuta la GUI en memoria si Tkinter y display están disponibles."""
    print("=== 1. VERIFICACIÓN ESTÁTICA DE LA GUI ===")
    errores_estaticos = verificar_codigo_estatico()
    if errores_estaticos:
        for err in errores_estaticos:
            print(f"  [FALLO] {err}", file=sys.stderr)
        return 1
    print("  [OK] Código fuente de gui.py cumple las directivas de diseño moderno (sin ttk.Notebook principal).")

    print("\n=== 2. VERIFICACIÓN EN TIEMPO DE EJECUCIÓN (TKINTER) ===")
    try:
        import tkinter as tk
        from tkinter import ttk
    except ImportError as e:
        print(f"  [AVISO] Tkinter no está presente en este entorno ({e}). Omitiendo validación en vivo.")
        return 0

    try:
        # Intentar inicializar App
        from cookieguard import gui

        app = gui.App()
        app.update_idletasks()
        app.update()

        # Comprobar que no hay ttk.Notebook en la raíz
        for child in app.winfo_children():
            if isinstance(child, ttk.Notebook):
                print("  [FALLO] Se detectó ttk.Notebook montado directamente en la ventana principal.", file=sys.stderr)
                app.destroy()
                return 1

        # Comprobar barra de navegación personalizada
        if not hasattr(app, "nav") or not hasattr(app, "nav_buttons"):
            print("  [FALLO] La ventana no contiene la barra de navegación personalizada 'app.nav'.", file=sys.stderr)
            app.destroy()
            return 1
        print(f"  [OK] Barra de navegación personalizada activa ({len(app.nav_buttons)} pestañas).")

        # Comprobar tarjetas KPI sin relieve tosco
        if hasattr(app, "kpi_cards"):
            for k, card in app.kpi_cards.items():
                c_relief = card["frame"].cget("relief")
                c_bd = card["frame"].cget("bd")
                if c_relief == "solid" and int(c_bd) > 0:
                    print(f"  [FALLO] Tarjeta KPI '{k}' tiene relieve arcaico ({c_relief}, bd={c_bd}).", file=sys.stderr)
                    app.destroy()
                    return 1
        print(f"  [OK] Tarjetas KPI verificadas con acabado plano moderno.")

        # Comprobar alternancia de temas
        print("  [INFO] Verificando selector de temas...")
        original_theme = app.current_theme
        app.toggle_theme()
        app.update_idletasks()
        app.update()
        if app.current_theme == original_theme:
            print("  [FALLO] toggle_theme() no alteró el tema.", file=sys.stderr)
            app.destroy()
            return 1
        print(f"  [OK] Cambio de tema verificado a '{app.current_theme}'.")

        # Volver al tema original
        app.toggle_theme()
        app.update_idletasks()
        app.update()

        # Captura visual si PIL está disponible (típico en Windows CI)
        artifact_dir = ROOT / "artifacts"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        img_path = artifact_dir / "cookieguard_windows_gui.png"

        try:
            from PIL import ImageGrab
            time.sleep(0.3)
            x = app.winfo_rootx()
            y = app.winfo_rooty()
            w = app.winfo_width()
            h = app.winfo_height()
            if w > 100 and h > 100:
                img = ImageGrab.grab(bbox=(x, y, x + w, y + h))
                img.save(str(img_path))
                print(f"  [OK] Captura de pantalla de la GUI guardada en: {img_path}")
            else:
                print(f"  [INFO] Dimensiones de ventana muy reducidas para captura ({w}x{h}).")
        except Exception as e:
            print(f"  [INFO] Captura con Pillow no realizada ({e}). Verificación estructural completada.")

        app.destroy()
        print("\n=== COMPROBACIÓN VISUAL DE LA GUI EN WINDOWS EXITOSA ===")
        return 0

    except Exception as e:
        print(f"  [ERROR] Fallo durante la ejecución de la GUI: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(verificar_en_vivo())
