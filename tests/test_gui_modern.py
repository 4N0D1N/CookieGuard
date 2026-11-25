"""Pruebas de arquitectura e integridad visual de la interfaz gráfica de CookieGuard.
Verifica que no se produzcan regresiones hacia controles clásicos de Tkinter (ttk.Notebook).
"""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestGUIArchitecture(unittest.TestCase):
    def test_gui_source_no_classic_notebook_regression(self):
        gui_path = ROOT / "cookieguard" / "gui.py"
        self.assertTrue(gui_path.exists(), "cookieguard/gui.py debe existir")
        content = gui_path.read_text(encoding="utf-8")

        # No debe haber ttk.Notebook como navegador principal
        self.assertNotIn("self.nb = ttk.Notebook", content,
                         "Regresión detectada: self.nb = ttk.Notebook encontrado.")

        # Debe tener los métodos del navegador personalizado
        self.assertIn("def _select_tab(", content, "Debe existir _select_tab")
        self.assertIn("def _update_nav_styles(", content, "Debe existir _update_nav_styles")

        # Debe tener temas claro y oscuro
        self.assertIn('"claro": {', content, "Debe existir definición de tema claro")
        self.assertIn('"oscuro": {', content, "Debe existir definición de tema oscuro")

    def test_gui_verifier_script_exists(self):
        tool_path = ROOT / "tools" / "verificar_gui_windows.py"
        self.assertTrue(tool_path.exists(), "tools/verificar_gui_windows.py debe existir")


if __name__ == "__main__":
    unittest.main()
