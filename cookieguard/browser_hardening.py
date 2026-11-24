"""
Generador y validador de directivas de Hardening de Sistema para Navegadores.
Genera plantillas de políticas empresariales para Google Chrome, Microsoft Edge,
Brave y Firefox destinadas a mitigar la exfiltración de credenciales por infostealers:
- Bloqueo de depuración remota no autorizada (RemoteDebuggingAllowed = false)
- Forzar aislamiento estricto de procesos por sitio (SitePerProcess = true)
- Advertencias obligatorias ante flags inseguras de línea de comandos
- Habilitación de Device Bound Session Credentials (DBSC)
- Restricción de instalación de extensiones desconocidas
"""

import os
import sys
import json
from typing import Dict, Any, List, Optional

# Políticas recomendadas de Chromium (Chrome, Edge, Brave)
CHROMIUM_RECOMMENDED_POLICIES = {
    # Mitigación contra robo de sesión vía CDP
    "RemoteDebuggingAllowed": False,
    "CommandLineFlagSecurityWarningsEnabled": True,
    # Aislamiento estricto de memoria (anti-Spectre / anti-memory scrapers)
    "SitePerProcess": True,
    "IsolateOrigins": "*",
    # Protección de credenciales y sesiones
    "DeviceBoundSessionCredentialsEnabled": True,
    "PasswordProtectionWarningTrigger": 1,
    # Seguridad de extensiones
    "ExtensionInstallBlocklist": ["*"],
    # Forzar actualización automática para parchear vulnerabilidades de 0-day
    "RelaunchNotification": 1,
}

# Políticas para Firefox (distribution/policies.json)
FIREFOX_RECOMMENDED_POLICIES = {
    "policies": {
        "DisableDeveloperTools": False,  # No deshabilitar completamente para no romper trabajo legítimo
        "ExtensionSettings": {
            "*": {
                "installation_mode": "blocked"
            }
        },
        "DisablePasswordReveal": True,
        "SanitizeOnShutdown": {
            "Cache": False,
            "Cookies": False,  # Se mantiene false para no borrar sesiones deseadas por sorpresa
            "History": False
        }
    }
}


def generate_windows_reg_script() -> str:
    """Genera un archivo .reg para Windows con políticas para Chrome y Edge."""
    lines = [
        "Windows Registry Editor Version 5.00",
        "",
        "; ====================================================================",
        "; CookieGuard Hardening Policies for Google Chrome & Microsoft Edge",
        "; Aplica directivas de seguridad para prevenir robo de cookies y CDP.",
        "; ====================================================================",
        "",
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Google\\Chrome]",
        '"RemoteDebuggingAllowed"=dword:00000000',
        '"CommandLineFlagSecurityWarningsEnabled"=dword:00000001',
        '"SitePerProcess"=dword:00000001',
        '"DeviceBoundSessionCredentialsEnabled"=dword:00000001',
        "",
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Edge]",
        '"RemoteDebuggingAllowed"=dword:00000000',
        '"CommandLineFlagSecurityWarningsEnabled"=dword:00000001',
        '"SitePerProcess"=dword:00000001',
        '"DeviceBoundSessionCredentialsEnabled"=dword:00000001',
        ""
    ]
    return "\r\n".join(lines)


def generate_linux_policy_json() -> str:
    """Genera archivo JSON de políticas para Chrome/Chromium en Linux."""
    return json.dumps(CHROMIUM_RECOMMENDED_POLICIES, indent=2)


def generate_firefox_policy_json() -> str:
    """Genera archivo policies.json para Firefox."""
    return json.dumps(FIREFOX_RECOMMENDED_POLICIES, indent=2)


def generate_hardening_bundle(output_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    Genera el lote completo de archivos de políticas listos para aplicar en Windows y Linux.
    """
    if not output_dir:
        output_dir = os.path.join(os.getcwd(), "cookieguard_hardening_policies")
    os.makedirs(output_dir, exist_ok=True)

    # 1. Windows .reg
    win_reg_path = os.path.join(output_dir, "cookieguard_browser_hardening.reg")
    with open(win_reg_path, "w", encoding="utf-8") as f:
        f.write(generate_windows_reg_script())

    # 2. Linux Chromium / Chrome JSON
    linux_chrome_path = os.path.join(output_dir, "chrome_policies_managed.json")
    with open(linux_chrome_path, "w", encoding="utf-8") as f:
        f.write(generate_linux_policy_json())

    # 3. Firefox policies.json
    firefox_path = os.path.join(output_dir, "firefox_policies.json")
    with open(firefox_path, "w", encoding="utf-8") as f:
        f.write(generate_firefox_policy_json())

    # 4. Instrucciones README
    readme_path = os.path.join(output_dir, "INSTRUCCIONES_HARDENING.md")
    instructions = f"""# 🛡️ Guía de Aplicación de Políticas de Hardening (CookieGuard)

Estos archivos configuran directivas a nivel de sistema operativo para blindar tus navegadores frente a infostealers.

## 🪟 En Windows
1. Haz doble clic en `{os.path.basename(win_reg_path)}` o ejecútalo como Administrador.
2. Acepta la solicitud de Control de Cuentas de Usuario (UAC) para añadir las claves a `HKLM\\SOFTWARE\\Policies`.
3. Reinicia Chrome y Edge. Al entrar en `chrome://policy` o `edge://policy`, verás las reglas aplicadas.

## 🐧 En Linux
1. Para Google Chrome:
   ```bash
   sudo mkdir -p /etc/opt/chrome/policies/managed
   sudo cp {os.path.basename(linux_chrome_path)} /etc/opt/chrome/policies/managed/cookieguard.json
   ```
2. Para Chromium:
   ```bash
   sudo mkdir -p /etc/chromium/policies/managed
   sudo cp {os.path.basename(linux_chrome_path)} /etc/chromium/policies/managed/cookieguard.json
   ```
3. Para Firefox:
   ```bash
   sudo mkdir -p /etc/firefox/policies
   sudo cp {os.path.basename(firefox_path)} /etc/firefox/policies/policies.json
   ```

## 📋 Resumen de Protecciones Aplicadas
- **RemoteDebuggingAllowed = false**: Impide que malware abra Chrome/Edge con flags de depuración remota para volcar sesiones en memoria.
- **CommandLineFlagSecurityWarningsEnabled = true**: Alerta al usuario si un proceso abre el navegador con flags manipuladas.
- **SitePerProcess = true**: Fuerza el aislamiento estricto de procesos por dominio (protección contra Spectre y volcadores de RAM).
- **DeviceBoundSessionCredentialsEnabled = true**: Activa el enlace criptográfico de sesiones DBSC cuando el servidor lo soporte.
"""
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(instructions)

    return {
        "directorio": output_dir,
        "archivos_generados": [
            win_reg_path,
            linux_chrome_path,
            firefox_path,
            readme_path
        ],
        "total_archivos": 4,
        "politicas_chromium": CHROMIUM_RECOMMENDED_POLICIES
    }


def audit_system_policies(test_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Comprueba si las políticas de hardening están actualmente presentes en el sistema operativo.
    """
    if test_data is not None:
        return test_data

    hallazgos = []
    recomendaciones = []
    politicas_detectadas = False

    if sys.platform == "win32":
        # Comprobar claves de registro en Windows
        try:
            import winreg
            for path in [r"SOFTWARE\Policies\Google\Chrome", r"SOFTWARE\Policies\Microsoft\Edge"]:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                        politicas_detectadas = True
                        try:
                            val, _ = winreg.QueryValueEx(key, "RemoteDebuggingAllowed")
                            if val == 0:
                                hallazgos.append(f"[OK] {path}: RemoteDebuggingAllowed deshabilitado correctamente.")
                            else:
                                hallazgos.append(f"[ALERTA] {path}: RemoteDebuggingAllowed está permitido ({val}).")
                        except FileNotFoundError:
                            hallazgos.append(f"[AVISO] {path}: RemoteDebuggingAllowed no configurado explícitamente.")
                except FileNotFoundError:
                    pass
        except Exception as e:
            hallazgos.append(f"No se pudo consultar el Registro: {e}")
    else:
        # Comprobar directorios en Linux
        rutas_linux = [
            "/etc/opt/chrome/policies/managed",
            "/etc/chromium/policies/managed",
            "/etc/firefox/policies"
        ]
        for r in rutas_linux:
            if os.path.exists(r) and os.listdir(r):
                politicas_detectadas = True
                archivos = os.listdir(r)
                hallazgos.append(f"[OK] Políticas detectadas en {r}: {', '.join(archivos)}")

    if not politicas_detectadas:
        recomendaciones.append("No se detectaron políticas empresariales de hardening. Genera y aplica las plantillas con `cookieguard politicas`.")

    return {
        "politicas_activas": politicas_detectadas,
        "hallazgos": hallazgos,
        "recomendaciones": recomendaciones
    }
