# -*- coding: utf-8 -*-
"""
CookieGuard - Verificación de Integridad y Firmas de Binarios de Navegadores.
Verifica que los ejecutables instalados de Chrome, Edge, Firefox, Brave, etc.
sean legítimos, no hayan sido reemplazados por binarios troyanizados en rutas no estándar,
y que mantengan firmas digitales válidas (Authenticode en Windows / Permisos estándar en Linux).
"""

from __future__ import annotations
import os
import sys
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional

KNOWN_PUBLISHERS = [
    "Google LLC",
    "Microsoft Corporation",
    "Mozilla Corporation",
    "Brave Software",
    "Opera Norway AS",
    "Vivaldi Technologies AS"
]

def find_installed_browser_binaries() -> List[Dict[str, str]]:
    """Localiza los ejecutables de navegadores conocidos en el sistema actual."""
    binaries: List[Dict[str, str]] = []

    if sys.platform.startswith("win"):
        # Rutas comunes en Windows
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        local_appdata = os.environ.get("LocalAppData", "")

        candidates = [
            ("Google Chrome", rf"{program_files}\Google\Chrome\Application\chrome.exe"),
            ("Google Chrome", rf"{program_files_x86}\Google\Chrome\Application\chrome.exe"),
            ("Google Chrome (User)", rf"{local_appdata}\Google\Chrome\Application\chrome.exe"),
            ("Microsoft Edge", rf"{program_files}\Microsoft\Edge\Application\msedge.exe"),
            ("Microsoft Edge", rf"{program_files_x86}\Microsoft\Edge\Application\msedge.exe"),
            ("Mozilla Firefox", rf"{program_files}\Mozilla Firefox\firefox.exe"),
            ("Mozilla Firefox", rf"{program_files_x86}\Mozilla Firefox\firefox.exe"),
            ("Brave Browser", rf"{program_files}\BraveSoftware\Brave-Browser\Application\brave.exe"),
        ]

        for name, path_str in candidates:
            if path_str and os.path.isfile(path_str):
                binaries.append({"browser": name, "path": path_str, "os": "windows"})

    else:
        # Rutas comunes en Linux
        linux_candidates = [
            ("Google Chrome", ["google-chrome", "google-chrome-stable"]),
            ("Chromium", ["chromium", "chromium-browser"]),
            ("Mozilla Firefox", ["firefox"]),
            ("Brave Browser", ["brave-browser", "brave"]),
            ("Microsoft Edge", ["microsoft-edge", "microsoft-edge-stable"]),
        ]

        for name, commands in linux_candidates:
            for cmd in commands:
                found = shutil.which(cmd)
                if found and os.path.isfile(found):
                    binaries.append({"browser": name, "path": found, "os": "linux"})
                    break

    return binaries


def verify_windows_authenticode(binary_path: str) -> Dict[str, Any]:
    """Comprueba la firma digital Authenticode de un binario en Windows vía PowerShell."""
    if not sys.platform.startswith("win"):
        return {"status": "SKIPPED", "valid": True, "detail": "No disponible en Linux"}

    try:
        ps_cmd = (
            f"$sig = Get-AuthenticodeSignature -FilePath '{binary_path}'; "
            f"Write-Output $sig.Status; Write-Output ($sig.SignerCertificate.Subject)"
        )
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=8
        )
        if proc.returncode == 0 and proc.stdout:
            lines = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
            status = lines[0] if len(lines) > 0 else "Unknown"
            subject = lines[1] if len(lines) > 1 else ""

            is_valid = status.lower() == "valid"
            is_recognized_publisher = any(pub in subject for pub in KNOWN_PUBLISHERS)

            return {
                "status": status,
                "valid": is_valid,
                "subject": subject,
                "recognized_publisher": is_recognized_publisher,
                "tampered_risk": not is_valid or not is_recognized_publisher
            }
    except Exception as e:
        return {"status": "ERROR", "valid": False, "error": str(e), "tampered_risk": True}

    return {"status": "UNKNOWN", "valid": False, "tampered_risk": True}


def verify_linux_binary_integrity(binary_path: str) -> Dict[str, Any]:
    """Comprueba permisos y propiedades básicas del binario en Linux."""
    try:
        p = Path(binary_path).resolve()
        stat = p.stat()
        # Verificar permisos SUID (alerta crítica si un navegador tiene SUID)
        has_suid = bool(stat.st_mode & 0o4000)
        # Comprobar si reside en un directorio seguro del sistema (/usr, /opt, /snap, /var/lib/flatpak)
        is_system_path = any(str(p).startswith(prefix) for prefix in ["/usr/", "/bin/", "/opt/", "/snap/", "/var/lib/flatpak/", "/nix/store/"])

        return {
            "status": "VALID" if not has_suid and is_system_path else "WARNING",
            "valid": not has_suid,
            "has_suid": has_suid,
            "resolved_path": str(p),
            "is_system_path": is_system_path,
            "tampered_risk": has_suid or not is_system_path
        }
    except Exception as e:
        return {"status": "ERROR", "valid": False, "error": str(e), "tampered_risk": True}


def audit_binary_integrity(custom_binaries: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
    """Audita todos los binarios de navegadores detectados."""
    binaries = custom_binaries if custom_binaries is not None else find_installed_browser_binaries()
    results = []

    for b in binaries:
        path = b["path"]
        browser_name = b["browser"]

        if sys.platform.startswith("win"):
            verification = verify_windows_authenticode(path)
        else:
            verification = verify_linux_binary_integrity(path)

        results.append({
            "browser": browser_name,
            "path": path,
            "verification": verification,
            "is_tampered_risk": verification.get("tampered_risk", False)
        })

    risks = [r for r in results if r.get("is_tampered_risk")]
    return {
        "total_audited": len(results),
        "tampered_count": len(risks),
        "has_tampered_risk": len(risks) > 0,
        "results": results
    }
