# -*- coding: utf-8 -*-
"""Módulo de auditoría de portapapeles y detección de malware Clipper (MITRE ATT&CK T1115).

Analiza de forma segura si el portapapeles contiene credenciales expuestas (JWT,
claves API, claves privadas) o direcciones de criptomonedas susceptibles de secuestro
por stealer clippers (Lumma, RedLine, Vidar, Stealc).
Permite además purgar/vaciar el portapapeles para evitar fuga de credenciales en memoria.

100% Python estándar (ctypes y fallback PowerShell en Windows, herramientas nativas en Linux).
Zero telemetría. Sin dependencias externas.
"""
from __future__ import annotations

import os
import platform
import re
import subprocess
import sys
from typing import Any


# Patrones de credenciales sensibles y tokens en portapapeles
SENSITIVE_PATTERNS = [
    {
        "tipo": "JWT_TOKEN",
        "severidad": "CRITICA",
        "regex": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "descripcion": "Token de autenticación JWT activo en portapapeles expuesto a procesos locales.",
    },
    {
        "tipo": "BEARER_AUTH",
        "severidad": "ALTA",
        "regex": re.compile(r"Bearer\s+[A-Za-z0-9._~+/-]{20,}", re.IGNORECASE),
        "descripcion": "Cabecera de autorización Bearer presente en el portapapeles.",
    },
    {
        "tipo": "PRIVATE_KEY",
        "severidad": "CRITICA",
        "regex": re.compile(r"-----BEGIN (?:RSA|OPENSSH|EC|DSA|PGP)?\s*PRIVATE KEY-----"),
        "descripcion": "Clave privada criptográfica expuesta en texto plano en el portapapeles.",
    },
    {
        "tipo": "AWS_KEY",
        "severidad": "CRITICA",
        "regex": re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"),
        "descripcion": "Identificador de clave de acceso AWS en portapapeles.",
    },
    {
        "tipo": "GITHUB_TOKEN",
        "severidad": "CRITICA",
        "regex": re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}"),
        "descripcion": "Token personal de GitHub en el portapapeles.",
    },
    {
        "tipo": "CONNECTION_STRING",
        "severidad": "ALTA",
        "regex": re.compile(r"(?:postgres|postgresql|mysql|mongodb|redis)://[^\s:]+:[^\s@]+@[^\s]+", re.IGNORECASE),
        "descripcion": "Cadena de conexión a base de datos con contraseña en el portapapeles.",
    },
]

# Patrones de direcciones de criptomonedas (objetivos de clippers)
CRYPTO_PATTERNS = [
    {
        "tipo": "CRYPTO_BITCOIN",
        "moneda": "Bitcoin (BTC)",
        "regex": re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b"),
    },
    {
        "tipo": "CRYPTO_ETHEREUM",
        "moneda": "Ethereum / EVM (ETH)",
        "regex": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    },
    {
        "tipo": "CRYPTO_SOLANA",
        "moneda": "Solana (SOL)",
        "regex": re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b"),
    },
    {
        "tipo": "CRYPTO_TRON",
        "moneda": "Tron (TRX)",
        "regex": re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b"),
    },
]


def _read_clipboard_windows() -> str:
    """Lee el contenido de texto del portapapeles en Windows usando ctypes, con fallback a PowerShell."""
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        CF_UNICODETEXT = 13

        if user32.OpenClipboard(None):
            try:
                handle = user32.GetClipboardData(CF_UNICODETEXT)
                if handle:
                    kernel32.GlobalLock.restype = ctypes.c_void_p
                    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
                    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]

                    ptr = kernel32.GlobalLock(handle)
                    if ptr:
                        try:
                            text = ctypes.c_wchar_p(ptr).value or ""
                            if text:
                                return text
                        finally:
                            kernel32.GlobalUnlock(handle)
            finally:
                user32.CloseClipboard()
    except Exception:
        pass

    # Fallback PowerShell si ctypes falla
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Get-Clipboard"],
            capture_output=True, text=True, timeout=3, errors="ignore"
        )
        if proc.returncode == 0 and proc.stdout:
            return proc.stdout.strip()
    except Exception:
        pass

    return ""


def _clear_clipboard_windows() -> bool:
    """Vacía el portapapeles de Windows de forma segura (ctypes + fallback PowerShell)."""
    cleared = False
    try:
        import ctypes
        user32 = ctypes.windll.user32
        if user32.OpenClipboard(None):
            try:
                user32.EmptyClipboard()
                cleared = True
            finally:
                user32.CloseClipboard()
    except Exception:
        pass

    if not cleared:
        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Set-Clipboard -Value $null"],
                capture_output=True, text=True, timeout=3, errors="ignore"
            )
            if proc.returncode == 0:
                cleared = True
        except Exception:
            pass

    return cleared


def _read_clipboard_linux() -> str:
    """Lee el texto del portapapeles en Linux mediante wl-paste, xclip o xsel."""
    for cmd in [["wl-paste", "--no-newline"], ["xclip", "-selection", "clipboard", "-o"], ["xsel", "--clipboard", "--output"]]:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=1.5, check=False)
            if p.returncode == 0 and p.stdout:
                return p.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
    return ""


def _clear_clipboard_linux() -> bool:
    """Vacía el portapapeles en Linux mediante herramientas disponibles."""
    cleared = False
    for cmd, stdin_data in [
        (["wl-copy", "--clear"], None),
        (["xclip", "-selection", "clipboard"], b""),
        (["xsel", "--clipboard", "--clear"], None),
    ]:
        try:
            p = subprocess.run(cmd, input=stdin_data, capture_output=True, timeout=1.5, check=False)
            if p.returncode == 0:
                cleared = True
                break
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
    return cleared


def read_system_clipboard() -> str:
    """Obtiene el texto actualmente almacenado en el portapapeles del sistema operativo."""
    system = platform.system()
    if system == "Windows":
        try:
            return _read_clipboard_windows()
        except Exception:
            return ""
    elif system == "Linux" or system == "Darwin":
        try:
            return _read_clipboard_linux()
        except Exception:
            return ""
    return ""


def clear_system_clipboard() -> bool:
    """Limpia el contenido del portapapeles para evitar que procesos maliciosos lean credenciales."""
    system = platform.system()
    if system == "Windows":
        try:
            return _clear_clipboard_windows()
        except Exception:
            return False
    else:
        try:
            return _clear_clipboard_linux()
        except Exception:
            return False


def audit_clipboard(sample_text: str | None = None) -> dict[str, Any]:
    """Audita el portapapeles actual buscando tokens de sesión expuestos o patrones de clipper malware.

    Si se proporciona sample_text, audita ese texto directamente (útil para pruebas y CI).
    """
    text = sample_text if sample_text is not None else read_system_clipboard()
    
    alertas: list[dict[str, Any]] = []
    cripto_detectadas: list[dict[str, str]] = []

    if not text:
        return {
            "accesible": sample_text is not None or bool(text),
            "longitud_texto": 0,
            "has_alerts": False,
            "has_critical": False,
            "total_alertas": 0,
            "alertas": [],
            "cripto_detectadas": [],
            "recomendacion": "El portapapeles está vacío o no contiene texto legible.",
            "mitre_technique": "T1115 (Clipboard Data)",
        }

    # 1. Comprobación de credenciales y tokens sensibles
    for p in SENSITIVE_PATTERNS:
        matches = p["regex"].findall(text)
        if matches:
            alertas.append({
                "tipo": p["tipo"],
                "severidad": p["severidad"],
                "descripcion": p["descripcion"],
                "coincidencias": len(matches),
                "mitre": "T1115",
                "recomendacion": "Purgar el portapapeles inmediatamente con 'cookieguard clipboard --limpiar'."
            })

    # 2. Comprobación de direcciones de criptomonedas (objetivo de Clippers)
    for c in CRYPTO_PATTERNS:
        matches = c["regex"].findall(text)
        if matches:
            for m in matches[:3]:
                anon = m[:6] + "..." + m[-4:] if len(m) > 12 else m[:4] + "..."
                cripto_detectadas.append({
                    "moneda": c["moneda"],
                    "direccion_anonimizada": anon,
                })
            alertas.append({
                "tipo": "DIRECCION_CRIPTOMONEDA",
                "severidad": "MEDIA",
                "descripcion": f"Dirección de {c['moneda']} detectada en portapapeles. Los 'clippers' suelen sustituir estas direcciones.",
                "coincidencias": len(matches),
                "mitre": "T1115",
                "recomendacion": "Verifica minuciosamente la dirección antes de confirmar cualquier transferencia."
            })

    has_critical = any(a["severidad"] == "CRITICA" for a in alertas)
    has_alerts = len(alertas) > 0

    if has_critical:
        rec = "¡ALERTA CRÍTICA! Hay secretos o tokens activos en tu portapapeles. Ejecuta 'cookieguard clipboard --limpiar' para vaciarlo."
    elif has_alerts:
        rec = "Se detectaron datos sensibles o direcciones en el portapapeles. Revisa las alertas y purga el contenido si ya no lo necesitas."
    else:
        rec = "Portapapeles limpio: no se detectaron tokens, claves ni patrones susceptibles de ataque clipper."

    return {
        "accesible": True,
        "longitud_texto": len(text),
        "has_alerts": has_alerts,
        "has_critical": has_critical,
        "total_alertas": len(alertas),
        "alertas": alertas,
        "cripto_detectadas": cripto_detectadas,
        "recomendacion": rec,
        "mitre_technique": "T1115 (Clipboard Data)",
    }
