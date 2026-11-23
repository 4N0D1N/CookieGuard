"""Módulo de auditoría de certificados raíz y configuración de proxy del sistema y navegador.

Detecta técnicas de intercepción de tráfico TLS/HTTPS (Adversary-in-the-Middle / MITM,
MITRE ATT&CK T1557 / T1556 / T1573) y configuración de proxies locales no autorizados
utilizados por herramientas de espionaje o infostealers para capturar cookies en tránsito.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from .common import IS_LINUX, IS_WIN, log

KNOWN_MITM_CA_PATTERNS = [
    (r"(?i)fiddler", "Certificado de depuración Fiddler (DO_NOT_TRUST_FiddlerRoot)", "Alta"),
    (r"(?i)charles\s*proxy", "Certificado de intercepción Charles Proxy", "Alta"),
    (r"(?i)portswigger|burp\s*suite", "Certificado de prueba Burp Suite / PortSwigger", "Alta"),
    (r"(?i)mitmproxy", "Certificado de intercepción mitmproxy", "Alta"),
    (r"(?i)mkcert", "Certificado local de desarrollo mkcert", "Media"),
    (r"(?i)owasp\s*zap|zed\s*attack", "Certificado de intercepción OWASP ZAP", "Alta"),
]

SUSPICIOUS_PROXY_IPS = ["127.0.0.1", "localhost", "::1", "0.0.0.0"]


def audit_proxy_configuration() -> dict[str, Any]:
    """Audita la configuración de proxies en variables de entorno y en el registro de Windows."""
    findings: list[dict[str, Any]] = []
    proxy_info: dict[str, Any] = {
        "env_proxies": {},
        "system_proxy_enabled": False,
        "proxy_server": None,
        "autoconfig_url": None,
    }

    # 1. Variables de entorno
    for env_var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        val = os.environ.get(env_var)
        if val:
            proxy_info["env_proxies"][env_var] = val
            is_local = any(ip in val.lower() for ip in SUSPICIOUS_PROXY_IPS)
            findings.append({
                "tipo": "proxy_env",
                "origen": env_var,
                "valor": val,
                "severidad": "Alta" if is_local else "Media",
                "descripcion": f"Variable de entorno de proxy activa: {env_var}={val}" +
                               (" (apunta a host local: posible proxy MITM)" if is_local else "")
            })

    # 2. Configuración en registro de Windows
    if IS_WIN:
        try:
            import winreg
            reg_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_READ) as key:
                try:
                    proxy_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
                    proxy_info["system_proxy_enabled"] = bool(proxy_enable)
                except OSError:
                    pass

                try:
                    proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
                    proxy_info["proxy_server"] = str(proxy_server)
                except OSError:
                    pass

                try:
                    autoconfig, _ = winreg.QueryValueEx(key, "AutoConfigURL")
                    proxy_info["autoconfig_url"] = str(autoconfig)
                except OSError:
                    pass

            if proxy_info["system_proxy_enabled"] and proxy_info["proxy_server"]:
                srv = proxy_info["proxy_server"]
                is_local = any(ip in srv.lower() for ip in SUSPICIOUS_PROXY_IPS)
                findings.append({
                    "tipo": "windows_proxy_server",
                    "origen": "HKCU Internet Settings: ProxyServer",
                    "valor": srv,
                    "severidad": "Crítica" if is_local else "Alta",
                    "descripcion": f"Proxy del sistema activo redirigiendo a: {srv}" +
                                   (" (Proxy local: posible secuestro de tráfico web)" if is_local else "")
                })

            if proxy_info["autoconfig_url"]:
                pac = proxy_info["autoconfig_url"]
                findings.append({
                    "tipo": "windows_pac_url",
                    "origen": "HKCU Internet Settings: AutoConfigURL",
                    "valor": pac,
                    "severidad": "Alta",
                    "descripcion": f"Archivo PAC de configuración automática de proxy configurado: {pac}"
                })
        except Exception as e:
            log(f"[CertAudit] Error leyendo registro de proxy en Windows: {e}")

    return {
        "proxy_info": proxy_info,
        "hallazgos": findings
    }


def audit_root_certificates() -> dict[str, Any]:
    """Audita certificados raíz de confianza en busca de Autoridades de Certificación anómalas."""
    findings: list[dict[str, Any]] = []
    certs_checked = 0

    if IS_WIN:
        try:
            # Ejecuta certutil para listar certificados del almacén Root de forma no interactiva
            cmd = ["certutil", "-store", "root"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
            if proc.returncode == 0:
                output = proc.stdout
                for pattern, desc, sev in KNOWN_MITM_CA_PATTERNS:
                    matches = re.findall(pattern, output)
                    if matches:
                        findings.append({
                            "tipo": "root_ca_mitm",
                            "almacen": "Windows Root CA",
                            "patron": pattern,
                            "coincidencias": len(matches),
                            "severidad": sev,
                            "descripcion": f"Detectada CA de intercepción local: {desc}"
                        })
                certs_checked = len(re.findall(r"=== Certificado", output)) or len(re.findall(r"Certificate", output))
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
            log(f"[CertAudit] certutil no disponible o agotó tiempo de espera: {e}")

    elif IS_LINUX:
        # Analizar carpetas habituales de certificados CA locales
        custom_ca_dirs = [
            Path("/usr/local/share/ca-certificates"),
            Path("/etc/ssl/certs"),
            Path.home() / ".pki" / "nssdb"
        ]
        for d in custom_ca_dirs:
            if d.exists() and d.is_dir():
                try:
                    for cert_file in d.glob("*"):
                        if cert_file.is_file() and cert_file.suffix in (".crt", ".pem", ".cer"):
                            certs_checked += 1
                            try:
                                content = cert_file.read_text(encoding="utf-8", errors="ignore")
                                for pattern, desc, sev in KNOWN_MITM_CA_PATTERNS:
                                    if re.search(pattern, content):
                                        findings.append({
                                            "tipo": "root_ca_mitm",
                                            "almacen": str(d),
                                            "archivo": cert_file.name,
                                            "severidad": sev,
                                            "descripcion": f"Certificado de intercepción en {cert_file.name}: {desc}"
                                        })
                            except Exception:
                                pass
                except Exception as e:
                    log(f"[CertAudit] Error inspeccionando directorio {d}: {e}")

    return {
        "certificados_revisados": certs_checked,
        "hallazgos": findings
    }


def audit_certificates_and_proxies() -> dict[str, Any]:
    """Ejecuta la auditoría combinada de proxies y certificados de intercepción."""
    proxy_res = audit_proxy_configuration()
    cert_res = audit_root_certificates()

    total_alertas = len(proxy_res["hallazgos"]) + len(cert_res["hallazgos"])

    return {
        "total_alertas": total_alertas,
        "proxy": proxy_res["proxy_info"],
        "certificados_analizados": cert_res["certificados_revisados"],
        "alertas": proxy_res["hallazgos"] + cert_res["hallazgos"],
        "recomendacion": "Si detectas proxies no autorizados o CAs desconocidas, retíralos de inmediato para evitar descifrado de sesiones HTTPS." if total_alertas > 0 else None
    }
