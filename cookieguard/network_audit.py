# -*- coding: utf-8 -*-
"""
CookieGuard - Auditoría Heurística de Red Local (Archivo hosts y DNS).
Inspecciona si malware o infostealers han manipulado el archivo hosts local
para bloquear sitios de seguridad (antivirus, análisis) o redirigir portales de login.
"""

from __future__ import annotations
import os
import sys
import re
from pathlib import Path
from typing import Dict, Any, List, Optional

SECURITY_DOMAINS = [
    "virustotal.com",
    "kaspersky.com",
    "bitdefender.com",
    "avast.com",
    "avg.com",
    "malwarebytes.com",
    "sophos.com",
    "eset.com",
    "trendmicro.com",
    "microsoft.com",
    "windowsupdate.com",
    "symantec.com",
    "mcafee.com"
]

CRITICAL_AUTH_DOMAINS = [
    "accounts.google.com",
    "login.microsoftonline.com",
    "login.live.com",
    "appleid.apple.com",
    "github.com",
    "auth0.com"
]

def get_default_hosts_path() -> Path:
    """Devuelve la ruta predeterminada del archivo hosts según el SO."""
    if sys.platform.startswith("win"):
        sys_root = os.environ.get("SystemRoot", r"C:\Windows")
        return Path(sys_root) / "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


def parse_hosts_file(hosts_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Lee y parsea un archivo hosts extrayendo asignaciones de IP y dominios."""
    p = hosts_path if hosts_path is not None else get_default_hosts_path()
    entries = []

    if not p.is_file():
        return entries

    try:
        content = p.read_text(encoding="utf-8", errors="ignore")
        for line_num, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Eliminar comentarios en línea
            if "#" in line:
                line = line.split("#", 1)[0].strip()

            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                domains = parts[1:]
                for dom in domains:
                    entries.append({
                        "line": line_num,
                        "ip": ip,
                        "domain": dom.lower().strip()
                    })
    except Exception:
        pass

    return entries


def audit_hosts_entries(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detecta manipulaciones de sinkholing o redirecciones sospechosas en el archivo hosts."""
    anomalies = []

    for entry in entries:
        dom = entry["domain"]
        ip = entry["ip"]
        is_loopback = ip in ["127.0.0.1", "::1", "0.0.0.0"]

        # 1. Sinkholing de seguridad: Bloqueo de antivirus o VirusTotal a loopback
        for sec in SECURITY_DOMAINS:
            if dom == sec or dom.endswith("." + sec):
                if is_loopback:
                    anomalies.append({
                        "tipo": "security_sinkhole",
                        "dominio": dom,
                        "ip": ip,
                        "linea": entry["line"],
                        "severidad": "CRITICAL",
                        "detalle": f"Dominio de seguridad/antivirus '{dom}' redirigido a {ip} para cegar actualizaciones o análisis."
                    })

        # 2. Phishing local: Redirección de autenticación crítica a IPs ajenas
        for auth in CRITICAL_AUTH_DOMAINS:
            if dom == auth:
                if not is_loopback:
                    anomalies.append({
                        "tipo": "auth_spoofing",
                        "dominio": dom,
                        "ip": ip,
                        "linea": entry["line"],
                        "severidad": "CRITICAL",
                        "detalle": f"Portal de autenticación crítico '{dom}' mapeado a IP no local {ip} (posible MITM/Phishing local)."
                    })

    return anomalies


def audit_linux_resolv_conf(resolv_path: Optional[Path] = None) -> Dict[str, Any]:
    """Inspecciona /etc/resolv.conf en sistemas Unix/Linux."""
    p = resolv_path if resolv_path is not None else Path("/etc/resolv.conf")
    nameservers = []

    if p.is_file():
        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) > 1:
                        nameservers.append(parts[1])
        except Exception:
            pass

    return {
        "nameservers": nameservers,
        "count": len(nameservers)
    }


def run_network_audit(custom_hosts_path: Optional[Path] = None) -> Dict[str, Any]:
    """Ejecuta la auditoría integral de red local (hosts y DNS)."""
    hosts_path = custom_hosts_path if custom_hosts_path else get_default_hosts_path()
    entries = parse_hosts_file(hosts_path)
    anomalies = audit_hosts_entries(entries)

    dns_info = {}
    if not sys.platform.startswith("win"):
        dns_info = audit_linux_resolv_conf()

    has_critical = any(a.get("severidad") == "CRITICAL" for a in anomalies)

    return {
        "hosts_path": str(hosts_path),
        "total_hosts_entries": len(entries),
        "anomalies_count": len(anomalies),
        "has_anomalies": len(anomalies) > 0,
        "has_critical": has_critical,
        "anomalies": anomalies,
        "dns_info": dns_info
    }
