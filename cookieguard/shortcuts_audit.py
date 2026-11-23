"""Módulo de auditoría de accesos directos y lanzadores de navegador (.lnk y .desktop).

Detecta técnicas de persistencia y secuestro de navegador (Browser Shortcut Hijacking,
MITRE ATT&CK T1547 / T1059 / T1204), como la inyección de flags maliciosos:
--load-extension, --proxy-server, --disable-web-security, --remote-debugging-port
o envoltorios intermedios (powershell, cmd.exe, bash, curl).
"""
from __future__ import annotations

import os
import re
import struct
from pathlib import Path
from typing import Any

from .common import IS_WIN, log

KNOWN_BROWSERS = [
    "chrome", "msedge", "edge", "firefox", "brave", "opera", "vivaldi", "arc",
    "chromium", "google-chrome", "waterfox", "librewolf", "yandex"
]

SUSPICIOUS_FLAGS = [
    (r"--load-extension[=\s]([^\s\"']+)", "Carga de extensión local no empaquetada (--load-extension)", "Alta"),
    (r"--proxy-server[=\s]([^\s\"']+)", "Desvío de tráfico a través de proxy no estándar (--proxy-server)", "Alta"),
    (r"--proxy-pac-url[=\s]([^\s\"']+)", "Uso de archivo PAC de autoconfiguración de proxy (--proxy-pac-url)", "Alta"),
    (r"--disable-web-security", "Desactivación de la política del mismo origen (SOP) (--disable-web-security)", "Crítica"),
    (r"--remote-debugging-port[=\s]([0-9]+)", "Apertura de puerto de depuración remota de DevTools (--remote-debugging-port)", "Alta"),
    (r"--user-data-dir[=\s]([^\s\"']+)", "Redirección del directorio de datos de usuario (--user-data-dir)", "Media"),
    (r"--single-process", "Ejecución en proceso único, desactiva el aislamiento de pestañas (--single-process)", "Media"),
    (r"--allow-running-insecure-content", "Permite contenido mixto inseguro (--allow-running-insecure-content)", "Media"),
    (r"--host-rules[=\s]([^\s\"']+)", "Reglas personalizadas de resolución de hosts (--host-rules)", "Alta"),
]

SUSPICIOUS_WRAPPERS = [
    (r"powershell(\.exe)?", "Lanzador envuelto en script PowerShell", "Alta"),
    (r"cmd(\.exe)?\s+/c", "Lanzador envuelto en consola CMD de Windows", "Alta"),
    (r"mshta(\.exe)?", "Ejecución mediante MSHTA (ejecutable de HTML Applications)", "Crítica"),
    (r"(wscript|cscript)(\.exe)?", "Ejecución de script mediante WScript/CScript", "Alta"),
    (r"(curl|wget)\b", "Descarga remota en la línea de comandos", "Crítica"),
    (r"(bash|sh)\s+-c", "Ejecución mediante sub-shell bash/sh", "Media"),
]


def parse_lnk_arguments(data: bytes) -> tuple[str | None, str | None]:
    """Extrae argumentos y posible ruta destino de un fichero .lnk de Windows (MS-SHLLINK).
    
    Devuelve (target_path, command_line_arguments).
    """
    if len(data) < 76:
        return None, None
    try:
        header_size = struct.unpack_from("<I", data, 0)[0]
        if header_size != 76:
            return None, None
        flags = struct.unpack_from("<I", data, 0x14)[0]
        has_target_id = bool(flags & 0x01)
        has_link_info = bool(flags & 0x02)
        has_name = bool(flags & 0x04)
        has_rel_path = bool(flags & 0x08)
        has_working_dir = bool(flags & 0x10)
        has_arguments = bool(flags & 0x20)
        is_unicode = bool(flags & 0x80)

        offset = 76
        if has_target_id:
            if offset + 2 > len(data):
                return None, None
            id_size = struct.unpack_from("<H", data, offset)[0]
            offset += 2 + id_size

        target_path: str | None = None
        if has_link_info:
            if offset + 4 > len(data):
                return None, None
            info_size = struct.unpack_from("<I", data, offset)[0]
            # Try to read local base path if present
            if info_size >= 28 and offset + info_size <= len(data):
                local_base_offset = struct.unpack_from("<I", data, offset + 16)[0]
                if local_base_offset > 0 and offset + local_base_offset < len(data):
                    end_idx = data.find(b"\x00", offset + local_base_offset)
                    if end_idx != -1:
                        raw_base = data[offset + local_base_offset:end_idx]
                        target_path = raw_base.decode("latin-1", errors="replace")
            offset += info_size

        def read_string(curr_offset: int) -> tuple[str, int]:
            if curr_offset + 2 > len(data):
                return "", curr_offset
            cch = struct.unpack_from("<H", data, curr_offset)[0]
            curr_offset += 2
            byte_len = cch * 2 if is_unicode else cch
            if curr_offset + byte_len > len(data):
                return "", curr_offset
            raw = data[curr_offset:curr_offset + byte_len]
            curr_offset += byte_len
            try:
                val = raw.decode("utf-16-le" if is_unicode else "latin-1", errors="replace")
                return val, curr_offset
            except Exception:
                return "", curr_offset

        if has_name:
            _, offset = read_string(offset)
        if has_rel_path:
            rel, offset = read_string(offset)
            if not target_path:
                target_path = rel
        if has_working_dir:
            _, offset = read_string(offset)
        if has_arguments:
            args, offset = read_string(offset)
            return target_path, args

        return target_path, None
    except Exception as e:
        log(f"[Shortcuts] Error parseando LNK: {e}")
        return None, None


def parse_desktop_file(path: Path) -> dict[str, str]:
    """Parsea un archivo .desktop de Linux y extrae sus campos principales."""
    res: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("["):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip()
                if k not in res:
                    res[k] = v
    except Exception as e:
        log(f"[Shortcuts] Error leyendo archivo .desktop {path}: {e}")
    return res


def get_default_shortcut_locations() -> list[Path]:
    """Devuelve las rutas estándar donde residen los accesos directos del sistema."""
    home = Path.home()
    dirs: list[Path] = []

    if IS_WIN:
        appdata = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
        localappdata = Path(os.environ.get("LOCALAPPDATA", home / "AppData/Local"))
        programdata = Path(os.environ.get("PROGRAMDATA", "C:/ProgramData"))

        candidates = [
            home / "Desktop",
            appdata / "Microsoft/Windows/Start Menu/Programs",
            programdata / "Microsoft/Windows/Start Menu/Programs",
            appdata / "Microsoft/Internet Explorer/Quick Launch/User Pinned/TaskBar",
            localappdata / "Microsoft/Windows/Shell",
        ]
        for c in candidates:
            if c.is_dir():
                dirs.append(c)
    else:
        candidates = [
            home / ".local/share/applications",
            home / ".config/autostart",
            home / "Desktop",
            Path("/usr/share/applications"),
            Path("/usr/local/share/applications"),
        ]
        for c in candidates:
            if c.is_dir():
                dirs.append(c)

    return dirs


def analyze_shortcut(path: Path) -> dict[str, Any] | None:
    """Analiza un archivo de acceso directo (.lnk o .desktop) individual."""
    if not path.is_file():
        return None

    name = path.name.lower()
    tipo = "lnk" if name.endswith(".lnk") else ("desktop" if name.endswith(".desktop") else "desconocido")
    if tipo == "desconocido":
        return None

    target = ""
    args = ""

    if tipo == "lnk":
        try:
            raw = path.read_bytes()
            t, a = parse_lnk_arguments(raw)
            target = t or ""
            args = a or ""
            # Fallback en caso de LNK no estándar: buscar strings binarias
            if not args and (b"--load-extension" in raw or b"--proxy-server" in raw):
                args = "(detectado por escaneo de cadenas binarias)"
        except Exception:
            return None
    elif tipo == "desktop":
        entry = parse_desktop_file(path)
        exec_cmd = entry.get("Exec", "")
        if not exec_cmd:
            return None
        parts = exec_cmd.split(None, 1)
        target = parts[0] if parts else ""
        args = parts[1] if len(parts) > 1 else ""

    combined = f"{target} {args} {path.stem}".lower()
    es_navegador = any(b in combined for b in KNOWN_BROWSERS)

    # Si no es un navegador ni invoca nada conocido, pero tiene flags de navegador, también se analiza
    tiene_flags_navegador = any(re.search(pat, args, re.IGNORECASE) for pat, _, _ in SUSPICIOUS_FLAGS)

    if not es_navegador and not tiene_flags_navegador:
        return None

    hallazgos = []
    # 1. Comprobar flags sospechosos
    for pat, desc, sev in SUSPICIOUS_FLAGS:
        m = re.search(pat, args, re.IGNORECASE)
        if m:
            val = m.group(1) if m.groups() else ""
            hallazgos.append({
                "descripcion": f"{desc}: {val}".strip(),
                "severidad": sev,
                "patron": pat
            })

    # 2. Comprobar wrappers sospechosos
    for pat, desc, sev in SUSPICIOUS_WRAPPERS:
        if re.search(pat, f"{target} {args}", re.IGNORECASE):
            hallazgos.append({
                "descripcion": desc,
                "severidad": sev,
                "patron": pat
            })

    # 3. Comprobar ejecutable en carpeta temporal
    target_lower = target.lower()
    if any(tmp in target_lower for tmp in ["/tmp", "\\temp\\", "\\appdata\\local\\temp"]):
        hallazgos.append({
            "descripcion": f"El destino apunta a una carpeta temporal no confiable: {target}",
            "severidad": "Crítica",
            "patron": "temp_dir"
        })

    estado = "alerta" if hallazgos else "ok"
    recomendacion = ""
    if hallazgos:
        recomendacion = "Elimina o repara este acceso directo. Un malware podría estar lanzando el navegador con una extensión espía o un proxy malicioso."

    return {
        "archivo": str(path),
        "nombre": path.name,
        "tipo": tipo,
        "destino": target,
        "argumentos": args,
        "es_navegador": es_navegador,
        "estado": estado,
        "hallazgos": hallazgos,
        "recomendacion": recomendacion
    }


def audit_shortcuts(custom_paths: list[Path] | None = None) -> dict[str, Any]:
    """Audita todos los accesos directos estándar o los directorios especificados."""
    search_dirs = custom_paths if custom_paths is not None else get_default_shortcut_locations()
    analizados: list[dict[str, Any]] = []
    alertas: list[dict[str, Any]] = []

    for d in search_dirs:
        if not d.is_dir():
            continue
        try:
            # Buscar recursivamente hasta 2 niveles de profundidad para evitar loops
            for pattern in ("*.lnk", "*.desktop", "*/*.lnk", "*/*.desktop"):
                for p in d.glob(pattern):
                    res = analyze_shortcut(p)
                    if res:
                        analizados.append(res)
                        if res["estado"] == "alerta":
                            alertas.append(res)
        except Exception as e:
            log(f"[Shortcuts] Error escaneando {d}: {e}")

    return {
        "total_analizados": len(analizados),
        "total_alertas": len(alertas),
        "estado_general": "alerta" if alertas else "limpio",
        "accesos_directos": analizados,
        "alertas": alertas
    }
