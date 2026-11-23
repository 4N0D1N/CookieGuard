"""Módulo de recolección y captura de evidencias forenses volátiles (Live Forensics).

Genera un snapshot empaquetado y cifrado/hasheado con el estado del sistema en el
momento del incidente: conexiones de red activas, árbol de procesos, caché DNS y
hashes SHA-256 de binarios sospechosos para análisis posterior o reporte al SOC.
Incluye saneamiento heurístico de datos personales y cifrado autenticado opcional
mediante la dependencia extra ``cryptography``.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import secrets
import sys
import tempfile
import time
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

from .common import IS_LINUX, IS_WIN, data_dir, log, ps, run


def capture_volatile_snapshot(
    reason: str = "alerta_detectada",
    output_dir: Path | None = None,
    sanitize: bool = True,
    password: str | None = None
) -> str:
    """Captura las evidencias volátiles del sistema y las empaqueta en un ZIP con manifiesto SHA-256.

    Args:
        reason: Motivo de la captura.
        output_dir: Carpeta destino (por defecto data_dir() / 'forense').
        sanitize: Si es True, anonimiza el nombre de usuario y redacta tokens en líneas de comandos.
        password: Si se especifica, cifra el paquete final con contenedor autenticado PBKDF2-HMAC-SHA256.
    """
    if password is not None and len(password) < 12:
        raise ValueError("Usa una contraseña de al menos 12 caracteres para cifrar el snapshot.")

    if output_dir is None:
        target_dir = data_dir() / "forense"
    else:
        target_dir = Path(output_dir)

    target_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    zip_path = target_dir / f"snapshot_{timestamp}.zip"

    manifest_entries = {}
    current_user = os.environ.get("USERNAME") or os.environ.get("USER") or "desconocido"
    if sanitize:
        reason = _sanitize_data(reason, current_user)

    with tempfile.TemporaryDirectory() as td:
        temp_path = Path(td)

        # 1. Información del sistema
        sys_info = {
            "timestamp": datetime.now().isoformat(),
            "motivo": reason,
            "hostname": "<REDACTED_HOST>" if sanitize else platform.node(),
            "sistema": platform.system(),
            "version": platform.version(),
            "arquitectura": platform.machine(),
            "usuario": "<REDACTED_USER>" if sanitize else current_user,
            "anonimizado": sanitize
        }
        _write_artifact(temp_path, "entorno_sistema.json", sys_info, manifest_entries)

        # 2. Árbol de procesos
        procs = _collect_processes()
        if sanitize:
            procs = _sanitize_data(procs, current_user)
        _write_artifact(temp_path, "procesos.json", procs, manifest_entries)

        # 3. Conexiones de red activas
        conns = _collect_network_connections()
        if sanitize:
            conns = _sanitize_data(conns, current_user)
        _write_artifact(temp_path, "conexiones_red.json", conns, manifest_entries)

        # 4. Caché DNS
        dns = _collect_dns_cache()
        if sanitize:
            dns = _sanitize_data(dns, current_user)
        _write_artifact(temp_path, "dns_cache.json", dns, manifest_entries)

        # 5. Hashes de ejecutables sospechosos
        hashes = _collect_suspicious_hashes(procs)
        if sanitize:
            hashes = _sanitize_data(hashes, current_user)
        _write_artifact(temp_path, "hashes_sospechosos.json", hashes, manifest_entries)

        # 6. Manifiesto final de integridad
        manifest_file = temp_path / "manifest.json"
        manifest_data = {
            "snapshot_id": f"CG-SNAP-{timestamp}",
            "fecha": datetime.now().isoformat(),
            "total_artefactos": len(manifest_entries),
            "artefactos": manifest_entries,
            "cifrado": bool(password),
            "anonimizado": sanitize
        }
        manifest_file.write_text(json.dumps(manifest_data, indent=2, ensure_ascii=False), encoding="utf-8")

        # Empaquetar todo en el archivo ZIP
        private_zip_path = temp_path / "snapshot.zip"
        with zipfile.ZipFile(private_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for item in temp_path.iterdir():
                if item.is_file() and item != private_zip_path:
                    zf.write(item, arcname=item.name)
        zip_bytes = private_zip_path.read_bytes()

    if password:
        final_path = target_dir / f"snapshot_{timestamp}.cgenc"
        _atomic_write(final_path, _encrypt_payload(zip_bytes, password))
        log(f"[Forensics] Snapshot volátil cifrado generado en: {final_path}")
        return str(final_path)

    _atomic_write(zip_path, zip_bytes)
    log(f"[Forensics] Snapshot volátil generado con éxito en: {zip_path}")
    return str(zip_path)


def _atomic_write(path: Path, data: bytes) -> None:
    """Escribe atómicamente con permisos restrictivos cuando el SO los soporta."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(path.name + f".{secrets.token_hex(6)}.tmp")
    try:
        with open(temp_path, "xb") as fh:
            try:
                os.chmod(temp_path, 0o600)
            except OSError:
                pass
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp_path, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        try:
            temp_path.unlink()
        except OSError:
            pass


def _sanitize_data(data: Any, username: str | None = None) -> Any:
    """Anonimiza nombres de usuario y redacta tokens en cadenas arbitrarias."""
    if username is None:
        username = os.environ.get("USERNAME") or os.environ.get("USER") or ""

    if isinstance(data, str):
        res = data
        if username and len(username) > 1:
            res = res.replace(username, "<REDACTED_USER>")
        # Redactar tokens y secretos comunes en líneas de comando
        res = re.sub(
            r"(token|secret|password|passwd|auth|bearer)[\s=:\"']+[A-Za-z0-9_\-\.]{8,}",
            r"\1=<REDACTED>",
            res,
            flags=re.I
        )
        res = re.sub(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "<REDACTED_EMAIL>", res, flags=re.I)
        return res
    elif isinstance(data, list):
        return [_sanitize_data(x, username) for x in data]
    elif isinstance(data, dict):
        cleaned = {}
        sensitive_keys = {"cookie", "cookie_value", "password", "passwd", "token", "secret", "authorization", "credential"}
        for key, value in data.items():
            if any(part in str(key).lower() for part in sensitive_keys):
                cleaned[key] = "<REDACTED>"
            else:
                cleaned[key] = _sanitize_data(value, username)
        return cleaned
    return data


def _encrypt_payload(plaintext: bytes, password: str) -> bytes:
    """Cifra usando AES-256-GCM de la dependencia opcional ``cryptography``.

    No implementa cifrado propio ni cae a un modo inseguro si la dependencia falta.
    Archivo: CG02 + salt aleatorio de 16 bytes + nonce GCM de 12 bytes + ciphertext/tag.
    """
    if not password or len(password) < 12:
        raise ValueError("Usa una contraseña de al menos 12 caracteres para cifrar el snapshot.")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise RuntimeError(
            "Para cifrar snapshots instala la dependencia opcional: "
            "python -m pip install -r requirements-forensics.txt"
        ) from exc

    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000, dklen=32)
    header = b"CG02" + salt + nonce
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, header)
    return header + ciphertext


def decrypt_snapshot(enc_file: str | Path, password: str, output_zip: str | Path | None = None) -> str:
    """Descifra un snapshot .cgenc y recupera el archivo ZIP original verificado."""
    enc_path = Path(enc_file)
    data = enc_path.read_bytes()
    if len(data) < 4 + 16 + 12 + 16:
        raise ValueError("Archivo cifrado demasiado corto o corrupto.")
    if data[:4] != b"CG02":
        raise ValueError("Formato de snapshot no reconocido o versión de cifrado antigua.")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise RuntimeError(
            "Para descifrar snapshots instala la dependencia opcional: "
            "python -m pip install -r requirements-forensics.txt"
        ) from exc

    salt, nonce = data[4:20], data[20:32]
    header, ciphertext = data[:32], data[32:]
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000, dklen=32)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, header)
    except Exception as exc:
        raise ValueError("Contraseña incorrecta o snapshot alterado (autenticación AES-GCM fallida).") from exc

    out_path = Path(output_zip) if output_zip is not None else enc_path.with_suffix(".zip")
    if out_path.exists():
        raise FileExistsError(f"El destino ya existe y no se sobrescribirá: {out_path}")
    _atomic_write(out_path, plaintext)
    log(f"[Forensics] Snapshot descifrado con éxito en {out_path}")
    return str(out_path)


def _write_artifact(base: Path, filename: str, data: Any, manifest: dict[str, str]) -> None:
    fpath = base / filename
    content = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
    fpath.write_bytes(content)
    sha256 = hashlib.sha256(content).hexdigest()
    manifest[filename] = sha256


def _collect_processes() -> list[dict[str, Any]]:
    """Recolecta los procesos en ejecución."""
    procs = []
    if IS_WIN:
        code, out, _ = ps("Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath,CreationDate | ConvertTo-Json -Compress", 60)
        try:
            d = json.loads(out) if out.strip() else []
            d = [d] if isinstance(d, dict) else d
            for item in d:
                procs.append({
                    "pid": item.get("ProcessId"),
                    "ppid": item.get("ParentProcessId"),
                    "name": item.get("Name") or "",
                    "cmd": item.get("CommandLine") or "",
                    "exe": item.get("ExecutablePath") or ""
                })
        except Exception:
            pass
    elif IS_LINUX:
        for p in Path("/proc").iterdir():
            if not p.name.isdigit():
                continue
            try:
                cmd = (p / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace").strip()
                comm = (p / "comm").read_text().strip()
                try:
                    exe = os.readlink(p / "exe")
                except OSError:
                    exe = ""
                procs.append({"pid": int(p.name), "name": comm, "cmd": cmd, "exe": exe})
            except (OSError, ValueError):
                continue
    return procs


def _collect_network_connections() -> list[dict[str, Any]]:
    """Recolecta conexiones activas TCP y UDP."""
    conns = []
    if IS_WIN:
        code, out, _ = run(["netstat", "-ano"], timeout=30)
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("TCP") or line.startswith("UDP"):
                parts = line.split()
                if len(parts) >= 4:
                    conns.append({
                        "protocolo": parts[0],
                        "local": parts[1],
                        "remoto": parts[2],
                        "estado": parts[3] if len(parts) > 4 else "N/A",
                        "pid": parts[-1]
                    })
    elif IS_LINUX:
        code, out, _ = run(["ss", "-tunap"], timeout=20)
        if code != 0:
            code, out, _ = run(["netstat", "-tunap"], timeout=20)
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("tcp") or line.startswith("udp"):
                parts = line.split()
                if len(parts) >= 5:
                    conns.append({
                        "protocolo": parts[0],
                        "local": parts[4] if len(parts) > 5 else parts[3],
                        "remoto": parts[5] if len(parts) > 5 else parts[4],
                        "estado": parts[1] if parts[0].startswith("tcp") else "N/A"
                    })
    return conns[:200]


def _collect_dns_cache() -> list[str]:
    """Obtiene entradas de la caché DNS."""
    dns_entries = []
    if IS_WIN:
        code, out, _ = run(["ipconfig", "/displaydns"], timeout=30)
        dns_entries = re.findall(r"(?:Record Name|Nombre de registro)[ .]*:\s*(\S+)", out, re.I)
    return sorted(set(dns_entries))


def _collect_suspicious_hashes(procs: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Calcula el hash SHA-256 de binarios situados en rutas no estándar."""
    hashes = []
    seen = set()
    for p in procs:
        exe = p.get("exe") or ""
        if not exe or exe in seen:
            continue
        seen.add(exe)
        low = exe.lower()
        if any(k in low for k in ("temp", "downloads", "/tmp", "/dev/shm", "public")):
            try:
                p_file = Path(exe)
                if p_file.is_file() and p_file.stat().st_size < 30_000_000:
                    sha = hashlib.sha256(p_file.read_bytes()).hexdigest()
                    hashes.append({
                        "pid": str(p.get("pid")),
                        "nombre": p.get("name", ""),
                        "ruta": exe,
                        "sha256": sha
                    })
            except Exception:
                continue
    return hashes
