"""Actualizador y motor de Threat Intelligence (IoCs) para CookieGuard.

Permite que CookieGuard actualice de forma automatica y autonoma su base de datos
de Indicadores de Compromiso (C2 domains, C2 IPs, hashes SHA-256 de stealers, y
patrones de ejecutables) sin dependencias externas.

Garantias de privacidad y arquitectura CookieGuard:
1. Privacidad absoluta: Peticion HTTP GET estandar y anonima sin telemetria ni cookies.
2. Cero modulos de red en Python: Usa curl en Linux o Invoke-RestMethod en Windows (politica estricta).
3. Modo offline-first: Si no hay conexion o falla el feed, se usa el catalogo semilla local sin errores.
4. Actualizacion en segundo plano: Hilo daemon no bloqueante con control de frecuencia (TTL 24h).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .common import APP_ROOT, IS_WIN, data_dir, load_config, log, ps, run

DEFAULT_FEED_URL = "https://raw.githubusercontent.com/4N0D1N/CookieGuard/main/catalogo/iocs.json"
CACHE_FILE = "iocs_cache.json"
_LOCK = threading.Lock()
_IOCS_MEM_CACHE: dict[str, Any] | None = None
_IOCS_MEM_TIME: float = 0.0


def _load_seed_iocs() -> dict[str, Any]:
    """Carga el catalogo semilla de IoCs incluido en la instalacion."""
    seed_path = APP_ROOT / "catalogo" / "iocs.json"
    if seed_path.exists():
        try:
            return json.loads(seed_path.read_text(encoding="utf-8-sig"))
        except Exception as e:
            log(f"Error cargando catalogo semilla de IoCs: {e}")
    return {
        "_version": "seed-fallback",
        "c2_dominios": [],
        "c2_ips": [],
        "stealer_hashes_sha256": [],
        "stealer_nombres_ejecutables": [],
        "patrones_argumentos": [],
    }


def _load_cached_iocs() -> dict[str, Any] | None:
    """Carga los IoCs descargados previamente en la carpeta de datos del usuario."""
    cache_path = data_dir() / CACHE_FILE
    if cache_path.exists():
        try:
            return json.loads(cache_path.read_text(encoding="utf-8"))
        except Exception as e:
            log(f"Cache de IoCs corrupta o invalida: {e}")
    return None


def get_active_iocs() -> dict[str, Any]:
    """Obtiene la base de datos activa de IoCs combinando semilla y cache actualizada."""
    global _IOCS_MEM_CACHE, _IOCS_MEM_TIME
    now = time.time()
    with _LOCK:
        if _IOCS_MEM_CACHE is not None and (now - _IOCS_MEM_TIME < 300):
            return _IOCS_MEM_CACHE

    seed = _load_seed_iocs()
    cached = _load_cached_iocs()

    if not cached:
        merged = seed
    else:
        # Fusionar manteniendo versiones y sumando nuevos indicadores unicos
        merged = dict(seed)
        merged["_version"] = cached.get("_version", seed.get("_version", "1.0"))
        merged["actualizado"] = cached.get("actualizado", seed.get("actualizado", ""))
        merged["fuente"] = cached.get("fuente", "Cache local actualizada")

        # Fusionar dominios
        dom_seen = {d.get("dominio") for d in seed.get("c2_dominios", []) if isinstance(d, dict)}
        dom_list = list(seed.get("c2_dominios", []))
        for d in cached.get("c2_dominios", []):
            if isinstance(d, dict) and d.get("dominio") and d.get("dominio") not in dom_seen:
                dom_seen.add(d.get("dominio"))
                dom_list.append(d)
        merged["c2_dominios"] = dom_list

        # Fusionar IPs
        ip_seen = {i.get("ip") for i in seed.get("c2_ips", []) if isinstance(i, dict)}
        ip_list = list(seed.get("c2_ips", []))
        for i in cached.get("c2_ips", []):
            if isinstance(i, dict) and i.get("ip") and i.get("ip") not in ip_seen:
                ip_seen.add(i.get("ip"))
                ip_list.append(i)
        merged["c2_ips"] = ip_list

        # Fusionar hashes
        hash_seen = {h.get("sha256", "").lower() for h in seed.get("stealer_hashes_sha256", []) if isinstance(h, dict)}
        hash_list = list(seed.get("stealer_hashes_sha256", []))
        for h in cached.get("stealer_hashes_sha256", []):
            if isinstance(h, dict) and h.get("sha256"):
                h_val = h["sha256"].lower()
                if h_val not in hash_seen:
                    hash_seen.add(h_val)
                    hash_list.append(h)
        merged["stealer_hashes_sha256"] = hash_list

        # Fusionar nombres ejecutables
        nombres = set(seed.get("stealer_nombres_ejecutables", []))
        nombres.update(cached.get("stealer_nombres_ejecutables", []))
        merged["stealer_nombres_ejecutables"] = sorted(nombres)

        # Fusionar patrones argumentos
        patrones = set(seed.get("patrones_argumentos", []))
        patrones.update(cached.get("patrones_argumentos", []))
        merged["patrones_argumentos"] = sorted(patrones)

    # Preparar sets indexados para consultas rapidas
    merged["_hash_set"] = {h.get("sha256", "").lower(): h for h in merged.get("stealer_hashes_sha256", []) if isinstance(h, dict)}
    merged["_exe_set"] = {e.lower() for e in merged.get("stealer_nombres_ejecutables", [])}

    with _LOCK:
        _IOCS_MEM_CACHE = merged
        _IOCS_MEM_TIME = now

    return merged


def _download_feed_content(url: str, timeout: int = 15) -> tuple[int, str, str]:
    """Descarga el contenido sin importar modulos de red de Python (utiliza curl o PowerShell)."""
    if IS_WIN:
        script = f"$ProgressPreference='SilentlyContinue'; (Invoke-WebRequest -Uri '{url}' -UseBasicParsing -TimeoutSec {timeout}).Content"
        return ps(script, timeout=timeout + 5)
    else:
        if not shutil.which("curl"):
            return -1, "", "curl no encontrado en el sistema"
        cmd = ["curl", "-s", "-m", str(timeout), "-A", "CookieGuard-Feed/1.4", url]
        return run(cmd, timeout=timeout + 2)


def update_iocs(feed_url: str | None = None, force: bool = False, timeout: int = 15) -> dict[str, Any]:
    """Descarga el feed de IoCs y actualiza la cache local si es valida."""
    cfg = load_config()
    url = feed_url or cfg.get("iocs_feed_url") or DEFAULT_FEED_URL

    cache_path = data_dir() / CACHE_FILE
    ttl_hours = float(cfg.get("iocs_ttl_horas", 24))

    # Comprobar si ya esta actualizado recientemente salvo force=True
    if not force and cache_path.exists():
        try:
            mtime = cache_path.stat().st_mtime
            age_hours = (time.time() - mtime) / 3600.0
            if age_hours < ttl_hours:
                active = get_active_iocs()
                return {
                    "success": True,
                    "actualizado": False,
                    "mensaje": f"IoCs al dia (ultima actualizacion hace {age_hours:.1f}h, TTL {ttl_hours}h)",
                    "total_hashes": len(active.get("stealer_hashes_sha256", [])),
                    "total_dominios": len(active.get("c2_dominios", [])),
                    "total_ips": len(active.get("c2_ips", [])),
                    "version": active.get("_version", "local"),
                }
        except Exception:
            pass

    log(f"Iniciando actualizacion de IoCs desde {url}...")
    code, stdout, stderr = _download_feed_content(url, timeout=timeout)

    try:
        if code != 0 or not stdout.strip():
            raise ValueError(f"Fallo al descargar feed ({stderr.strip() or 'sin respuesta'})")

        parsed = json.loads(stdout.strip())

        # Validar integridad mínima del feed para evitar corrupcion
        if not isinstance(parsed, dict):
            raise ValueError("El feed descargado no tiene formato JSON de diccionario.")

        required_keys = ["c2_dominios", "stealer_hashes_sha256"]
        if not any(k in parsed for k in required_keys):
            raise ValueError("El feed carece de las secciones esenciales de IoCs.")

        # Guardar de forma atomica
        parsed["_descargado_en"] = datetime.now(timezone.utc).isoformat()
        parsed["_fuente_remota"] = url

        tmp_file = cache_path.with_suffix(".tmp")
        tmp_file.write_text(json.dumps(parsed, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp_file.replace(cache_path)

        # Invalidar cache en memoria
        global _IOCS_MEM_CACHE
        with _LOCK:
            _IOCS_MEM_CACHE = None

        active = get_active_iocs()
        msg = f"IoCs actualizados con exito ({len(active.get('stealer_hashes_sha256', []))} hashes, {len(active.get('c2_dominios', []))} dominios)."
        log(msg)
        return {
            "success": True,
            "actualizado": True,
            "mensaje": msg,
            "total_hashes": len(active.get("stealer_hashes_sha256", [])),
            "total_dominios": len(active.get("c2_dominios", [])),
            "total_ips": len(active.get("c2_ips", [])),
            "version": parsed.get("_version", "remota"),
        }
    except Exception as e:
        err_msg = f"No se pudo descargar el feed de IoCs ({e}). Continuando con base local."
        log(err_msg)
        active = get_active_iocs()
        return {
            "success": False,
            "actualizado": False,
            "mensaje": err_msg,
            "total_hashes": len(active.get("stealer_hashes_sha256", [])),
            "total_dominios": len(active.get("c2_dominios", [])),
            "total_ips": len(active.get("c2_ips", [])),
            "version": active.get("_version", "local"),
            "error": str(e)
        }


def should_auto_update(cfg: dict[str, Any] | None = None) -> bool:
    """Evalua si debe ejecutarse una actualizacion automatica de IoCs."""
    if cfg is None:
        cfg = load_config()
    if not cfg.get("iocs_auto_actualizar", True):
        return False
    cache_path = data_dir() / CACHE_FILE
    if not cache_path.exists():
        return True
    ttl_hours = float(cfg.get("iocs_ttl_horas", 24))
    age_hours = (time.time() - cache_path.stat().st_mtime) / 3600.0
    return age_hours >= ttl_hours


def auto_update_in_background(cfg: dict[str, Any] | None = None) -> None:
    """Lanza la actualizacion en un hilo secundario sin bloquear el proceso principal."""
    if not should_auto_update(cfg):
        return

    def _worker():
        try:
            update_iocs(force=False, timeout=12)
        except Exception:
            pass

    t = threading.Thread(target=_worker, name="CookieGuard-IoCUpdater", daemon=True)
    t.start()


def match_process_against_iocs(
    nombre: str = "",
    ruta: str = "",
    sha256: str = "",
    cmdline: str = "",
    iocs: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Compara un proceso contra la base de datos de IoCs activa."""
    if iocs is None:
        iocs = get_active_iocs()

    coincidencias: list[dict[str, Any]] = []

    # 1. Comprobacion de Hash SHA-256
    if sha256:
        sha_norm = sha256.lower().strip()
        hash_dict = iocs.get("_hash_set", {})
        if sha_norm in hash_dict:
            hit = hash_dict[sha_norm]
            coincidencias.append({
                "tipo": "sha256_stealer",
                "valor": sha_norm,
                "familia": hit.get("familia", "Infostealer conocido"),
                "severidad": "CRITICA",
                "peso": hit.get("peso", 10),
                "detalle": f"El hash SHA-256 coincide exactamente con la muestra maliciosa '{hit.get('familia')}'"
            })

    # 2. Comprobacion de Nombre de Ejecutable
    if nombre:
        exe_norm = Path(nombre).name.lower()
        if exe_norm in iocs.get("_exe_set", set()):
            coincidencias.append({
                "tipo": "nombre_stealer",
                "valor": exe_norm,
                "familia": "Binario con nombre caracteristico de stealer/dropper",
                "severidad": "ALTA",
                "peso": 8,
                "detalle": f"El ejecutable '{exe_norm}' coincide con nombres utilizados comunmente por infostealers"
            })

    # 3. Comprobacion de Patrones en Linea de Comandos
    if cmdline:
        for patron in iocs.get("patrones_argumentos", []):
            try:
                if re.search(patron, cmdline, re.IGNORECASE):
                    coincidencias.append({
                        "tipo": "patron_cmdline_ioc",
                        "valor": cmdline[:100] + ("..." if len(cmdline) > 100 else ""),
                        "familia": "Comando malicioso / Stager en linea de comandos",
                        "severidad": "CRITICA",
                        "peso": 9,
                        "detalle": f"Coincide con patron de ejecucion de stealer: {patron}"
                    })
                    break
            except re.error:
                continue

    return coincidencias


def match_network_against_iocs(
    ip: str = "",
    dominio: str = "",
    iocs: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Compara una direccion IP o dominio de red contra los IoCs de C2 conocidos."""
    if iocs is None:
        iocs = get_active_iocs()

    coincidencias: list[dict[str, Any]] = []

    if dominio:
        dom_norm = dominio.lower().strip()
        for c2 in iocs.get("c2_dominios", []):
            patron = c2.get("dominio", "").lower()
            if patron and (dom_norm == patron or dom_norm.endswith("." + patron) or patron in dom_norm):
                coincidencias.append({
                    "tipo": "c2_dominio",
                    "valor": dom_norm,
                    "familia": c2.get("familia", "Canal de exfiltracion C2"),
                    "severidad": "CRITICA" if c2.get("peso", 5) >= 8 else "ALTA",
                    "peso": c2.get("peso", 7),
                    "detalle": f"Dominio de destino '{dom_norm}' catalogado como {c2.get('tipo', 'C2')}"
                })
                break

    if ip:
        ip_norm = ip.strip()
        for c2_ip in iocs.get("c2_ips", []):
            patron_ip = c2_ip.get("ip", "")
            if "/" in patron_ip:
                prefijo = patron_ip.split("/")[0].rsplit(".", 1)[0]
                if ip_norm.startswith(prefijo):
                    coincidencias.append({
                        "tipo": "c2_ip_subnet",
                        "valor": ip_norm,
                        "familia": c2_ip.get("familia", "Subred C2 conocida"),
                        "severidad": "CRITICA",
                        "peso": c2_ip.get("peso", 9),
                        "detalle": f"IP de destino '{ip_norm}' en subred catalogada de C2 ({patron_ip})"
                    })
                    break
            elif ip_norm == patron_ip:
                coincidencias.append({
                    "tipo": "c2_ip",
                    "valor": ip_norm,
                    "familia": c2_ip.get("familia", "Nodo C2 de infostealer"),
                    "severidad": "CRITICA",
                    "peso": c2_ip.get("peso", 9),
                    "detalle": f"IP de destino '{ip_norm}' coincide con servidor C2 conocido"
                })
                break

    return coincidencias
