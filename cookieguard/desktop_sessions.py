"""Auditor de sesiones y billeteras de aplicaciones de escritorio (Desktop Sessions Auditor).

Los infostealers modernos (Lumma, Stealc, RedLine, Vidar, Meduza) no solo roban cookies
de navegadores; su objetivo prioritario incluye sesiones de mensajería (Telegram, Discord)
y credenciales o claves de billeteras cripto de escritorio (MetaMask, Exodus, Electrum).

Este modulo audita la presencia, integridad y actividad sobre estas sesiones críticas.

POLITICA DE PRIVACIDAD ESTRICTA:
- Solo se analizan METADATOS: rutas de archivo, conteo de ficheros, marcas de tiempo y
  procesos que mantienen abiertos sus descriptores.
- NUNCA se leen, descifran ni exponen tokens de sesion, claves privadas ni datos de usuario.
- 100% local, sin conexion ni telemetria.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any

from .common import IS_LINUX, IS_WIN, log


def get_desktop_session_targets() -> list[dict[str, Any]]:
    """Define las ubicaciones estandar de almacenamiento de sesion de aplicaciones comunes."""
    home = Path.home()
    targets: list[dict[str, Any]] = []

    # 1. Telegram Desktop (tdata)
    if IS_WIN:
        appdata = os.environ.get("APPDATA") or str(home / "AppData" / "Roaming")
        tdata_path = Path(appdata) / "Telegram Desktop" / "tdata"
    else:
        tdata_path = home / ".local" / "share" / "TelegramDesktop" / "tdata"

    targets.append({
        "app": "Telegram Desktop",
        "categoria": "Mensajeria / Sesion C2",
        "tipo": "tdata",
        "ruta": tdata_path,
        "archivos_clave": ["key_datas", "D877F783D5D3EF8C*"],
        "proceso_legitimo": ["telegram.exe", "telegram", "Telegram"],
        "criticidad": "ALTA",
        "consejo": "Si sospechas robo de sesion en Telegram: Ajustes > Dispositivos > Cerrar todas las demas sesiones y activar Verificacion en Dos Pasos."
    })

    # 2. Discord Desktop (LevelDB Local Storage)
    discord_variants = [
        ("Discord", "discord"),
        ("Discord Canary", "discordcanary"),
        ("Discord PTB", "discordptb")
    ]
    for nombre, carpeta in discord_variants:
        if IS_WIN:
            appdata = os.environ.get("APPDATA") or str(home / "AppData" / "Roaming")
            p = Path(appdata) / carpeta / "Local Storage" / "leveldb"
        else:
            p = home / ".config" / carpeta / "Local Storage" / "leveldb"
        targets.append({
            "app": nombre,
            "categoria": "Mensajeria / Token Discord",
            "tipo": "leveldb_token",
            "ruta": p,
            "archivos_clave": ["*.ldb", "*.log"],
            "proceso_legitimo": [f"{carpeta}.exe", carpeta, f"{carpeta.lower()}"],
            "criticidad": "ALTA",
            "consejo": "Para invalidar tokens robados de Discord: Cambia inmediatamente la contrasena de tu cuenta de Discord y habilita 2FA."
        })

    # 3. Billeteras Cripto de Escritorio
    # Exodus
    if IS_WIN:
        exodus_path = Path(os.environ.get("APPDATA", "")) / "Exodus"
        electrum_path = Path(os.environ.get("APPDATA", "")) / "Electrum" / "wallets"
        atomic_path = Path(os.environ.get("APPDATA", "")) / "atomic" / "Local Storage" / "leveldb"
    else:
        exodus_path = home / ".config" / "Exodus"
        electrum_path = home / ".electrum" / "wallets"
        atomic_path = home / ".config" / "atomic" / "Local Storage" / "leveldb"

    targets.append({
        "app": "Exodus Wallet",
        "categoria": "Billetera Cripto",
        "tipo": "wallet_vault",
        "ruta": exodus_path,
        "archivos_clave": ["exodus.wallet"],
        "proceso_legitimo": ["exodus.exe", "exodus"],
        "criticidad": "CRITICA",
        "consejo": "Alerta maxima: Si un stealer toco tus billeteras, traslada fondos a una direccion limpia / hardware wallet inmediatamente."
    })
    targets.append({
        "app": "Electrum Bitcoin Wallet",
        "categoria": "Billetera Cripto",
        "tipo": "wallet_file",
        "ruta": electrum_path,
        "archivos_clave": ["default_wallet", "*"],
        "proceso_legitimo": ["electrum.exe", "electrum"],
        "criticidad": "CRITICA",
        "consejo": "Traslada tus fondos inmediatamente si detectas procesos ajenos leyendo la carpeta de Electrum."
    })
    targets.append({
        "app": "Atomic Wallet",
        "categoria": "Billetera Cripto",
        "tipo": "wallet_leveldb",
        "ruta": atomic_path,
        "archivos_clave": ["*.ldb"],
        "proceso_legitimo": ["atomic.exe", "atomic"],
        "criticidad": "CRITICA",
        "consejo": "Traslada inmediatamente tus fondos a una direccion generada en un entorno no comprometido."
    })

    # 4. Steam (Sesion de juegos / inventario)
    if IS_WIN:
        prog_x86 = os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")
        steam_path = Path(prog_x86) / "Steam" / "config"
    else:
        steam_path = home / ".steam" / "steam" / "config"

    targets.append({
        "app": "Steam Desktop",
        "categoria": "Plataforma de Videojuegos / Inventario",
        "tipo": "steam_config",
        "ruta": steam_path,
        "archivos_clave": ["loginusers.vdf"],
        "proceso_legitimo": ["steam.exe", "steam"],
        "criticidad": "MEDIA",
        "consejo": "Cierra sesiones en todos los dispositivos desde Ajustes de Steam > Administrar Steam Guard y cambia tu contrasena."
    })

    return targets


def audit_desktop_sessions() -> dict[str, Any]:
    """Audita metadatos de las sesiones de escritorio instaladas."""
    targets = get_desktop_session_targets()
    hallazgos: list[dict[str, Any]] = []
    instaladas: list[str] = []
    resumen_criticidad = {"CRITICA": 0, "ALTA": 0, "MEDIA": 0, "BAJA": 0}

    now = time.time()

    for t in targets:
        p: Path = t["ruta"]
        if not p.exists():
            continue

        instaladas.append(t["app"])

        # Metadatos del directorio / archivos sin abrir contenido sensible
        num_archivos = 0
        ultimo_mtime = 0.0
        tam_total = 0

        try:
            if p.is_dir():
                for root, _, files in os.walk(p):
                    for f in files:
                        num_archivos += 1
                        try:
                            fp = Path(root) / f
                            st = fp.stat()
                            tam_total += st.st_size
                            if st.st_mtime > ultimo_mtime:
                                ultimo_mtime = st.st_mtime
                        except Exception:
                            continue
            else:
                st = p.stat()
                num_archivos = 1
                ultimo_mtime = st.st_mtime
                tam_total = st.st_size
        except Exception:
            continue

        horas_desde_modificacion = (now - ultimo_mtime) / 3600.0 if ultimo_mtime > 0 else 99999.0

        hallazgos.append({
            "app": t["app"],
            "categoria": t["categoria"],
            "tipo": t["tipo"],
            "ruta": str(p),
            "presente": True,
            "num_archivos": num_archivos,
            "tamano_bytes": tam_total,
            "horas_ultima_modificacion": round(horas_desde_modificacion, 1),
            "criticidad": t["criticidad"],
            "procesos_legitimos": t["proceso_legitimo"],
            "consejo": t["consejo"]
        })
        resumen_criticidad[t["criticidad"]] += 1

    return {
        "apps_detectadas": len(instaladas),
        "apps_lista": instaladas,
        "sesiones": hallazgos,
        "resumen_criticidad": resumen_criticidad
    }
