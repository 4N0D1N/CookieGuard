"""Deteccion de navegadores y perfiles (Windows y Linux)."""
from __future__ import annotations

import configparser
import glob
import os
from dataclasses import dataclass
from pathlib import Path

from .common import IS_WIN


@dataclass
class Profile:
    browser: str
    family: str          # 'chromium' | 'firefox'
    profile: str
    path: Path           # carpeta del perfil
    cookies_db: Path | None
    root: Path           # carpeta raiz (User Data / carpeta Firefox)


def _chromium_roots() -> list[tuple[str, Path]]:
    home = Path.home()
    out: list[tuple[str, Path]] = []
    if IS_WIN:
        la = Path(os.environ.get("LOCALAPPDATA", home / "AppData/Local"))
        ra = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
        rel = {
            "Chrome": "Google/Chrome/User Data", "Chrome Beta": "Google/Chrome Beta/User Data",
            "Chrome Canary": "Google/Chrome SxS/User Data", "Edge": "Microsoft/Edge/User Data",
            "Brave": "BraveSoftware/Brave-Browser/User Data", "Vivaldi": "Vivaldi/User Data",
            "Chromium": "Chromium/User Data", "Yandex": "Yandex/YandexBrowser/User Data",
        }
        for n, r in rel.items():
            out.append((n, la / r))
        out.append(("Opera", ra / "Opera Software/Opera Stable"))
        out.append(("Opera GX", ra / "Opera Software/Opera GX Stable"))
        for p in glob.glob(str(la / "Packages/TheBrowserCompany.Arc_*/LocalCache/Local/Arc/User Data")):
            out.append(("Arc", Path(p)))
        for p in glob.glob(str(la / "*" / "User Data")) + glob.glob(str(la / "*" / "*" / "User Data")):
            out.append((f"Chromium ({Path(p).parent.name})", Path(p)))
    else:
        cfg = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
        rel = {
            "Chrome": "google-chrome", "Chrome Beta": "google-chrome-beta", "Chromium": "chromium",
            "Edge": "microsoft-edge", "Brave": "BraveSoftware/Brave-Browser", "Vivaldi": "vivaldi",
            "Opera": "opera", "Yandex": "yandex-browser",
        }
        for n, r in rel.items():
            out.append((n, cfg / r))
        out.append(("Chromium (snap)", home / "snap/chromium/common/chromium"))
        flat = {"com.google.Chrome": "google-chrome", "org.chromium.Chromium": "chromium",
                "com.brave.Browser": "BraveSoftware/Brave-Browser", "com.microsoft.Edge": "microsoft-edge"}
        for app, r in flat.items():
            out.append((f"{app.split('.')[-1]} (flatpak)", home / ".var/app" / app / "config" / r))
        for p in glob.glob(str(cfg / "*" / "Local State")):
            out.append((f"Chromium ({Path(p).parent.name})", Path(p).parent))
    return out


def _firefox_roots() -> list[tuple[str, Path]]:
    home = Path.home()
    if IS_WIN:
        ra = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
        return [("Firefox", ra / "Mozilla/Firefox"), ("LibreWolf", ra / "LibreWolf"), ("Waterfox", ra / "Waterfox")]
    return [("Firefox", home / ".mozilla/firefox"), ("Firefox (snap)", home / "snap/firefox/common/.mozilla/firefox"),
            ("Firefox (flatpak)", home / ".var/app/org.mozilla.firefox/.mozilla/firefox"),
            ("LibreWolf", home / ".librewolf"), ("Waterfox", home / ".waterfox")]


def _chromium_profiles(name: str, root: Path) -> list[Profile]:
    res: list[Profile] = []
    if not root.is_dir():
        return res
    cands = []
    for rel in ("Network/Cookies", "Cookies"):
        if (root / rel).is_file():  # estilo Opera: el perfil es la propia raiz
            cands.append((root, root / rel, "(raiz)"))
            break
    try:
        for d in sorted(root.iterdir()):
            if not d.is_dir():
                continue
            for rel in ("Network/Cookies", "Cookies"):
                if (d / rel).is_file():
                    cands.append((d, d / rel, d.name))
                    break
    except OSError:
        pass
    for pdir, db, pname in cands:
        res.append(Profile(name, "chromium", pname, pdir, db, root))
    return res


def _firefox_profiles(name: str, root: Path) -> list[Profile]:
    res: list[Profile] = []
    ini = root / "profiles.ini"
    seen = set()
    if ini.is_file():
        cp = configparser.RawConfigParser()
        try:
            cp.read(ini, encoding="utf-8")
        except Exception:
            pass
        for sec in cp.sections():
            if not sec.lower().startswith("profile"):
                continue
            p = cp.get(sec, "Path", fallback="")
            if not p:
                continue
            rel = cp.get(sec, "IsRelative", fallback="1") == "1"
            d = (root / p) if rel else Path(p)
            seen.add(str(d))
            db = d / "cookies.sqlite"
            res.append(Profile(name, "firefox", cp.get(sec, "Name", fallback=d.name), d,
                               db if db.is_file() else None, root))
    for base in (root, root / "Profiles"):
        if base.is_dir():
            for d in base.iterdir():
                if d.is_dir() and (d / "cookies.sqlite").is_file() and str(d) not in seen:
                    res.append(Profile(name, "firefox", d.name, d, d / "cookies.sqlite", root))
    return res


def discover(extra_chromium: list[Path] | None = None, extra_firefox: list[Path] | None = None,
             only_extra: bool = False) -> list[Profile]:
    """Devuelve todos los perfiles con base de cookies. extra_* y only_extra sirven para pruebas."""
    roots_c = [] if only_extra else _chromium_roots()
    roots_f = [] if only_extra else _firefox_roots()
    for p in extra_chromium or []:
        roots_c.append((f"Chromium ({Path(p).name})", Path(p)))
    for p in extra_firefox or []:
        roots_f.append(("Firefox (prueba)", Path(p)))
    profiles: list[Profile] = []
    seen_roots = set()
    for name, root in roots_c:
        key = str(root).lower()
        if key in seen_roots:
            continue
        seen_roots.add(key)
        profiles += _chromium_profiles(name, root)
    for name, root in roots_f:
        key = str(root).lower()
        if key in seen_roots:
            continue
        seen_roots.add(key)
        profiles += _firefox_profiles(name, root)
    uniq, dbs = [], set()
    for p in profiles:
        k = str(p.cookies_db).lower()
        if p.cookies_db and k in dbs:
            continue
        dbs.add(k)
        uniq.append(p)
    return [p for p in uniq if p.cookies_db]


def sensitive_files(profiles: list[Profile]) -> list[Path]:
    """Ficheros sensibles de cada perfil (para auditoria/SACL y vigilancia)."""
    names_c = ["Network/Cookies", "Cookies", "Login Data", "Web Data"]
    names_f = ["cookies.sqlite", "logins.json", "key4.db"]
    out: list[Path] = []
    seen = set()
    for p in profiles:
        if p.family == "chromium":
            cands = [p.path / n for n in names_c] + [p.root / "Local State"]
        else:
            cands = [p.path / n for n in names_f]
        for c in cands:
            if c.is_file() and str(c) not in seen:
                seen.add(str(c))
                out.append(c)
    return out
