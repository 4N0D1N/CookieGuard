"""Comprueba que las URLs del catalogo responden (herramienta de mantenimiento; hace peticiones de red).
Uso: python tools/verificar_urls.py [--solo-fallos]
Una URL se considera valida si responde 2xx/3xx, o 401/403/405/429 (pagina real que pide sesion o bloquea bots)."""
import json
import ssl
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UA = {"User-Agent": "Mozilla/5.0 (compatible; verificacion-enlaces)"}


def check(item):
    sid, kind, url = item
    for method in ("HEAD", "GET"):
        try:
            req = urllib.request.Request(url, method=method, headers=UA)
            with urllib.request.urlopen(req, timeout=15, context=ssl.create_default_context()) as r:
                return sid, kind, url, r.status, r.geturl()
        except urllib.error.HTTPError as e:
            if e.code in (401, 403, 405, 429) and method == "GET":
                return sid, kind, url, e.code, url
            if method == "GET" or e.code not in (400, 403, 404, 405, 501):
                return sid, kind, url, e.code, url
        except Exception as e:  # noqa: BLE001
            if method == "GET":
                return sid, kind, url, f"ERR {type(e).__name__}", url
    return sid, kind, url, "?", url


def main():
    cat = json.loads((ROOT / "catalogo" / "servicios.json").read_text(encoding="utf-8"))
    items = sorted({(s["id"], k, u) for s in cat["servicios"] for k, u in s["urls"].items()})
    only_fail = "--solo-fallos" in sys.argv
    bad = 0
    with ThreadPoolExecutor(max_workers=10) as ex:
        for sid, kind, url, st, final in ex.map(check, items):
            ok = isinstance(st, int) and (st < 400 or st in (401, 403, 405, 429))
            bad += 0 if ok else 1
            if not (ok and only_fail):
                print(f"{'OK ' if ok else 'MAL'} {st!s:>14} {sid}/{kind}: {url}" + ("" if final == url else f"  -> {final}"))
    print(f"\n{len(items)} URLs, {bad} con problemas")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
