"""Empaqueta CookieGuard.zip listo para copiar a otro equipo (Windows o Linux)."""
import argparse
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT.parent / "CookieGuard.zip"
SKIP_DIRS = {"__pycache__", ".git", "tmp", ".pytest_cache"}
EXEC = {"cookieguard.sh", "rescate-usb.sh"}


def main():
    parser = argparse.ArgumentParser(description="Empaquetador de CookieGuard")
    parser.add_argument("-o", "--output", help="Ruta del archivo ZIP de salida", default=None)
    args = parser.parse_args()

    out = Path(args.output).resolve() if args.output else DEFAULT_OUT
    out.parent.mkdir(parents=True, exist_ok=True)

    n = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(ROOT.rglob("*")):
            rel = p.relative_to(ROOT)
            if p.is_dir() or SKIP_DIRS & set(rel.parts) or p.suffix in (".pyc", ".zip"):
                continue
            zi = zipfile.ZipInfo(str(Path("CookieGuard") / rel).replace("\\", "/"), date_time=(2026, 11, 21, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = ((0o755 if p.name in EXEC else 0o644) << 16)
            data = p.read_bytes()
            if p.suffix in (".cmd", ".sh") or p.name.endswith(".md"):
                data = data.replace(b"\r\n", b"\n")
                if p.suffix == ".cmd":
                    data = data.replace(b"\n", b"\r\n")
            z.writestr(zi, data)
            n += 1
    print(f"{out} ({n} ficheros, {out.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
