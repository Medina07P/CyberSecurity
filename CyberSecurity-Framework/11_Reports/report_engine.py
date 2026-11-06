#!/usr/bin/env python3
"""CLI del motor de informes.
Uso: python3 report_engine.py --objetivo <objetivo> --tipo <tipo>
Ejemplo: python3 report_engine.py --objetivo 127.0.0.1 --tipo ambos --cliente ACME --auditor Ana

Genera informes técnico y/o cliente a partir de los resultados de escaneo
en <repo>/scans/, o re-renderiza desde un findings.json con --desde-json.
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Resolución de rutas del framework: este script vive en 11_Reports/
_THIS_DIR = Path(__file__).resolve().parent
_FRAMEWORK_ROOT = _THIS_DIR.parent          # CyberSecurity-Framework/
_REPO_ROOT = _FRAMEWORK_ROOT.parent         # repo root

# Imports relativos al paquete lib que vive junto a este script
sys.path.insert(0, str(_THIS_DIR))
from lib.engine import collect
from lib.render import write_reports, to_json, from_json
from lib.attribution import slug as target_slug

__all__ = ["build_parser", "read_profile", "write_profile", "run", "main"]


def read_profile(path: Path) -> dict[str, str]:
    """Lee un perfil en formato ``clave=valor`` por línea.

    Las líneas vacías o que empiezan por ``#`` se ignoran. Si el fichero no
    existe devuelve un diccionario vacío.
    """
    data: dict[str, str] = {}
    path = Path(path)
    if not path.exists():
        return data
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        data[key.strip()] = value.strip()
    return data


def write_profile(path: Path, data: dict[str, str]) -> None:
    """Escribe un perfil en formato ``clave=valor`` por línea."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"{k}={v}" for k, v in data.items()]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _default_scans_dir() -> Path:
    env = os.environ.get("REPORT_SCANS_DIR")
    if env:
        return Path(env)
    return _REPO_ROOT / "scans"


def _default_out_dir(objetivo: str | None) -> Path:
    env = os.environ.get("REPORT_OUT_DIR")
    if env:
        return Path(env)
    s = target_slug(objetivo) if objetivo else "sin_objetivo"
    return _FRAMEWORK_ROOT / "11_Reports" / "generated" / s


def _default_profile_path() -> Path:
    env = os.environ.get("REPORT_PROFILE")
    if env:
        return Path(env)
    return _FRAMEWORK_ROOT / "11_Reports" / ".report_profile"


def _session_target() -> str | None:
    """Primera línea de ``00_Config/.session`` si existe y no está vacía."""
    session_file = _FRAMEWORK_ROOT / "00_Config" / ".session"
    if not session_file.exists():
        return None
    try:
        text = session_file.read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return None


def build_parser() -> argparse.ArgumentParser:
    """Construye el ``ArgumentParser`` de la CLI."""
    p = argparse.ArgumentParser(
        prog="report_engine.py",
        description="Motor de informes: genera informes técnico y cliente.",
    )
    p.add_argument("--objetivo", default=None, help="Objetivo del informe")
    p.add_argument("--tipo", choices=["tecnico", "cliente", "ambos"], default="ambos",
                   help="Tipo de informe a generar (por defecto: ambos)")
    p.add_argument("--scans", default=None, help="Directorio de resultados de escaneo")
    p.add_argument("--salida", default=None, help="Directorio de salida")
    p.add_argument("--cliente", default=None, help="Nombre del cliente")
    p.add_argument("--auditor", default=None, help="Nombre del auditor")
    p.add_argument("--todos", action="store_true", help="Incluir hallazgos de todos los objetivos")
    p.add_argument("--incluir-sin-objetivo", action="store_true",
                   help="Incluir hallazgos sin objetivo atribuible")
    p.add_argument("--desde-json", default=None,
                   help="Ruta a findings.json para re-renderizar sin escanear")
    p.add_argument("--json", action="store_true",
                   help="Imprimir resumen JSON en la última línea de stdout")
    p.add_argument("--abrir", action="store_true",
                   help="Abrir el informe HTML con xdg-open al terminar")
    return p


def _tipos_from_arg(tipo: str) -> list[str]:
    if tipo == "ambos":
        return ["tecnico", "cliente"]
    return [tipo]


def _write_json(data: dict, out_dir: Path) -> Path:
    """Escribe findings.json usando la clave ``hallazgos`` (español)."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    # Renombrar "findings" -> "hallazgos" para el fichero en disco
    disk_data = dict(data)
    if "findings" in disk_data:
        disk_data["hallazgos"] = disk_data.pop("findings")
    path = out_dir / "findings.json"
    path.write_text(json.dumps(disk_data, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def _load_json(path: Path) -> dict:
    """Carga findings.json y normaliza ``hallazgos`` -> ``findings``."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if "hallazgos" in data and "findings" not in data:
        data["findings"] = data.pop("hallazgos")
    return data


def _summary(objetivo: str | None, collected, out_dir: Path) -> dict:
    confirmados = [f for f in collected.findings if f.confianza == "confirmado"]
    criticos = len([f for f in confirmados if f.severidad == "critica"])
    return {
        "objetivo": objetivo or "",
        "hallazgos": len(collected.findings),
        "criticos": criticos,
        "no_evaluable": len(collected.no_evaluable),
        "salida": str(out_dir),
    }


def run(argv: list[str] | None = None) -> int:
    """Punto de entrada de la CLI. Devuelve el código de salida."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse llama a sys.exit: --help => 0, errores => 2
        code = exc.code if isinstance(exc.code, int) else 1
        if code == 0:
            return 0
        return 1

    # --- Cargar perfil y resolver valores por defecto ---
    profile_path = _default_profile_path()
    profile = read_profile(profile_path)

    # Objetivo: flag > session > None
    objetivo = args.objetivo
    if objetivo is None:
        objetivo = _session_target()
    todos = args.todos
    if objetivo is None and not todos:
        print("Aviso: no se indicó --objetivo ni hay sesión activa; se usan todos los hallazgos.",
              file=sys.stderr)
        todos = True

    # Cliente/auditor: flag > perfil > valor por defecto
    cliente = args.cliente
    if cliente is None:
        cliente = profile.get("cliente", "No indicado")
    auditor = args.auditor
    if auditor is None:
        auditor = profile.get("auditor", os.environ.get("USER", "quien"))

    # Scans y salida
    scans_dir = Path(args.scans) if args.scans else _default_scans_dir()
    out_dir = Path(args.salida) if args.salida else _default_out_dir(objetivo)
    out_dir.mkdir(parents=True, exist_ok=True)

    tipos = _tipos_from_arg(args.tipo)

    # --- Modo --desde-json: no tocar scans ---
    if args.desde_json:
        try:
            data = _load_json(Path(args.desde_json))
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            print(f"Error al cargar {args.desde_json}: {exc}", file=sys.stderr)
            return 1

        # Aplicar overrides de cliente/auditor desde la CLI
        meta = dict(data.get("meta", {}))
        if args.cliente is not None:
            meta["cliente"] = args.cliente
        if args.auditor is not None:
            meta["auditor"] = args.auditor
        data["meta"] = meta

        try:
            collected, _ = from_json(data)
        except Exception as exc:
            print(f"Error al reconstruir hallazgos: {exc}", file=sys.stderr)
            return 1

        try:
            write_reports(collected, meta, out_dir, tipos)
            _write_json(data, out_dir)
        except OSError as exc:
            print(f"Error al escribir informes: {exc}", file=sys.stderr)
            return 1

        if args.json:
            print(json.dumps(_summary(objetivo, collected, out_dir), ensure_ascii=False))

        if args.abrir:
            html = out_dir / ("informe_tecnico.html" if "tecnico" in tipos else "informe_cliente.html")
            try:
                subprocess.run(["xdg-open", str(html)], check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except OSError:
                pass

        return 0

    # --- Modo normal: collect desde scans ---
    try:
        collected = collect(
            Path(scans_dir),
            _REPO_ROOT,
            objetivo,
            incluir_sin_objetivo=args.incluir_sin_objetivo,
            todos=todos,
        )
    except OSError as exc:
        print(f"Error al leer scans: {exc}", file=sys.stderr)
        return 1

    if not collected.evaluado:
        print("No se evaluó ningún parser con éxito; no hay material para informar.",
              file=sys.stderr)
        return 3

    meta = {
        "cliente": cliente,
        "auditor": auditor,
        "fecha": datetime.now().strftime("%Y-%m-%d"),
        "objetivo": objetivo or "No especificado",
        "herramientas": sorted({
            f.tecnica for f in collected.findings if f.tecnica
        }),
    }

    try:
        write_reports(collected, meta, out_dir, tipos)
        data = to_json(collected, meta)
        _write_json(data, out_dir)
    except OSError as exc:
        print(f"Error al escribir informes: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(_summary(objetivo, collected, out_dir), ensure_ascii=False))

    if args.abrir:
        html = out_dir / ("informe_tecnico.html" if "tecnico" in tipos else "informe_cliente.html")
        try:
            subprocess.run(["xdg-open", str(html)], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            pass

    return 0


def main() -> None:
    """Punto de entrada como script: ``sys.exit(run())``."""
    sys.exit(run())


if __name__ == "__main__":
    main()
