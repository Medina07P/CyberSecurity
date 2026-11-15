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
from datetime import datetime, timezone
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
from lib import validation
from lib.publication import preflight, write_private
from lib import history

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


def _default_out_dir(objetivo: str | None, todos: bool = False) -> Path:
    env = os.environ.get("REPORT_OUT_DIR")
    if env:
        return Path(env)
    s = '_todos' if todos else target_slug(objetivo) if objetivo else "sin_objetivo"
    return _FRAMEWORK_ROOT / "11_Reports" / "generated" / s


def _default_profile_path() -> Path:
    env = os.environ.get("REPORT_PROFILE")
    if env:
        return Path(env)
    return _FRAMEWORK_ROOT / "11_Reports" / ".report_profile"


def _session_target() -> str | None:
    """Primera línea de ``00_Config/.session`` si existe y no está vacía."""
    session_file = Path(os.environ.get("SESSION_FILE", str(_FRAMEWORK_ROOT / "00_Config" / ".session")))
    if not session_file.exists():
        return None
    try:
        text = session_file.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
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
    p.add_argument('--fuentes', default=None, help='Raíz del framework con evidencias anteriores (01/02/07/08/10)')
    p.add_argument("--salida", default=None, help="Raíz de historial; cada generación crea runs/<id>/ sin sobrescribir")
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
    # Renombrar "findings" -> "hallazgos" para el fichero en disco
    disk_data = dict(data)
    if "findings" in disk_data:
        disk_data["hallazgos"] = disk_data.pop("findings")
    path = out_dir / "findings.json"
    write_private(path, json.dumps(disk_data, indent=2, ensure_ascii=False))
    return path


def _load_json(path: Path) -> dict:
    """Carga findings.json y normaliza ``hallazgos`` -> ``findings``."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError('el registro debe ser un objeto')
    if 'hallazgos' in data and 'findings' in data:
        raise ValueError('registro ambiguo: findings y hallazgos simultáneos')
    if "hallazgos" in data and "findings" not in data:
        data["findings"] = data.pop("hallazgos")
    return data


def _summary(objetivo: str | None, collected, out_dir: Path, written: list[Path]) -> dict:
    confirmados = [f for f in collected.findings if f.confianza == "confirmado"]
    criticos = len([f for f in confirmados if f.severidad == "critica"])
    return {
        "objetivo": objetivo or "",
        "hallazgos": len(collected.findings),
        "criticos": criticos,
        "no_evaluable": len(collected.no_evaluable),
        "salida": str(out_dir),
        "archivos": [str(path.absolute()) for path in written],
        "run_id": out_dir.name,
    }


def _publish(collected, meta: dict, base: Path, tipos: list[str], args, objetivo: str | None) -> int:
    """Normal y rerender comparten reserva exclusiva, cierre y recibo final."""
    rc = 0 if collected.evaluado else 3
    stamp = datetime.now(timezone.utc)
    meta = dict(meta, fecha=stamp.strftime('%Y-%m-%d'), generado_en=stamp.isoformat())
    if args.todos:
        meta.update(objetivo='No especificado', alcance='Todos los objetivos incluidos', modo='todos')
    mode = 'todos' if args.todos else ('incluir_sin_objetivo' if args.incluir_sin_objetivo else 'objetivo')
    try:
        run = history.reserve(base, objetivo, mode, args.tipo, 'json' if args.desde_json else 'scans')
        written = write_reports(collected, meta, run.path, tipos)
        written.append(_write_json(to_json(collected, meta), run.path))
        written.append(history.finish(run, written, rc))
    except (OSError, ValueError) as exc:
        print(f'Error al publicar informes: {exc}', file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(_summary(objetivo, collected, run.path, written), ensure_ascii=False))
    if rc == 3:
        print('No hubo fuentes evaluables; informes limitados, no acredita ausencia de vulnerabilidades.', file=sys.stderr)
    if args.abrir:
        html = next(path for path in written if path.suffix == '.html')
        try:
            subprocess.run(['xdg-open', str(html)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            pass
    return rc


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

    # Validar entradas antes de crear directorios o publicar resultados.
    data = None
    try:
        if args.desde_json:
            data = _load_json(Path(args.desde_json))
            validation.document(data)
        objetivo = args.objetivo
        if objetivo is None and not args.todos:
            objetivo = data['meta'].get('objetivo') if data is not None else _session_target()
        if objetivo == 'No especificado' and args.todos:
            objetivo = None
        if objetivo is not None:
            objetivo = validation.target(objetivo)
        if objetivo is None and not args.todos:
            raise ValueError('indique --objetivo, una sesión activa o --todos explícito')
        if data is not None:
            validation.scope(data, objetivo, args.todos, args.incluir_sin_objetivo)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f'Error de entrada: {exc}', file=sys.stderr)
        return 1

    # --- Cargar perfil y resolver valores por defecto ---
    profile_path = _default_profile_path()
    try:
        profile = read_profile(profile_path)
    except (OSError, UnicodeError) as exc:
        print(f'Error al leer perfil: {exc}', file=sys.stderr)
        return 1
    todos = args.todos

    # Cliente/auditor: flag > perfil > valor por defecto
    cliente = args.cliente
    if cliente is None:
        cliente = profile.get("cliente", "No indicado")
    auditor = args.auditor
    if auditor is None:
        auditor = profile.get("auditor", os.environ.get("USER", "quien"))

    # Scans y salida
    scans_dir = Path(args.scans) if args.scans else _default_scans_dir()
    out_dir = Path(args.salida) if args.salida else _default_out_dir(objetivo, todos)
    # Una raíz scans externa no autoriza leer los otros árboles del checkout.
    fuentes = args.fuentes or os.environ.get('REPORT_FRAMEWORK_ROOT')
    if fuentes is None and args.scans is None and not os.environ.get('REPORT_SCANS_DIR'):
        fuentes = str(_FRAMEWORK_ROOT)

    tipos = _tipos_from_arg(args.tipo)
    try:
        preflight(out_dir / 'runs', [])
    except OSError as exc:
        print(f'Error de salida: {exc}', file=sys.stderr)
        return 1

    # --- Modo --desde-json: no tocar scans ---
    if args.desde_json:
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

        return _publish(collected, meta, out_dir, tipos, args, objetivo)

    # --- Modo normal: collect desde scans ---
    try:
        collected = collect(
            Path(scans_dir),
            _REPO_ROOT,
            objetivo,
            incluir_sin_objetivo=args.incluir_sin_objetivo,
            todos=todos,
            framework_root=Path(fuentes) if fuentes is not None else None,
        )
    except OSError as exc:
        print(f"Error al leer scans: {exc}", file=sys.stderr)
        return 1

    meta = {
        "cliente": cliente,
        "auditor": auditor,
        "fecha": datetime.now().strftime("%Y-%m-%d"),
        "objetivo": objetivo or "No especificado",
        "alcance": objetivo or "No especificado",
        "generado_en": datetime.now().isoformat(),
        "modo": "todos" if todos else ("incluir_sin_objetivo" if args.incluir_sin_objetivo else "objetivo"),
        "scans_dir": str(scans_dir),
        "herramientas": sorted({
            f.tecnica for f in collected.findings if f.tecnica
        }),
    }

    return _publish(collected, meta, out_dir, tipos, args, objetivo)


def main() -> None:
    """Punto de entrada como script: ``sys.exit(run())``."""
    sys.exit(run())


if __name__ == "__main__":
    main()
