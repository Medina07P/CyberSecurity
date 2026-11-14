#!/usr/bin/env python3
"""Shim obsoleto: preview explícito; ejecución por el núcleo común de 09.

Uso: python3 report_generator.py --input <DIR> --output <FILE> --target <HOST>
"""
import argparse
import os
from pathlib import Path
import sys
from typing import Sequence

_FRAMEWORK = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_FRAMEWORK / '00_Config/lib'))

from automation.adapters import execute_plan
from automation.model import Permissions, PlanError, PreflightError, RuntimeContext
from automation.planner import build_plan, render_plan
from automation.reporting import check_report_destination, publish_reports, report_generation


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Compatibilidad obsoleta: motor 11 mediante núcleo 09')
    parser.add_argument('--input', required=True, help='Directorio scans explícito')
    parser.add_argument('--output', required=True, help='Archivo histórico: su directorio debe ser nuevo')
    parser.add_argument('--target', required=True, help='Objetivo explícito; nunca usa sesión')
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--allow', action='append', default=[], choices=['report:report_read'])
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)
    try:
        # Lexical absolute paths, not resolve(): do not silently follow symlinks.
        scans = Path(args.input)
        scans = scans if scans.is_absolute() else Path.cwd() / scans
        output = Path(args.output)
        output = output if output.is_absolute() else Path.cwd() / output
        destination = output.parent
        plan = build_plan('report', {'target': args.target, 'report_input': scans})
        ctx = RuntimeContext(_FRAMEWORK, _FRAMEWORK.parent, Path(sys.executable), os.defpath)
        print('Aviso: shim obsoleto. Los datos pueden ser históricos; no acreditan fases ejecutadas.')
        print('El archivo --output indica su directorio. Nombres: findings.json, '
              'informe_tecnico.md, informe_tecnico.html, informe_cliente.md, informe_cliente.html')
        print(render_plan(plan, ctx))
        if not args.execute:
            print('Preview: no se leen evidencias ni se crean salidas. Requiere --execute --allow report:report_read.')
            return 0
        permissions = Permissions(frozenset(), frozenset(tuple(item.split(':')) for item in args.allow))
        parent_identity = check_report_destination(destination)
        result = execute_plan(plan, ctx, permissions)
        raw_rc = result.steps[0].rc if result.steps else None
        # Never turn cancellation/storage failures into success via the raw rc.
        if result.steps and result.steps[0].state in ('completado', 'fallido') and raw_rc in (0, 3):
            if raw_rc == 0 and result.rc != 0:
                return result.rc
            generation = report_generation(result.run_dir, 'report', plan.steps[0].inputs['target'], raw_rc)
            publish_reports(generation, destination, parent_identity)
        return raw_rc if raw_rc is not None and result.rc in (0, 1) else result.rc
    except PlanError as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 2
    except (PreflightError, OSError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
