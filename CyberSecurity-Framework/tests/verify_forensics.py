#!/usr/bin/env python3
"""Read-only check of an explicit 08 run; never imports executors or reads originals."""
from pathlib import Path
import sys
import types


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print('Uso: verify_forensics.py RUN_JSON', file=sys.stderr)
        return 2
    path = Path(args[0])
    try:
        path.lstat()
    except FileNotFoundError:
        print('NO_EVALUABLE: sin datos de ejecución.', file=sys.stderr)
        return 2
    except OSError:
        print('NO_EVALUABLE: metadata inaccesible.', file=sys.stderr)
        return 1
    try:
        # Direct compilation avoids __pycache__ even with ordinary Python (no -B).
        library = Path(__file__).resolve().parents[1] / '00_Config/lib/forensics_evidence.py'
        reader = types.ModuleType('forensics_evidence')
        reader.__file__ = str(library)
        exec(compile(library.read_bytes(), str(library), 'exec'), reader.__dict__)
        data = reader.read_run(path)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
        # Container shape errors must not expose a traceback or evidence paths.
        print('NO_EVALUABLE: ejecución inconsistente o ilegible.', file=sys.stderr)
        return 1
    if data['finished'] is None:
        print('INCOMPLETO: ejecución sin finalizar.')
        return 2
    if not data['complete'] or data['rc'] != 0:
        print('NO_COMPLETO: ejecución parcial, fallida o cancelada.')
        return 1
    print('COMPLETADO: metadata y artefactos privados coherentes; no certifica origen ni custodia legal.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
