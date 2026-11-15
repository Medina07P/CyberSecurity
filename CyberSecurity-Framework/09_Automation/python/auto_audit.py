#!/usr/bin/env python3
"""Uso: python3 auto_audit.py <target> [recon|scan|enum|web] [opciones]."""
from pathlib import Path
import sys
from typing import Sequence

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / '00_Config/lib'))
from automation.cli import main as cli_main


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0].startswith('-'):
        return cli_main(args)
    target = args.pop(0)
    phase = None
    if args and not args[0].startswith('-'):
        phase = args.pop(0)
        if phase not in ('recon', 'scan', 'enum', 'web'):
            print('Fase desconocida; recon|scan|enum|web', file=sys.stderr)
            return 2
    return cli_main(['--target', target, *(['--phase', phase] if phase else ['--full']), *args])


if __name__ == '__main__':
    sys.exit(main())
