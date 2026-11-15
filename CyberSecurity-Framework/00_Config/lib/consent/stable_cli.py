"""Public SMB/PSExec mode parser. No operation without an explicit mode."""
from pathlib import Path
import sys

# -I excludes cwd and PYTHONPATH; load only the leaf's own reviewed library.
sys.path.insert(0, str(Path(__file__).absolute().parent))
from generate import emit_launcher
from stable_tools import run_smb, run_psexec, validate_smb, validate_psexec


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in ('smb', 'psexec'):
        print('Herramienta no válida.', file=sys.stderr)
        return 2
    kind, args = argv[0], argv[1:]
    usage = ('enum_smb.sh HOST [PREFIJO] [--execute]' if kind == 'smb' else
             'ps_exec.sh HOST DOMINIO USUARIO PASS COMANDO [--execute]')
    help_text = (f'Uso: {usage}\nPreview por defecto: no ejecuta herramientas.\n'
                 'Modos exclusivos: --preview, --help, --execute, --generate DESTINO.\n'
                 'Generar no ejecuta ni guarda objetivo/credenciales; requiere destino NUEVO fuera del framework.\n'
                 'El lanzador requiere --framework-root DIR y modo explícito.\n'
                 'PSExec no oculta argv del sistema ni garantiza redacción universal del backend.')
    try:
        if args == ['--help'] or not args or args == ['--preview']:
            print(help_text)
            return 0
        if args[0] == '--generate':
            if len(args) != 2 or args[1].startswith('--'):
                raise ValueError('Generación requiere únicamente --generate DESTINO.')
            framework = Path(__file__).absolute().parents[3]
            emit_launcher(kind, Path(args[1]), framework)
            print('Lanzador nuevo creado; no ejecutado. Requiere raíz explícita del framework.')
            return 0
        mode = 'preview'
        if args[-1] in ('--execute', '--preview'):
            mode = args[-1][2:]
            args = args[:-1]
        # Only the final position is interpreted as a mode. In particular a
        # command/password beginning with -- remains literal positional data.
        # Exact arity and host validation reject unknown/duplicate mode extras.
        if kind == 'smb':
            if len(args) not in (1, 2):
                raise ValueError('SMB requiere HOST y un prefijo opcional.')
            if len(args) == 2 and args[1].startswith('--'):
                raise ValueError('Modo SMB desconocido, duplicado o fuera de posición.')
            prefix = validate_smb(args[0], args[1] if len(args) == 2 else None)
            if mode == 'execute':
                return run_smb(args[0], prefix)
        else:
            if len(args) != 5:
                raise ValueError('PSExec requiere exactamente cinco posiciones.')
            validate_psexec(*args)
            if mode == 'execute':
                return run_psexec(*args)
        print(help_text)
        return 0
    except ValueError as error:
        # Validators/emitter use fixed diagnostics, never interpolate argv.
        print(str(error), file=sys.stderr)
        return 2
    except OSError:
        # OS exception filenames can contain operator data; do not echo them.
        print('No se pudo crear el lanzador nuevo; no se reemplaza ningún destino.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
