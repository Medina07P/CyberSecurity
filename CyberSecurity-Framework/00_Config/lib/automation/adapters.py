"""Closed backends and execution-time authority checks. Never a preview reader.

Relative input paths are anchored to framework, not the caller's cwd. Preflight
does not create a run; compilation repeats checks and snapshots sensitive inputs
through no-follow descriptors. No inherited variable is an authorization.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import re
import shutil
import stat
from typing import Mapping
from urllib.parse import urlsplit

from .catalog import get_action, missing_python_dependencies
from .model import (Command, Permissions, Plan, PlanError, PreflightError,
                    RunResult, RuntimeContext, Step)
from .planner import validate_plan


_LEAVES = {
    'scan_basic': '03_Scanners/network_scanners/nmap/nmap_smart.sh',
    'ssh_enum': '04_Enumeration/ssh/enum_ssh.sh',
    'smb_audit': '04_Enumeration/smb/enum_smb_advanced.sh',
    'web_scan': '03_Scanners/web_scanners/nikto/nikto_scan.sh',
    'osint_domains': '01_OSINT/scripts/osint_harvester.sh',
    'config_check': '00_Config/scripts/validate_config.sh',
    'sqlmap_request': '05_Exploitation/web/sqlmap_request.sh',
}
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_MAX_REQUEST = 8 * 1024 * 1024
_SCANNER_SOURCES = ('scanner_runtime.bash', 'scans.bash')
_ENUM_SOURCES = _SCANNER_SOURCES + ('enumeration_services.bash',
                                  'enumeration_runtime.bash', 'enumeration_evidence.py')
_SOURCES = {
    'scan_basic': _SCANNER_SOURCES, 'web_scan': _SCANNER_SOURCES,
    'ssh_enum': _ENUM_SOURCES, 'smb_audit': _ENUM_SOURCES,
    'sqlmap_request': ('http_request.bash', 'scans.bash', 'session.bash'),
    'osint_domains': tuple('osint/' + name + '.py' for name in (
        '__init__', 'cli', 'credentials', 'discovery', 'dns', 'model', 'runtime', 'sources')),
}


def _path(ctx, path):
    path = Path(path)
    return path if path.is_absolute() else ctx.framework / path


@contextmanager
def _directory(path):
    """Pin each ancestor and reject substitutions before returning to caller."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise PreflightError('Ruta absoluta sin traversal requerida')
    fds, links = [], []
    entered = False
    try:
        fd = os.open('/', _DIR)
        fds.append(fd)
        for name in path.parts[1:]:
            child = os.open(name, _DIR, dir_fd=fd)
            links.append((fd, name, child))
            fds.append(child)
            fd = child
        entered = True
        yield fd
        for parent, name, child in links:
            current, pinned = os.stat(name, dir_fd=parent, follow_symlinks=False), os.fstat(child)
            if (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino):
                raise PreflightError('Identidad de directorio sustituida')
    except FileNotFoundError:
        if entered:
            raise
        raise PreflightError('Directorio requerido ausente') from None
    except OSError:
        raise PreflightError('Ruta ausente o identidad insegura') from None
    finally:
        for fd in reversed(fds):
            os.close(fd)


@contextmanager
def _regular(path):
    path = Path(path)
    with _directory(path.parent) as parent:
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                         dir_fd=parent)
        except FileNotFoundError:
            raise
        except OSError:
            raise PreflightError('Archivo no legible o inseguro') from None
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise PreflightError('Se requiere archivo regular sin enlaces simbólicos')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                yield stream
            after = os.fstat(fd)
            try:
                current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                raise PreflightError('Archivo retirado durante validación') from None
            identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            if identity(before) != identity(after) or identity(after) != identity(current):
                raise PreflightError('Identidad de archivo sustituida')
        finally:
            os.close(fd)


def _read(path, limit):
    try:
        with _regular(path) as stream:
            content = stream.read(limit + 1)
            if len(content) > limit:
                raise PlanError('Entrada supera límite de tamaño')
            return content
    except FileNotFoundError:
        raise PreflightError('Archivo requerido ausente') from None


def _tool(ctx, name):
    path = ':'.join(p for p in ctx.path.split(':') if p.startswith('/'))
    result = shutil.which(name, path=path) if path else None
    if result is None:
        raise PreflightError(f'Backend requerido ausente: {name}')
    return result


def _gate(step, permissions, gate):
    if (step.id, gate) not in permissions.grants:
        raise PlanError(f'{step.id}: falta permiso {gate}')


def _authority(authority, scheme):
    # Validate host/port with the same lexical validator used by the planner.
    from .validation import validate
    url = validate('url', scheme + '://' + authority)
    parsed = urlsplit(url)
    if parsed.path or parsed.query:
        raise PlanError('Autoridad de petición inválida')
    return parsed.hostname, parsed.port or (443 if scheme == 'https' else 80)


def _request(step, ctx, permissions):
    values = step.inputs
    path = _path(ctx, values['request_file'])
    raw = _read(path, _MAX_REQUEST)
    if path.suffix != '.req':
        raise PlanError('SQLmap exige un fichero .req explícito')
    try:
        header = raw.replace(b'\r\n', b'\n').split(b'\n\n', 1)[0].decode('ascii')
        lines = header.split('\n')
        method, destination, version = lines[0].split(' ')
        if (not re.fullmatch(r'[A-Z]+', method) or version not in ('HTTP/1.0', 'HTTP/1.1')
                or any(ord(c) < 32 and c != '\t' for c in header.replace('\n', ''))):
            raise ValueError()
        headers = []
        for line in lines[1:]:
            name, value = line.split(':', 1)
            if not re.fullmatch(r'[A-Za-z0-9-]+', name):
                raise ValueError()
            headers.append((name.lower(), value.strip()))
        hosts = [value for key, value in headers if key == 'host']
        if len(hosts) != 1:
            raise ValueError()
    except (UnicodeError, ValueError):
        raise PlanError('Cabeceras de petición no admitidas') from None
    authority = _authority(hosts[0], values['scheme'])
    if authority[0] != values['target']:
        raise PlanError('Destino de petición distinto del target')
    # The leaf compares literal host before rewriting it: fail rather than
    # silently changing a noncanonical vhost spelling in its private copy.
    if hosts[0].split(':')[0] != values['target']:
        raise PlanError('Host de petición debe usar el target canónico')
    if not destination.startswith('/') or destination.startswith('//'):
        from .validation import validate
        parsed = urlsplit(validate('url', destination))
        absolute = (parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80))
        if parsed.scheme != values['scheme'] or absolute != authority:
            raise PlanError('Autoridad/puerto/esquema de petición no concordantes')
    if method not in ('GET', 'HEAD'):
        _gate(step, permissions, 'sqlmap_replay')
    # Adjacent context wins over env in the existing leaf: reject conflicts,
    # then snapshot only the validated request (context is not needed there).
    try:
        with _regular(path.parent / 'contexto.txt') as stream:
            context = stream.read(65537)
        if len(context) > 65536:
            raise PlanError('Contexto demasiado grande')
        fields = {}
        for line in context.decode('utf-8').splitlines():
            if '=' not in line:
                continue
            key, value = line.split('=', 1)
            if key in fields:
                raise PlanError('Contexto duplicado')
            fields[key] = value
        if ('esquema' in fields and fields['esquema'] != values['scheme']
                or 'host' in fields and _authority(fields['host'], values['scheme']) != authority
                or 'metodo' in fields and fields['metodo'] != method):
            raise PlanError('Contexto de petición no concordante')
    except FileNotFoundError:
        pass
    except UnicodeError:
        raise PlanError('Contexto no admitido') from None
    return raw


def _check(step, ctx, permissions):
    spec = get_action(step.action)
    v = step.inputs
    if spec.network:
        destinations = {v.get('target', v.get('domain'))}
        if 'url' in v:
            destinations.add(urlsplit(v['url']).hostname)
        if not destinations <= permissions.targets:
            raise PlanError(f'{step.id}: destino sin autorización explícita')
    gates = spec.gates
    if step.action == 'sqlmap_request':
        gates = ('sqlmap_probe',)
        if 'database' in v:
            gates += ('sqlmap_enum',)
        if 'table' in v:
            gates += ('sqlmap_dump',)
    for gate in gates:
        _gate(step, permissions, gate)
    if step.action == 'web_scan' and ',' in v['url']:
        raise PlanError('Nikto no admite comas literales en URL')
    for tool in spec.tools:
        _tool(ctx, tool)
    if missing_python_dependencies(step.action):
        raise PreflightError('Dependencia Python requerida ausente: PyYAML (yaml)')
    sources = [ctx.framework / '00_Config/lib' / name for name in _SOURCES.get(step.action, ())]
    if step.action == 'report':
        sources.append(ctx.framework / '11_Reports/report_engine.py')
    if step.action in _LEAVES:
        sources.append(ctx.framework / _LEAVES[step.action])
    for source in sources:
        try:
            with _regular(source):
                pass
        except FileNotFoundError:
            raise PreflightError('Hoja requerida ausente') from None
    if step.action == 'ssh_attempts':
        try:
            with _regular(_path(ctx, v['wordlist'])):
                pass
        except FileNotFoundError:
            raise PreflightError('Wordlist requerida ausente') from None
    if step.action == 'sqlmap_request':
        return _request(step, ctx, permissions)
    return None


def preflight(plan: Plan, ctx: RuntimeContext, permissions: Permissions) -> None:
    """Revalidate ALL typed inputs, destinations, gates and backends; no writes."""
    plan = validate_plan(plan)
    for step in plan.steps:
        _check(step, ctx, permissions)
        if step.action == 'report':
            from .reporting import report_preflight
            report_preflight(step, ctx)


def _private_directory(parent, name):
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
    except FileExistsError:
        pass
    fd = os.open(name, _DIR, dir_fd=parent)
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(fd)
        raise PreflightError('Directorio de ejecución no privado')
    return fd


def _private_write(run_dir, name, data):
    with _directory(run_dir) as parent:
        _private_root(parent)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    return str(run_dir / name)


def _private_root(fd):
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise PreflightError('Run de ejecución no privado')


def child_env(ctx: RuntimeContext, run_dir: Path) -> Mapping[str, str]:
    """Allowlist only: private HOME/empty API registry, no inherited overrides."""
    with _directory(run_dir) as parent:
        _private_root(parent)
        for name in ('home', 'empty-keys'):
            fd = _private_directory(parent, name)
            try:
                if name == 'empty-keys' and os.listdir(fd):
                    raise PreflightError('Directorio privado de claves no vacío')
            finally:
                os.close(fd)
        # Reusing the environment never overwrites an existing credential file.
        try:
            fd = os.open('keys.yaml', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=parent)
        except FileExistsError:
            with _regular(run_dir / 'keys.yaml') as stream:
                info = os.fstat(stream.fileno())
                if (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
                        or info.st_nlink != 1 or stream.read(4) != b'{}\n'):
                    raise PreflightError('Registro privado de claves alterado')
        else:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(b'{}\n')
    return {'PATH': ':'.join(p for p in ctx.path.split(':') if p.startswith('/')),
            'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'HOME': str(run_dir / 'home'),
            'KEYS_FILE': str(run_dir / 'keys.yaml'),
            'KEYS_HARVESTER_DIRS': str(run_dir / 'empty-keys')}


def compile_step(step: Step, run_dir: Path, ctx: RuntimeContext,
                 permissions: Permissions) -> tuple[Command, ...]:
    """Fixed argv/cwd/env, never executable or environment data from inputs."""
    # validate_plan rechecks a manually constructed Step too. Dependencies were
    # checked at whole-plan preflight; do not invent missing dependency steps.
    single = Step(step.id, step.action, step.inputs, ())
    step = validate_plan(Plan('compile', (single,), 86400)).steps[0]
    raw = _check(step, ctx, permissions)
    if step.action == 'report':
        from .reporting import report_command
        return (report_command(step, run_dir, ctx),)
    env = child_env(ctx, run_dir)
    v, action = step.inputs, step.action
    target = v.get('target')
    timeout = 300
    if action == 'ping':
        args = ['ping', '-c', '1', target]
    elif action in ('ports_full', 'services', 'nse_services', 'os_detect', 'scan_vuln', 'db_versions'):
        flags = {
            'ports_full': ['-sT', '-Pn', '-p-', '-T4'],
            'services': ['-Pn', '-sV'], 'nse_services': ['-Pn', '-sV', '-sC'],
            'os_detect': ['-Pn', '-O'], 'scan_vuln': ['-Pn', '-sV', '--script', 'vuln'],
            'db_versions': ['-Pn', '-sV', '-p', '3306,5432,6379'],
        }[action]
        if 'ports' in v:
            flags += ['-p', ','.join(map(str, v['ports']))]
        args = ['nmap', *flags, '-oX', str(run_dir / (step.id + '.xml')), target]
    elif action == 'smb_shares':
        args = ['smbclient', '-L', '//' + target, '-N']
    elif action == 'web_tech':
        args = ['whatweb', v['url'], '-a', '3']
    elif action == 'exploit_lookup':
        args = ['searchsploit', v['product']]
    elif action == 'ssh_attempts':
        candidates = []
        with _regular(_path(ctx, v['wordlist'])) as stream:
            for _ in range(v['max_attempts']):
                line = stream.readline(65537)
                if not line:
                    break
                if len(line) > 65536 or b'\x00' in line:
                    raise PlanError('Candidato fuera de límites')
                candidates.append(line.rstrip(b'\r\n') + b'\n')
        if not candidates:
            raise PlanError('Wordlist vacía')
        copy = _private_write(run_dir, step.id + '.wordlist', b''.join(candidates))
        args = ['hydra', '-l', v['account'], '-P', copy, '-s', str(v['port']),
                '-t', '1', '-f', target, 'ssh']
        timeout = min(300, v['max_seconds'])
    else:
        leaf_args = {
            'scan_basic': [target, 'basico'], 'ssh_enum': [target, str(v.get('port', 22))],
            'smb_audit': [target], 'web_scan': [v.get('url')], 'config_check': [],
            'osint_domains': [v.get('domain'), str(run_dir / 'osint')],
            'sqlmap_request': [],
        }[action]
        if action == 'sqlmap_request':
            copy = _private_write(run_dir, step.id + '.req', raw)
            leaf_args = [copy, target]
            timeout = 900
            env.update(SQLMAP_ESQUEMA=v['scheme'], SQLMAP_FILAS='50', SQLMAP_MAX_SEG='900',
                       SQLMAP_ENUMERAR='1' if (step.id, 'sqlmap_enum') in permissions.grants else '0')
            if (step.id, 'sqlmap_replay') in permissions.grants:
                env['SQLMAP_SI'] = '1'
            if 'database' in v:
                env['SQLMAP_DB'] = v['database']
            if 'table' in v:
                env['SQLMAP_TABLA'] = (v['table'] if '.' in v['table']
                                       else v['database'] + '.' + v['table'])
        args = ['bash', str(ctx.framework / _LEAVES[action]), *leaf_args]
    return (Command((_tool(ctx, args[0]), *args[1:]), ctx.framework, env, timeout),)


def execute_plan(plan: Plan, ctx: RuntimeContext, permissions: Permissions) -> RunResult:
    """Runner entry: full preflight before RunStore.create or any child spawn."""
    from .runner import run_plan
    plan = validate_plan(plan)
    preflight(plan, ctx, permissions)

    def compile_closure(step, run_dir):
        commands = compile_step(step, run_dir, ctx, permissions)
        # Runner additionally clamps each command to its monotonic remaining
        # global budget. Keep leaf phase bounds <= the declared plan budget too.
        bounded = []
        for command in commands:
            env = dict(command.env)
            if step.action == 'sqlmap_request':
                env['SQLMAP_MAX_SEG'] = str(min(900, plan.timeout))
            bounded.append(Command(command.argv, command.cwd, env, min(command.timeout, plan.timeout)))
        return tuple(bounded)

    return run_plan(plan, ctx, permissions, compile_closure)
