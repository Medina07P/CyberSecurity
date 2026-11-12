#!/usr/bin/env python3
"""Private text/timeline transformations. No implicit host access in source mode."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import types
from zoneinfo import ZoneInfo


def evidence():
    path = Path(__file__).with_name('forensics_evidence.py')
    module = types.ModuleType('forensics_evidence')
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


PATTERNS = {
    'sensitive': (True, 'password|pass|user|login|admin|root|token|secret|key|ssh|mysql|redis|postgres|credential|email|api'),
    'urls': (False, 'http://|https://|ftp://'),
    'emails': (False, r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    'levels': (False, 'ERROR|WARNING|INFO|DEBUG'),
    'errors': (True, 'error'),
    'auth': (False, 'authentication|login|auth|password'),
    'ssh': (False, 'sshd|ssh'),
    'ips': (False, r'\b([0-9]{1,3}\.){3}[0-9]{1,3}\b'),
}
TYPES = ('journal', 'auth', 'syslog', 'dpkg', 'wtmp', 'tree')
UTC = timezone.utc


def emit(value):
    print(json.dumps(value, ensure_ascii=True, separators=(',', ':')))


def checked_work(run, work, kind=None):
    data = evidence().read_run(Path(run))
    for item in data['inputs']:
        if item['work_path'] == str(Path(work).absolute()) and (kind is None or item['kind'] == kind):
            return item
    raise ValueError('unregistered input')


def utc(dt, zone):
    if dt.tzinfo is None:
        if zone is None:
            return None
        # Missing and repeated wall times are not disambiguated by guessing.
        a, b = dt.replace(tzinfo=zone, fold=0), dt.replace(tzinfo=zone, fold=1)
        if a.utcoffset() != b.utcoffset() or a.astimezone(UTC).astimezone(zone).replace(tzinfo=None) != dt:
            return None
        dt = a
    return dt.astimezone(UTC).isoformat().replace('+00:00', 'Z')


def epoch_ns(ns):
    seconds, nanos = divmod(ns, 1_000_000_000)
    dt = datetime.fromtimestamp(seconds, UTC)
    base = dt.strftime('%Y-%m-%dT%H:%M:%S')
    return base + (('.' + f'{nanos:09d}'.rstrip('0')) if nanos else '') + 'Z'


def command_environment(zone):
    env = dict(os.environ, LC_ALL='C')
    if zone:
        env['TZ'] = zone
    return env


def shell_rc(rc):
    return rc if rc >= 0 else 128 - rc


def text_time(line, year, zone):
    try:
        match = re.match(
            r'^(?P<seconds>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d)'
            r'(?:\.(?P<fraction>\d{1,9}))?'
            r'(?P<offset>Z|[+-](?:[01]\d|2[0-3]):?[0-5]\d)?(?=\s|$)', line)
        if match:
            # Require the whole timestamp token: malformed/unsupported suffixes
            # must not turn an explicit zone into a naive timestamp prefix.
            seconds = match['seconds'] + (match['offset'] or '').replace('Z', '+00:00')
            resolved = utc(datetime.fromisoformat(seconds), zone)
            # Convert only integer seconds through datetime (microsecond-only).
            # ISO fractions are unchanged by the integer-second UTC offset.
            if resolved and match['fraction'] is not None:
                return resolved[:-1] + '.' + match['fraction'] + 'Z'
            return resolved
        match = re.match(r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)', line)
        if match and year:
            return utc(datetime.strptime(f'{year} {match[1]}', '%Y %b %d %H:%M:%S'), zone)
        # last -F -w: retain the full line and resolve only its first full date.
        match = re.search(r'\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) ([A-Z][a-z]{2}\s+\d{1,2} \d\d:\d\d:\d\d \d{4})', line)
        if match:
            return utc(datetime.strptime(match[1], '%b %d %H:%M:%S %Y'), zone)
    except (ValueError, OverflowError, OSError):
        pass
    return None


def event(kind, origin, line, body, timestamp=None, reason=None):
    return {'version': 1, 'source_type': kind, 'origin': origin, 'line': line,
            'category': 'archivos_modificados' if kind == 'tree' else kind,
            'timestamp_utc': timestamp, 'section': 'resolved' if timestamp else 'unresolved',
            'reason': None if timestamp else (reason or 'date_not_resolved'), 'body': body}


def parse_lines(kind, lines, origin, year, zone):
    invalid = False
    for number, line in enumerate(lines, 1):
        timestamp = None
        if kind == 'journal':
            try:
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    raise ValueError('journal object required')
                value = obj.get('__REALTIME_TIMESTAMP')
                if isinstance(value, str) and re.fullmatch(r'[0-9]{1,19}', value):
                    timestamp = epoch_ns(int(value) * 1000)
            except (ValueError, TypeError, OverflowError, OSError):
                invalid = True
        else:
            timestamp = text_time(line, year, zone)
        emit(event(kind, origin, number, line, timestamp))
    return 1 if invalid else 0


def source(args):
    item = checked_work(args.run, args.work, 'tree' if args.kind == 'tree' else 'file')
    origin = item['input_id']
    zone = ZoneInfo(args.timezone) if args.timezone else None
    if args.kind == 'tree':
        temporal = item['original'].get('temporal')
        dates = {e['path']: e['mtime_ns'] for e in temporal['entries']} if temporal else {}
        for entry in item['original']['inventory']:
            if entry['kind'] == 'file':
                stamp = epoch_ns(dates[entry['path']]) if entry['path'] in dates else None
                emit(event('tree', origin, None, entry['path'], stamp, 'original_mtime_not_observed'))
        return 0
    backend_rc = 0
    if args.kind == 'wtmp':
        env = command_environment(args.timezone)
        result = subprocess.run(['last', '-f', args.work, '-F', '-w'], capture_output=True, env=env)
        backend_rc = shell_rc(result.returncode)
        sys.stderr.buffer.write(result.stderr)
        lines = result.stdout.decode('utf-8', 'replace').splitlines()
    else:
        lines = Path(args.work).read_text(errors='replace').splitlines()
    parse_rc = parse_lines(args.kind, lines, origin, args.year, zone)
    return backend_rc or parse_rc


def local_source(args):
    # Only called after the leaf's explicit LOCAL_SI confirmation. These are
    # historical host queries, never fallbacks from an offline failure.
    commands = {
        'journal': (['journalctl', '--since', '24 hours ago', '-o', 'json'], 100, False),
        'wtmp': (['last', '-a'], 20, False),
        'auth': (['grep', 'sshd', '/var/log/auth.log'], 20, True),
        'tree': (['find', '/', '-type', 'f', '-mtime', '-1', '-printf', '%T@ %p\n'], 20, False),
        'dpkg': (['grep', 'install', '/var/log/dpkg.log'], 10, True),
    }
    command, limit, tail = commands[args.kind]
    env = command_environment(args.timezone)
    result = subprocess.run(command, capture_output=True, env=env)
    backend_rc = shell_rc(result.returncode)
    if command[0] == 'grep':
        print(json.dumps({'grep_rc': result.returncode}), file=sys.stderr, flush=True)
        if result.returncode == 1:
            backend_rc = 0
    sys.stderr.buffer.write(result.stderr)
    lines = result.stdout.decode('utf-8', 'replace').splitlines()
    lines = lines[-limit:] if tail else lines[:limit]
    if args.kind == 'tree':
        for number, line in enumerate(lines, 1):
            match = re.match(r'^(-?\d+)\.(\d{1,9}) (.*)$', line)
            timestamp = None
            if match:
                timestamp = epoch_ns(int(match[1]) * 10**9 + int(match[2].ljust(9, '0')))
            emit(event('tree', 'local_tree', number, line, timestamp))
        return backend_rc
    parse_rc = parse_lines(args.kind, lines, 'local_' + args.kind, args.year,
                           ZoneInfo(args.timezone) if args.timezone else None)
    return backend_rc or parse_rc


def filter_text(args):
    insensitive, pattern = PATTERNS[args.filter]
    result = subprocess.run(['grep', '-E', *(['-i'] if insensitive else []), '--', pattern, args.work],
                            capture_output=True)
    sys.stdout.buffer.write(result.stdout)
    # Receipt is sealed as the capture's private stderr, not public UI. grep1
    # is a normal empty result, while >1/signal remains a failed wrapper rc.
    emit_rc = {'grep_rc': result.returncode}
    print(json.dumps(emit_rc), file=sys.stderr)
    sys.stderr.buffer.write(result.stderr)
    return 0 if result.returncode in (0, 1) else (result.returncode if result.returncode > 0 else 128 - result.returncode)


def summary(args):
    run = evidence().read_run(Path(args.run))
    checked_work(args.run, args.work, 'file')
    counts = {'lines': Path(args.work).read_bytes().count(b'\n')}
    grep_rc = {}
    for step in run['steps']:
        name = step['name']
        if name == 'summary':
            continue
        counts[name] = (Path(run['artifact_roots']['analysis']) / (name + '.stdout')).read_bytes().count(b'\n')
        if name in PATTERNS:
            receipt = (Path(run['artifact_roots']['analysis']) / (name + '.stderr')).read_text().splitlines()
            grep_rc[name] = json.loads(receipt[0])['grep_rc']
    emit({'counts': counts, 'grep_rc': grep_rc, 'interpretation': 'text_matches_not_proven_incidents'})
    return 0


def assemble(args):
    e = evidence()
    run = e.read_run(Path(args.run))
    analysis = Path(run['artifact_roots']['analysis'])
    events = []
    for step in run['steps']:
        if step['name'].startswith('source_'):
            with (analysis / (step['name'] + '.stdout')).open() as stream:
                events.extend(json.loads(line) for line in stream)
    def order(value):
        # datetime would truncate observed nanoseconds to microseconds. All
        # producer timestamps are UTC; pad fractions without losing precision.
        whole, _, fraction = value['timestamp_utc'][:-1].partition('.')
        return whole, fraction.ljust(9, '0')

    resolved = sorted((v for v in events if v['timestamp_utc']), key=order)
    unresolved = [v for v in events if not v['timestamp_utc']]
    products = []
    for name, value in [('events.jsonl', resolved + unresolved),
                        ('timeline_summary.json', {'resolved': len(resolved), 'unresolved': len(unresolved),
                         'mode': run['mode'], 'year': args.year, 'timezone': args.timezone,
                         'coverage': 'historical_fragments' if run['mode'] == 'local' else 'selected_sources_only',
                         'limits': {'journal': 100, 'wtmp': 20, 'auth': 20, 'tree': 20, 'dpkg': 10} if run['mode'] == 'local' else {},
                         'interpretation': 'not_a_proven_chronology'})]:
        path = analysis / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            if name == 'events.jsonl':
                for v in value:
                    stream.write(json.dumps(v, ensure_ascii=True) + '\n')
            else:
                json.dump(value, stream, ensure_ascii=True)
                stream.write('\n')
        products.append(path)
    e.record_step(Path(args.run), 'timeline_products', 0, 'COMPLETADO',
                  {'code': 'derived_selected_sources', 'complete': True, 'requested': True}, products)
    return 0


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError('invalid arguments')


def main():
    parser = Parser(description=__doc__)
    parser.add_argument('action', choices=('validate', 'source', 'local', 'filter', 'summary', 'assemble'))
    parser.add_argument('--run')
    parser.add_argument('--root')
    parser.add_argument('--work')
    parser.add_argument('--kind', choices=TYPES + ('file',))
    parser.add_argument('--filter', choices=tuple(PATTERNS))
    parser.add_argument('--year', type=int)
    parser.add_argument('--timezone')
    args = parser.parse_args()
    try:
        if args.year is not None and not 1 <= args.year <= 9999:
            raise ValueError('invalid year')
        if args.timezone:
            ZoneInfo(args.timezone)
        if args.action == 'validate':
            if args.work:
                e = evidence()
                path = e._path(Path(args.work))
                info = path.lstat()
                if not (stat.S_ISDIR(info.st_mode) if args.kind == 'tree' else stat.S_ISREG(info.st_mode)):
                    raise ValueError('invalid source kind')
                if not info.st_mode & 0o444:
                    raise ValueError('unreadable source')
                if args.root and e._overlaps(e._path(Path(args.root)), path):
                    raise ValueError('overlapping output')
            return 0
        return {'source': source, 'local': local_source, 'filter': filter_text,
                'summary': summary, 'assemble': assemble}[args.action](args)
    except (OSError, ValueError, KeyError, TypeError, OverflowError):
        print('Transformación forense no evaluable; diagnóstico privado del paso.', file=sys.stderr)
        return 2 if args.action == 'validate' else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except ValueError:
        print('Uso forense inválido.', file=sys.stderr)
        sys.exit(2)
