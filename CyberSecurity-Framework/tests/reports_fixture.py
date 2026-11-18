"""Allowlist cerrada de código de informes; nunca copia config/evidencias locales."""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile

REPORT = (
    'report_engine.py', 'report_generator.sh', 'run_all_reports.sh',
    'lib/__init__.py', 'lib/attribution.py', 'lib/catalog.py', 'lib/model.py',
    'lib/engine.py', 'lib/sources.py', 'lib/render.py', 'lib/validation.py',
    'lib/coverage.py', 'lib/exploitation_metadata.py', 'lib/publication.py', 'lib/history.py',
    'lib/parsers/__init__.py', 'lib/parsers/exploitation.py', 'lib/parsers/postexploitation.py',
    'lib/parsers/nmap.py', 'lib/parsers/nuclei.py', 'lib/parsers/nikto.py', 'lib/parsers/ffuf.py',
    'lib/parsers/headers.py', 'lib/parsers/host_sources.py', 'lib/parsers/http_inject.py',
    'lib/parsers/rate_limit.py', 'lib/parsers/sqli_findings.py', 'lib/parsers/sqlmap.py',
    'lib/parsers/prior_modules.py', 'lib/parsers/scanner_ports.py',
)
BASH = ('params', 'session', 'phase_status', 'prompt', 'report_profile', 'scans', 'module_intro',
        'scanners_menu', 'exploitation_menu', 'enumeration_menu', 'postexploitation_menu',
        'wireless_menu', 'forensics_menu', 'evidence_menu')
EVIDENCE = ('__init__', 'model', 'storage', 'inventory')
TESTS = ('test_report_engine.py', 'test_postexploitation_reports.py',
         'test_reports_evidence_contract.py', 'test_reports_runner.py', 'test_reports_ports.py', 'test_reports_history.py',
         'test_reports_history_integration.py', 'reports_fixture.py', 'run_reports_evidence.sh')
AI = ('__init__', 'redact')
SOURCES = (('cyber_framework.sh',) + tuple('11_Reports/' + p for p in REPORT)
           + tuple('00_Config/lib/' + p + '.bash' for p in BASH)
           + ('00_Config/lib/postexploitation_evidence.py',)
           + tuple('00_Config/lib/evidence/' + p + '.py' for p in EVIDENCE)
           + tuple('00_Config/lib/ai/' + p + '.py' for p in AI)
           + tuple('tests/' + p for p in TESTS))
CONFIG = ('00_Config/scope.yaml', '00_Config/targets.txt', '00_Config/.session', '11_Reports/.report_profile')


def latest_run(base):
    """Selección solo para fixtures; producción consume el recibo de CLI."""
    candidates = sorted(Path(base).glob('runs/run-*'))
    if not candidates:
        raise AssertionError(f'no synthetic report run under {base}')
    return candidates[-1]


def manifest(source, paths=SOURCES):
    """Hash exclusivamente allowlist; ancestros por lstat, sin recorrer datos."""
    result = {}
    source = Path(source).absolute()
    for relative in paths:
        path = source / relative
        for ancestor in (path, *path.parents):
            if ancestor.is_symlink():
                raise ValueError('enlace en fuente permitida')
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('fuente no regular')
        result[relative] = (stat.S_IMODE(info.st_mode), hashlib.sha256(path.read_bytes()).hexdigest())
        for parent in path.parents:
            if parent == source.parent:
                break
            info = parent.lstat()
            result[str(parent.relative_to(source))] = (stat.S_IMODE(info.st_mode), stat.S_IFMT(info.st_mode))
    return result


@contextmanager
def sandbox():
    with tempfile.TemporaryDirectory(prefix='reports-suite-', dir='/tmp/opencode') as name:
        root = Path(name)
        root.chmod(0o700)
        yield root


def copy_sources(root):
    source = Path(__file__).absolute().parents[1]
    before = manifest(source)
    fw = root / 'CyberSecurity-Framework'
    for relative in SOURCES:
        destination = fw / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / relative, destination)
    for relative, value in zip(CONFIG, ('targets: {ips: [], domains: []}\n', '# synthetic\n', '', 'cliente=Synthetic\nauditor=Test\n')):
        path = fw / relative
        path.write_text(value)
        path.chmod(0o600)
    if manifest(source) != before:
        raise ValueError('fuentes cambiaron durante copia')
    return fw


def closed_env(root):
    bindir = root / 'bin'
    bindir.mkdir(mode=0o700)
    for name, executable in [('python3', sys.executable), ('bash', '/bin/bash'),
                              ('dirname', '/usr/bin/dirname'), ('cat', '/usr/bin/cat'),
                              ('find', '/usr/bin/find'), ('head', '/usr/bin/head'), ('tr', '/usr/bin/tr')]:
        (bindir / name).symlink_to(executable)
    for name in ('clear',):
        (bindir / name).write_text('#!/bin/bash\nexit 0\n')
        (bindir / name).chmod(0o700)
    (root / 'home').mkdir(mode=0o700)
    fw = root / 'CyberSecurity-Framework'
    return {'HOME': str(root / 'home'), 'PATH': str(bindir), 'LC_ALL': 'C.UTF-8',
            'TMPDIR': str(root), 'PYTHONDONTWRITEBYTECODE': '1',
            'REPORT_SCANS_DIR': str(root / 'scans'), 'REPORT_OUT_DIR': str(root / 'out'),
            'REPORT_FRAMEWORK_ROOT': str(fw), 'REPORT_PROFILE': str(fw / CONFIG[3]),
            'SESSION_FILE': str(fw / CONFIG[2]), 'SESSION_SCOPE_FILE': str(fw / CONFIG[0]),
            'SESSION_TARGETS_FILE': str(fw / CONFIG[1])}
