#!/bin/bash
# Suite aislada: solo fuentes allowlist; jamás copia configuración/evidencia real.
FW="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd)" || exit 1
exec python3 -B - "$FW" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

source = Path(sys.argv[1])
os.umask(0o077)
# Fixed source paths, not recursive discovery through module-owned output trees.
libraries = '''dangerous.txt enumeration_evidence.py enumeration_http.py
enumeration_menu.bash enumeration_runtime.bash enumeration_services.bash enumeration_web.bash
exploitation_evidence.py exploitation_menu.bash exploitation_runtime.bash
forensics_disk.bash forensics_evidence.py forensics_menu.bash forensics_runtime.bash
forensics_timeline.py forensics_volatility.bash http_request.bash params.bash
phase_status.bash postexploitation_evidence.py postexploitation_menu.bash
postexploitation_runtime.bash prompt.bash report_profile.bash scanner_runtime.bash
scanners_menu.bash scans.bash session.bash web_target.bash wireless_menu.bash'''.split()
leaves = '''requirements.sh run_all_forensics.sh show_results.sh
disk/disk_forensics.sh disk/file_carving.sh logs/log_analyzer.sh
memory/memory_dump.sh memory/strings_analysis.sh memory/volatility_analysis.sh
pcaps/pcap_analyzer.sh timeline/timeline_creator.sh'''.split()

def safe(path, directory=False):
    for parent in [path, *path.parents]:
        if stat.S_ISLNK(parent.lstat().st_mode):
            raise ValueError('symlink source')
    mode = path.lstat().st_mode
    if not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)):
        raise ValueError('nonregular source')

def source_names():
    tests = source / 'tests'
    safe(tests, True)
    discovered = sorted(p.name for p in tests.iterdir()
                        if p.name.startswith('test_forensics_') and p.name.endswith('.py'))
    if not discovered:
        raise ValueError('no tests')
    return (['cyber_framework.sh'] + ['00_Config/lib/' + n for n in libraries] +
            ['08_Forensics/' + n for n in leaves] +
            ['tests/' + n for n in discovered + ['forensics_fixture.py', 'verify_forensics.py', 'run_forensics.sh']])

def source_inventory():
    result = {}
    for name in source_names():
        p = source / name
        try:
            p.lstat()
        except FileNotFoundError:
            continue  # supports representative minimal runner fixtures
        safe(p)
        result[name] = [p.stat().st_mode, hashlib.sha256(p.read_bytes()).hexdigest()]
    return result

def source_layout():
    # Shallow names/types only in source directories: detects new entries without
    # opening unallowlisted files, config, evidence or symlink destinations.
    directories = {'', 'tests', '00_Config/lib', '08_Forensics'}
    directories.update('08_Forensics/' + n.split('/')[0] for n in leaves if '/' in n)
    result = {}
    for name in sorted(directories):
        parent = source / name
        try:
            parent.lstat()
        except FileNotFoundError:
            continue
        safe(parent, True)
        result[name] = sorted((p.name, p.lstat().st_mode) for p in parent.iterdir())
    return result

def inventory(root):
    # Only the newly-created synthetic tree; never follow any symlink.
    result = {}
    def visit(parent):
        for p in parent.iterdir():
            mode = p.lstat().st_mode
            key = str(p.relative_to(root))
            if stat.S_ISLNK(mode):
                result[key] = [mode, os.readlink(p)]
            elif stat.S_ISDIR(mode):
                result[key] = [mode, None]
                visit(p)
            elif stat.S_ISREG(mode):
                result[key] = [mode, hashlib.sha256(p.read_bytes()).hexdigest()]
            else:
                result[key] = [mode, 'SPECIAL']
    visit(root)
    return result

try:
    before_source = source_inventory()
    before_layout = source_layout()
    if '00_Config/lib/forensics_evidence.py' not in before_source:
        raise ValueError('missing reader')
    root = Path(tempfile.mkdtemp(prefix='forensics-suite-', dir='/tmp/opencode'))
    fw = root / 'CyberSecurity-Framework'
    for name in before_source:
        dst = fw / name
        dst.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        dst.write_bytes((source / name).read_bytes())
        dst.chmod(stat.S_IMODE(before_source[name][0]))
        if hashlib.sha256(dst.read_bytes()).hexdigest() != before_source[name][1]:
            raise ValueError('copy mismatch')
    config = fw / '00_Config'
    (config / 'scope.yaml').write_text('targets: {domains: [example.test], ips: []}\n')
    (config / 'targets.txt').write_text('# synthetic only\n')
    for name in ('home', 'bin', 'evidence'):
        (fw / name).mkdir(mode=0o700)
    (fw / 'evidence/synthetic').write_bytes(b'synthetic guard input')
    for name, target in [('python3', sys.executable), ('bash', '/bin/bash'), ('setsid', '/usr/bin/setsid')]:
        (fw / 'bin' / name).symlink_to(target)
    denied = '''sudo mount umount losetup journalctl dd ddrescue avml lime insmod modprobe
apt apt-get pip pip3 strings capinfos tshark tcpdump volatility volatility3 vol vol.py
fls mactime photorec foremost scalpel ewfacquire dmesg file fdisk blkid lsblk
find last grep curl wget'''.split()
    for name in denied:
        p = fw / 'bin' / name
        p.write_text('#!/bin/bash\nexit 99\n')
        p.chmod(0o700)
    env = dict(PATH=str(fw/'bin'), HOME=str(fw/'home'), TMPDIR='/tmp/opencode',
               LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
    before = inventory(root)
    print('Synthetic suite:', root, flush=True)
    completed = subprocess.run([sys.executable, '-B', '-m', 'unittest', 'discover',
                               '-s', 'tests', '-p', 'test_forensics_*.py', '-v'],
                               cwd=fw, env=env, umask=0o022)
    guard_ok = (inventory(root) == before and source_inventory() == before_source
                and source_layout() == before_layout)
    print('GUARD:', 'OK' if guard_ok else 'VIOLATION (inventory/content/mode)', flush=True)
    print('unittest rc:', completed.returncode, flush=True)
    sys.exit(completed.returncode if completed.returncode else (0 if guard_ok else 1))
except (OSError, ValueError, TypeError):
    print('GUARD: source/copy validation failed; no host fallback.', file=sys.stderr)
    sys.exit(1)
PY
