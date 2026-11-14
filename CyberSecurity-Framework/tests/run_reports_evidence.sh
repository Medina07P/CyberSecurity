#!/bin/bash
# Uso: ./run_reports_evidence.sh
# Suite allowlist, HOME/config sintéticos y PATH sin herramientas operacionales.
TEST_DIR="$(cd -- "${BASH_SOURCE[0]%/*}" && pwd)" || exit 1
python3 -B - "$TEST_DIR" <<'PY'
import pathlib
import subprocess
import sys
sys.path.insert(0, sys.argv[1])
from reports_fixture import CONFIG, SOURCES, closed_env, copy_sources, manifest, sandbox
origin = pathlib.Path(sys.argv[1]).parent
before = manifest(origin)
with sandbox() as root:
    fw = copy_sources(root)
    env = closed_env(root)
    copied = manifest(fw, SOURCES + CONFIG)
    results = []
    for pattern in ('test_report_engine.py', 'test_postexploitation_reports.py',
                    'test_reports_evidence_contract.py', 'test_reports_runner.py', 'test_reports_ports.py',
                    'test_reports_history.py', 'test_reports_history_integration.py'):
        results.append(subprocess.run([str(root / 'bin/python3'), '-B', '-m', 'unittest',
                                      'discover', '-s', str(fw / 'tests'), '-p', pattern, '-v'],
                                     cwd=fw, env=env).returncode)
    if manifest(fw, SOURCES + CONFIG) != copied or manifest(origin) != before:
        sys.exit('GUARD FAILED: fuentes o configuración sintética modificadas')
    print('GUARD OK: allowlist origen intacta; copia y configuración sintética intactas.', flush=True)
    sys.exit(1 if any(results) else 0)
PY
