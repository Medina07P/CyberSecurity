#!/bin/bash
# Suite aislada: storage/inventory/package/process/ledger/capture/CLI/menú desde allowlist.
# Incluye exportación sintética, configuración privada y PATH cerrado.
TEST_DIR="$(cd -- "${BASH_SOURCE[0]%/*}" && pwd)" || exit 1
python3 -B - "$TEST_DIR" <<'PY'
import pathlib
import subprocess
import sys
sys.path.insert(0, sys.argv[1])
from evidence_fixture import sandbox, copy_sources, closed_env, snapshot
with sandbox() as root:
    framework = copy_sources(root)
    env = closed_env(root)
    before = snapshot(framework)
    command = [str(root / 'bin/python3'), '-B', '-m', 'unittest', 'discover',
               '-s', str(framework / 'tests'), '-p', 'test_evidence_*.py', '-v']
    result = subprocess.run(command, cwd=root, env=env)
    if snapshot(framework) != before:
        sys.exit('ERROR: las fuentes/configuración sintéticas cambiaron')
    sys.exit(result.returncode)
PY
