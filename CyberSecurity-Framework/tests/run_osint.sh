#!/bin/bash
# Suite OSINT local: no consume APIs, no modifica configuración real.
FW="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPD="$(mktemp -d)" || exit 1
trap 'rm -rf "$TMPD"' EXIT
export PYTHONDONTWRITEBYTECODE=1
# Guardas por contenido y existencia; no imprimir secretos ni sus hashes.
python3 - "$FW" "$TMPD" <<'PY'
import hashlib
import os
import subprocess
import sys
from pathlib import Path

fw, tmp = map(Path, sys.argv[1:])
paths = [fw/'00_Config/scope.yaml', fw/'00_Config/targets.txt',
         Path(os.environ.get('KEYS_FILE', fw/'00_Config/credentials/api-keys.yaml')),
         Path.home()/'.theHarvester/api-keys.yaml']
def fingerprint(path):
    return hashlib.sha256(path.read_bytes()).digest() if path.exists() else None
before = [fingerprint(path) for path in paths]
env = dict(os.environ, HOME=str(tmp/'home'), KEYS_FILE=str(tmp/'keys.yaml'),
           KEYS_HARVESTER_DIRS=str(tmp/'harvester'))
result = subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', str(fw/'tests'), '-p', 'test_osint.py', '-v'], env=env)
after = [fingerprint(path) for path in paths]
if before != after:
    print('FALLO: la suite modificó configuración real', file=sys.stderr)
    sys.exit(1)
print('Guardas de configuración real: intactas')
sys.exit(result.returncode)
PY
