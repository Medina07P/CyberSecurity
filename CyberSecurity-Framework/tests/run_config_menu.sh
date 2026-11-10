#!/bin/bash
# Configuración guiada: fixtures locales, sin tocar claves ni objetivos reales.
FW="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
python3 - "$FW" <<'PY'
import hashlib
import os
import subprocess
import sys
from pathlib import Path

fw = Path(sys.argv[1])
paths = [fw/'00_Config/scope.yaml', fw/'00_Config/targets.txt',
         Path(os.environ.get('KEYS_FILE', fw/'00_Config/credentials/api-keys.yaml')),
         Path.home()/'.theHarvester/api-keys.yaml', Path.home()/'.shodan/api_key']
def fingerprint(path):
    return hashlib.sha256(path.read_bytes()).digest() if path.exists() else None
before = [fingerprint(path) for path in paths]
result = subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', str(fw/'tests'), '-p', 'test_config_menu.py', '-v'])
if before != [fingerprint(path) for path in paths]:
    print('FALLO: se alteró configuración real', file=sys.stderr)
    sys.exit(1)
print('Guardas de claves, scope y targets reales: intactas')
sys.exit(result.returncode)
PY
