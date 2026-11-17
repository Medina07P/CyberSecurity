#!/bin/bash
# Asistente IA local: pruebas sintéticas, sin red ni Ollama real, sin tocar
# claves, alcance ni objetivos reales.
FW="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
python3 - "$FW" <<'PY'
import hashlib
import subprocess
import sys
from pathlib import Path

fw = Path(sys.argv[1])
paths = [fw/'00_Config/scope.yaml', fw/'00_Config/targets.txt',
         fw/'00_Config/credentials/api-keys.yaml']
def fingerprint(path):
    return hashlib.sha256(path.read_bytes()).digest() if path.exists() else None
before = [fingerprint(path) for path in paths]
data_existed = (fw/'09_Automation/ai/data').exists()
pycache_before = {str(d.relative_to(fw)) for d in fw.rglob('__pycache__')}
result = subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', str(fw/'tests'), '-p', 'test_ai_*.py', '-v'], cwd=str(fw))
if before != [fingerprint(path) for path in paths]:
    print('FALLO: se alteró configuración real', file=sys.stderr)
    sys.exit(1)
if not data_existed and (fw/'09_Automation/ai/data').exists():
    print('FALLO: las pruebas dejaron 09_Automation/ai/data en el árbol', file=sys.stderr)
    sys.exit(1)
new_pycache = {str(d.relative_to(fw)) for d in fw.rglob('__pycache__')} - pycache_before
if new_pycache:
    print('FALLO: las pruebas dejaron __pycache__ en el árbol', file=sys.stderr)
    sys.exit(1)
print('Guardas de claves, scope y targets reales: intactas')
sys.exit(result.returncode)
PY
