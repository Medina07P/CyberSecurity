#!/bin/bash
# Pruebas aisladas: nunca invoca escáneres reales ni escribe en scans real.
FW="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
python3 - "$FW" <<'PY'
import hashlib
import subprocess
import sys
from pathlib import Path
fw = Path(sys.argv[1])
paths = [fw/'00_Config/scope.yaml', fw/'00_Config/targets.txt',
         fw/'00_Config/.session', fw/'00_Config/scripts/api_keys.py']
def snapshot():
    return [(p.stat().st_mode, hashlib.sha256(p.read_bytes()).hexdigest())
            if p.exists() else None for p in paths]
before = snapshot()
result = subprocess.run([sys.executable, '-m', 'unittest', 'discover',
                         '-s', str(fw/'tests'), '-p', 'test_scanners_menu.py', '-v'])
if before != snapshot():
    sys.exit('FALLO: configuración o permisos reales alterados')
print('Guardas de configuración, sesión y permisos: intactas')
sys.exit(result.returncode)
PY
