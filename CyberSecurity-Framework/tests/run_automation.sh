#!/bin/bash
# Suite sintética: discovery de contratos, sin suites heredadas ni auditorías.
TEST_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || exit 1
export PYTHONDONTWRITEBYTECODE=1
python3 -I -B - "$TEST_DIR" <<'PY'
import sys
import unittest
sys.path.insert(0, sys.argv[1])
from pathlib import Path
from automation_test_guard import install
install(Path(sys.argv[1]).resolve().parents[1])
suite = unittest.defaultTestLoader.discover(sys.argv[1], pattern='test_automation_*.py')
result = unittest.TextTestRunner(verbosity=2).run(suite)
print(f'Automation: {result.testsRun} tests; failures={len(result.failures)}; errors={len(result.errors)}', flush=True)
sys.exit(0 if result.wasSuccessful() else 1)
PY
rc=$?
if (( rc != 0 )); then
    printf 'Automation: discovery/pruebas fallaron (rc=%d). Consulte stderr.\n' "$rc" >&2
fi
exit "$rc"
