#!/bin/bash
# ============================================================
# TESTS - Motor de informes (11_Reports/lib/)
# Uso: ./run_reports.sh
# Ejemplo: ./run_reports.sh
# No necesita terminal interactiva: los tests crean sus propias fixtures.
# ============================================================

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FW="$(cd "$TESTS_DIR/.." && pwd)"
cd "$FW" || exit 1

python3 tests/test_report_engine.py
exit $?
