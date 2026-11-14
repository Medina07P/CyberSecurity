#!/bin/bash
# Pruebas locales y sintéticas; no ejecuta hojas del framework.
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 -B "$TEST_DIR/test_module_intro.py" "$@"
