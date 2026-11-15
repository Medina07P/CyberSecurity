#!/bin/bash
LIB="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../../00_Config/lib" && pwd)" || exit 1
exec python3 -I -B "$LIB/labs_runtime.py" thm "$@"
