#!/bin/bash
# Test-only fixed launcher. NOT RUN: Task4 review/authorization still pending.
case "$#:$1" in
    0:|1:--probes|1:--suite|1:--races) ;;
    *) printf '%s\n' 'BLOCKED: selector cerrado; sin comandos arbitrarios' >&2; exit 2 ;;
esac
if [[ -d /source/CyberSecurity-Framework/tests ]]; then
    printf '%s\n' 'BLOCKED: no reentrar al launcher desde sandbox' >&2
    exit 2
fi
case "${BASH_SOURCE[0]}" in
    */*) HERE="${BASH_SOURCE[0]%/*}" ;;
    *) HERE=. ;;
esac
exec /usr/bin/python3 -I -B "$HERE/automation_sandbox_launch.py" "$@"
