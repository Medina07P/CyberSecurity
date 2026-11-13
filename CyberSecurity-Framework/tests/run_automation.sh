#!/bin/bash
# BLOCKED: Task9 I1. No discovery, imports, probes, descendants or fallback.
# Intended discovery test_automation_*.py/PYTHONDONTWRITEBYTECODE remains
# disabled until an independently reviewed inherited OS barrier exists.
# This script uses shell builtins only; availability of bwrap is NOT approval.
printf '%s\n' 'BLOCKED: automation tests require an approved inherited filesystem/network OS barrier; audit hooks are insufficient. No tests or probes launched.' >&2
exit 2
