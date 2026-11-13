#!/bin/bash
# Visor forense: solo metadata validada, sin originales ni cuerpos.
# Uso: ./show_results.sh [--run PATH] [--input SHA256] [--operation OP]
script_dir=${BASH_SOURCE[0]%/*}
[[ $script_dir != "${BASH_SOURCE[0]}" ]] || script_dir=.
lib_dir=$(CDPATH= cd -- "$script_dir/../00_Config/lib" && pwd) || exit 2
python3 -B - "$lib_dir/forensics_evidence.py" "${FORENSICS_ANALYSIS_ROOT:-$lib_dir/../../08_Forensics/analysis}/runs" "$@" <<'PY'
import json, re, sys, types
from datetime import datetime, timezone
from pathlib import Path
helper, default, *args = sys.argv[1:]
e = types.ModuleType('forensics_evidence')
e.__file__ = helper
exec(compile(Path(helper).read_bytes(), helper, 'exec'), e.__dict__)
try:
    root = Path(default)
    filters = {}
    seen = set()
    while args:
        flag = args.pop(0)
        if flag not in ('--run', '--input', '--operation') or flag in seen or not args:
            raise ValueError()
        seen.add(flag)
        value = args.pop(0)
        if flag == '--run':
            root = e._path(value)
            candidate = root.parent if root.name == 'run.json' else root
            if not e.RUN_ID.fullmatch(candidate.name) or not candidate.is_dir():
                raise ValueError()
        else:
            filters['identity' if flag == '--input' else 'operation'] = value
    # Validate filters even when no runs exist. External roots require --run.
    for key, value in filters.items():
        e._hash(value) if key == 'identity' else e._choice(value, e.OPERATIONS)
    roots = [root] if root.exists() else []
    if '--run' not in seen:
        # Only our fixed local workflow layout, never arbitrary roots taken
        # from JSON, legacy capture globs, or an external parent supplied as run.
        workflows = e._path(root.parent / 'workflows')
        if workflows.exists():
            for flow in workflows.iterdir():
                if re.fullmatch(r'flow-[a-z0-9_]{8}', flow.name):
                    child = e._path(flow / 'acquisition' / 'runs')
                    if child.exists():
                        roots.append(child)
    rows = []
    for selected_root in roots:
        rows.extend(e.select_runs(selected_root, {k: v for k, v in filters.items() if k != 'identity'}))
    # Reconcile default and isolated local acquisitions as one UTC-ordered view.
    e.reconcile_current(rows)
    # --input accepts a source digest as well as the aggregate identity.
    # Filter last: unreadable/newest metadata must never revive an older run.
    if 'identity' in filters:
        digest = filters['identity']
        rows = [row for row in rows if row['invalid'] or row['identity'] == digest or
                any(item['sha256'] == digest for item in row['inputs'])]
except (ValueError, OSError, TypeError):
    print('NO_EVALUABLE: selección o metadata ilegible. Uso: show_results.sh [--run PATH] [--input SHA256] [--operation OP]', file=sys.stderr)
    sys.exit(2)
if not rows:
    print('Sin ejecuciones con metadata fiable para esta selección.', file=sys.stderr)
print('Históricos sin metadata: no se atribuyen como evidencia vigente.', file=sys.stderr)
for row in rows:
    if row['invalid']:
        print('NO_EVALUABLE: manifiesto inválido; vigencia bloqueada.', file=sys.stderr)
        continue
    # JSON quoting also prevents terminal control sequences in untrusted labels.
    summary = {key: row[key] for key in ('run_id', 'operation', 'mode', 'identity',
               'started', 'finished', 'state', 'complete', 'rc', 'inputs')}
    if 'identity_kind' in row:
        summary.update(identity_kind=row['identity_kind'], observed_devices=row['observed_devices'])
    print(('ACTUAL ' if row['current'] else 'HISTORICO ') + json.dumps(summary, ensure_ascii=True, sort_keys=True))
    for step in row['steps']:
        print(json.dumps({key: step[key] for key in ('name', 'tool', 'state', 'rc', 'signal', 'coverage')}, ensure_ascii=True, sort_keys=True))
        for ref in step['artifacts']:
            print(json.dumps({key: ref[key] for key in ('sha256', 'size')}, sort_keys=True))
sys.exit(1 if any(row['invalid'] for row in rows) else 0)
PY
