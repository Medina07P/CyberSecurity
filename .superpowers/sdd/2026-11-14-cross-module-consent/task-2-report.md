# Task2 — cleanup consent gates: STATIC delivery, DONE_WITH_CONCERNS

Date: 2026-11-14. Base: `a52a19718932c4c85ca5f9e06c2f789cebeec1fe`.
Implementation commit: `3889cd9` (`fix(cleanup): require explicit local consent and pin file operations`).
This report is delivered in a subsequent documentation-only commit.

**No functional GREEN claim.** Independent static review and fresh, exact
controller authorization are still required before any launcher/helper/import/
probe/test/product/backend execution. No such execution occurred in this task.
No nested agents, sudo, real log/history/access content, network, install, GUI,
cleanup, merge, push, reset, artifact deletion or global baseline refresh.

## Inputs and provenance

Read Task2 brief, Task1 context intro/Global Constraints (the file also exposes
downstream contracts), Task1 report lines455–479, binding design §§5/12–14 and
the supplied/current AGENTS.md restrictions. Task1 selection infrastructure is
retained, not reimplemented. Worktree was clean at the specified base.

Controller's prior suite evidence (not this delivery's verification):
`/tmp/opencode/automation-isolated-4085edf77d4849998fa1c4c2b8b5148d/evidence`:
reported 65 sandbox +179 integration, no failures/errors, one pwsh SKIP on base.

Prior meaningful RED was inspected **as data**, not rerun:
`/tmp/opencode/automation-isolated-152ea779f2fa4609a832caa9340dbfa4/evidence`.
`cross-consent.json` records nine tests,13 assertion failures,two errors,no skips,
no blocked cases; this is NOT a green selection. Worker stderr logs1–4 show:

| Case suffix (`test_cross_consent.ConsentTests.`) | Observed prior RED |
| --- | --- |
| `test_cleanup_nonexecution_is_inert` | Seven failing variants; default/preview/help called four sudo truncates and last; unsupported modes returned0 |
| `test_cleanup_requires_both_flags` | Missing-consent invocation returned0 instead of2 |
| `test_cleanup_local_plan_and_partial_failure` | Missing `consent` module error |
| `test_cleanup_refuses_links` | Missing `consent` module error |

Logs5–8 were also read: Burp still invokes curl during open, status writes,
verify lacks the gate and stop returns0 without consent. These REDs and the UI
RED are explicitly deferred to Tasks3/4. None was hidden, skipped or repaired
here. All old evidence/runs and final synthetic fixture trees remain untouched.

## Changes, sources and interfaces

All product/test paths below are relative to `CyberSecurity-Framework/`.

| File | Responsibility |
| --- | --- |
| `00_Config/lib/consent/__init__.py` | Import-inert package marker |
| `00_Config/lib/consent/files.py` | Descriptor-relative no-follow directories, pinned regular-file truncation, exclusive private snapshot writer |
| `00_Config/lib/consent/cleanup.py` | Immutable operations/results, exact pure seven-row plan, default operation adapter, allocation/iteration/partial results |
| `00_Config/lib/consent/cleanup_cli.py` | Strict public parser and LOCAL consent; no session lookup |
| `06_PostExploitation/cleanup/logs_cleaner.sh` | Stable public leaf; delegates with Python `-I -B -X utf8`, no automatic operation |
| `tests/automation_sandbox_sources.json` | Exactly four new consent source names |
| `tests/cross_module_fixture.py` | Exactly four new eager-copy names; minimal locale correction |
| `tests/test_cross_consent.py` | Existing cleanup IDs retain assertions; add strict help/error combinations, TTY rejection/EOF/generic yes, hardlink and ancestor-link refusals |

No runtime executable/library manifest change is needed: Python, Bash and proc
already belong to the reviewed runtime. `last` remains a mandatory fixture
double, not a new host-runtime tool. No backend fallback or grant changes.
No operational baseline contains the modified cleaner; its baseline JSON was
read and remains byte-for-byte unchanged. No menu/coordinator/Burp changes.

* `plan_cleanup(home: Path) -> tuple[CleanupOperation, ...]`: four fixed logs
  `/var/log/{auth.log,syslog,btmp,wtmp}`, `.bash_history`, child-history,
  snapshot. No destination inspection/read/write or subprocess while planning.
* Frozen `CleanupOperation(kind, path)`; frozen row
  `OperationResult(operation, success, error)`; frozen
  `CleanupResult(rc, operations, report_dir)`.
* `apply_cleanup(plan, report_root, ops=None)` treats report_root as
  **scans/cleanup BASE**. Exclusive UUID child allocated before operations;
  mode0700; child descriptor retained throughout execution. Allocation failure
  prevents all operations. No retry/reuse of colliding IDs or old artifacts.
* `CleanupOps.perform(operation, child)` returns bytes **only for snapshot**,
  None for other successful operations, or raises on failure. Default adapter
  checks fixed log/history destinations. Injection is Python-only, never a
  public environment variable/CLI argument or production destination override.
* Core exclusively writes0600 `last_access.txt`, does not reopen the directory
  pathname for publication, and retains all partial output. Each ordinary
  operation error becomes a failed row; later rows still run; any failed row
  yields rc1. Neither record bodies nor captured snapshot bytes are printed.
* CLI no args/preview/help are inert. Unknown/legacy/abbreviated options,
  incompatible modes and consent-alone fail2 before planning/effects. Help
  cannot mask an unknown argument or be combined with an operation mode.
* Apply requires `--execute` plus `--confirm-local-cleanup`, or actual stdin
  AND stderr TTY and exact `LIMPIAR LOCAL`. UID and impacts are displayed.
  EOF/no/generic yes return2. Global assume-yes and session target confer no
  permission. Parser errors may raise argparse's SystemExit2; wrapper preserves
  the exit status. Public main's framework/ops injection is internal Python only.

## Capability matrix and safety tradeoffs

| Capability | Before | After (static source contract, NOT runtime-certified) |
| --- | --- | --- |
| Fixed four logs | Implicit sudo/path-based truncation even on help | Same four destinations, explicit LOCAL gate, pinned inode, current credentials only |
| User history | Implicit shell redirection (could create/follow link) | Same history destination, existing regular single-link file required, no creation/following |
| Child history | `history -c` in leaf Bash | `history -c` only in fresh Bash child; never parent-shell memory |
| Access snapshot | last-a/head10 into shared `/tmp/last_access.txt` | last-a with ten-entry bound, first ten output lines in exclusive private UUID child |
| Failure | stderr suppressed; unconditional complete success | Inherited backend stderr, per-row success/error, partial rc1 |

**Intentional conservative privilege change:** no automatic sudo adapter is
implemented. The adapter operates only with the invoking process's existing
credentials; insufficient authority is a real per-operation failure, never a
retry under elevated authority. This preserves the original operation set but
does NOT promise the old automatic privilege-prompt workflow. It avoids both a
validate-then-sudo pathname race and introducing an elevated helper/protocol or
new security authority. Review this choice explicitly; if automatic escalation
is required, it needs separate context/design/authorization, not a fallback.
Do not solve failed integration by running real cleanup as root or adding sudo.
The existing synthetic test's comment about sudo refusal is historical: its
unchanged rc1 assertion now exercises missing/inaccessible fixed system paths;
the `last` double still supplies the recorded access snapshot. No fake sudo
call is added merely to satisfy the comment/recording.

`truncate_regular` walks parent components with O_DIRECTORY|O_NOFOLLOW, pins
the final name with O_PATH|O_NOFOLLOW, rejects links/nonregular/multilink objects
before opening a device/FIFO backend, then opens the **already pinned inode**
through `/proc/self/fd/<fd>`, rechecks identity/type/link count and ftruncates the
writable descriptor. The procfd alias is intentional: it is not an arbitrary
filesystem symlink and does not redo the original pathname lookup. Missing
Linux O_PATH/proc support/permissions fails closed; no unsafe fallback exists.
No O_TRUNC or creation is used on logs/history. Generic helpers are internal;
production log paths remain fixed, not test-overridable.

Existing parent directories are never chmodded. Newly created directory
components use0700; base must be owned by effective UID and not writable by
group/others. Snapshot uses O_EXCL|O_NOFOLLOW and fchmod0600. Old UUID children
and legacy `/tmp/last_access.txt` are neither read, removed nor migrated.

Limits: these descriptors do not certify a hostile same-UID process/kernel,
freeze concurrent legitimate writers, prevent every post-check hardlink race,
or make the printed pathname authoritative after an ancestor rename. No
Windows/Docker/operational compatibility, legal custody or whole-branch green
claim. Snapshot collection still depends on local last/permissions and records
only this bounded attempt. Failed publication can retain a partial private
artifact marked failed; no rollback/deletion is attempted.

## Locale carry-forward

Prior worker1/2/8 stderr explicitly showed Bash:
`setlocale: LC_ALL: cannot change locale (C.UTF-8): No such file or directory`.
The exact sandbox does not stage locale archives. Fixture LANG/LC_ALL now use
the guaranteed C locale, with PYTHONUTF8=1 for Python doubles. Production
isolated Python additionally uses explicit `-X utf8` (since -I ignores Python
environment overrides). This preserves Unicode without installing/staging a
locale or suppressing stderr. The global sandbox environment/runtime policy
was not broadened.

## Verification actually performed (static only)

The following standalone stdlib-only command read source as data. It did NOT
import the repo, invoke a helper, run tests or execute a product/backend:

```sh
python3 -I -B - <<'PY'
import ast
import json
from pathlib import Path
import subprocess
paths = [Path('CyberSecurity-Framework/00_Config/lib/consent') / name for name in ('__init__.py', 'files.py', 'cleanup.py', 'cleanup_cli.py')]
paths += [Path('CyberSecurity-Framework/tests') / name for name in ('cross_module_fixture.py', 'test_cross_consent.py')]
for path in paths:
    ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    print('AST OK', path)
manifest = json.loads(Path('CyberSecurity-Framework/tests/automation_sandbox_sources.json').read_text())
assert len(manifest['files']) == len(set(manifest['files']))
for path in paths[:4]:
    assert str(path) in manifest['files']
print('JSON OK source allowlist; no duplicates; four consent sources included')
result = subprocess.run(['/bin/bash', '-n', 'CyberSecurity-Framework/06_PostExploitation/cleanup/logs_cleaner.sh'], capture_output=True, text=True)
print('BASH -n rc=' + str(result.returncode), 'stdout=' + repr(result.stdout), 'stderr=' + repr(result.stderr))
assert result.returncode == 0 and result.stderr == ''
PY
```

Result rc0: six `AST OK` lines (four package sources, fixture, test module),
`JSON OK source allowlist; no duplicates; four consent sources included`,
`BASH -n rc=0 stdout='' stderr=''`. Stderr was explicitly captured/checked,
not discarded. `git diff --check` also returned0/no output before commit.
Git reads/diff/status and scoped staging/commit were used. Commit hooks were
disabled for this invocation (`git -c core.hooksPath=/dev/null -c commit.gpgsign=false
commit ...`) to avoid running unreviewed hooks under the strict static gate;
no persistent Git configuration was changed.

Self-review covered every changed source/diff, parser-before-effect ordering,
exact plan order, immutable interfaces, link/special refusal, descriptor lifetime,
exclusive publication, stderr/result semantics, manifest additions and scope.
The added assertions remain under the same four authorized case identities;
no new case IDs, permissions or weakened baseline expectations.

## Pending gates / NOT RUN on 3889cd9

All four cleanup cases, expanded assertions, the rest of `--cross-consent`,
and `--suite` are **NOT RUN** on the new SHA. RED was not replayed and GREEN
is not inferred from AST/syntax. Independent reviewer/controller must inspect
the privilege tradeoff, procfd semantics, source allowlist and synthetic tests.
Only after new exact authorization may the controller run:

`python3 -I -B CyberSecurity-Framework/tests/automation_sandbox_launch.py --cross-consent`

That prospective command is NOT authorization from this report. Cleanup's
expected outcome requires runtime observation; Burp/UI failures remain explicit
until later tasks. `--suite` needs separate authorization. Do not close Task2
functionally, Task9/global09 or the consent block on this static delivery.

## Refinement1 — M1/M2 coverage amendments, STATIC / runtime NOT RUN

Base: `7630b163edcc4d39f356bbea2f837731cffe1c9e`. Read the full independent
`task-2-static-review.md`: static spec PASS / quality APPROVE WITH NITS, no
Important/Critical findings. Controller requested both minors before runtime.
Only `tests/test_cross_consent.py` and this report change in this refinement;
production sources, source/runtime manifests, fixtures, selection and grants
remain unchanged. No subagents or artifact deletion.

**M1**, existing `test_cleanup_requires_both_flags`: public both-flags launch
now asserts the synthetic `.bash_history` is empty and no recorded backend is
sudo. Its rc1 comment now identifies missing/inaccessible fixed system logs,
not sudo refusal (superseding the historical comment discussion above).
Assertions require exactly four failed rows, one per fixed log, successful
history routing and truthful partial-result text. Existing remote-session,
snapshot privacy and prior-artifact preservation assertions remain.

**M2**, existing `test_cleanup_nonexecution_is_inert`: exact `LIMPIAR LOCAL`
TTY input reaches production `cleanup_cli.main(['--execute'], ...)`, production
planning/iteration/results and exclusive snapshot publication. Only
`ops.perform` is replaced by a recorder returning synthetic snapshot bytes;
no consent/parser/apply/result functions are mocked. Standard HOME is scoped
to the new synthetic fixture; stdin/stderr TTY and stdout are stream doubles.
The test asserts all seven operations in exact order/destinations, one UUID
child0700, snapshot0600/content, seven real success rows and rc0, with no remote
session disclosed and no backend calls. Despite stale global yes variables,
later EOF/no/generic-yes invocations must return2 without additional operations
or filesystem changes: prior success does not grant subsequent permission.
This is written coverage, NOT evidence of executed TTY acceptance.

### Actual static command and output

```sh
python3 -I -B - <<'PY'
import ast
from pathlib import Path
import subprocess
path = Path('CyberSecurity-Framework/tests/test_cross_consent.py')
current = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
base_text = subprocess.check_output(['git', 'show', '7630b16:' + str(path)], text=True)
base = ast.parse(base_text, filename='7630b16:' + str(path))
def case_names(tree):
    return sorted(node.name for node in ast.walk(tree)
                  if isinstance(node, ast.FunctionDef) and node.name.startswith('test_'))
assert case_names(current) == case_names(base)
assert len(case_names(current)) == 9
print('AST OK CyberSecurity-Framework/tests/test_cross_consent.py')
print('Existing test method IDs unchanged: 9')
PY
```

Exit0, stdout exactly:

```text
AST OK CyberSecurity-Framework/tests/test_cross_consent.py
Existing test method IDs unchanged: 9
```

`git diff --check` returned0/no output. Git diff inspection/self-review checked
the two amended methods against the unchanged production parser/operation
interface and reviewer requirements. No Bash source changed; no Bash or product
execution was needed for this amendment. No repository import/helper/test/probe/
launcher/backend was executed; the Python command above parses source as data
and invokes only read-only Git for the base text.

### Pending independent re-review and exact runtime gate

**All amended tests remain NOT RUN on this refinement's commit.** Static AST
parsing and unchanged method names do not establish functional acceptance or
runtime isolation compatibility. Independent static re-review must precede
any fresh exact controller authorization. Prospective test command, NOT RUN
and not authorized by this report:

`python3 -I -B CyberSecurity-Framework/tests/automation_sandbox_launch.py --cross-consent`

No broader suite or direct unittest command is substituted. Burp/UI RED and
Task2 functional/Task9/global gates remain pending. Refinement status:
DONE_WITH_CONCERNS (runtime gate and independent static re-review outstanding).
This tests/report amendment is recorded by its scoped Git commit; it does not
alter or supersede any preserved historical runtime receipt.
