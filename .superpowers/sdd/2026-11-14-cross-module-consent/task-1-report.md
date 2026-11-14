# Task1 — closed cross-consent infrastructure / STATIC NOT RUN

Date: 2026-11-14. BASE: `96cc823`. Detached HEAD, existing linked worktree.
Status: **DONE_WITH_CONCERNS — static delivery only**. Independent static review
and controller authorization remain mandatory. No production defect is declared
fixed, no RED/GREEN was observed, and no isolation/runtime compatibility is certified.

## Commits / tests-first evidence

- `24297e8`: all four requested boundary methods and all nine downstream methods
  written and committed **before** selection/fixture/worker/runtime implementation.
- `81752e1`: closed selection, fixture, grant integration, runtime manifests and
  static-review test refinements. Existing preservation inventory unchanged.
- This report is committed separately after the implementation commit; its SHA
  is the final handoff commit. No merge, push, branch switch or worktree cleanup.

TDD deviation expressly required by the controller: tests-first **NOT RUN**,
not an observed RED. Subsequent assertion refinements also remain NOT RUN.
No repository import, test discovery, helper, launcher, probe, product frontend
(including help), backend, GUI, sudo or network operation was executed.
No subagents/reviewers were dispatched. The author reviewed the full relevant
diff; this is **not** the independent static review.

## Interfaces and authority

- `cross_module_selection.group_cases(selector: str) -> tuple[str, ...]` accepts
  **only** `--cross-consent`, validates the adjacent fixed JSON against literal
  reviewed constants, returns the ordered nine full IDs below.
- `group_grants(selector: str) -> frozenset[str]` returns exactly those nine,
  never the union with09 or grants for later plans.
- `validate_cases(selector, cases)` rejects empty, changed, missing or duplicate
  loaded IDs. unittest loader `_FailedTest` IDs therefore fail validation before
  any case fork; missing downstream cores fail **inside methods** as real errors.
- `automation_sandbox_inside.validated_selection() -> str | None` reads only
  `_SELECTION`, set after successful boundary probes, checked against genuine
  diagnostic context. Entry resets it; no environment/test argv permission token.
- `automation_suite_selection.case_disposable_allowed(case_id: str) -> bool`
  checks the fixed inside controller identity and validated state. `--suite` and
  `--races` retain their exact historical25 authorization; cross uses only nine.
- Worker rechecks selector/ID/grant before scratch/fork. `configure_worker`
  repeats the selection-bound decision after Landlock, including exact cross
  membership. Root pin, root exclusion, foreign-case exclusion and `/source` /
  `/evidence` mutation rejection remain in place.
- `CrossModuleFixture(group: str)` exposes `repo`, `framework`, `home`, `bin`,
  `records()` and `run_leaf(relative, args=(), stdin='')`. It requires the current
  granted Landlock worker and matching controller selection. No host fallback.
  Extra test-only helpers: `snapshot`, `stub`, `set_session`, `run_menu`,
  `record_coordinator_leaves`. No close/finalizer/deletion of fixtures or outputs.

## Exact case IDs / grants

Each of these **nine full IDs** is both selected and granted exclusively for
new synthetic intermediate objects inside its pinned current-case scratch:

1. `test_cross_consent.ConsentTests.test_cleanup_nonexecution_is_inert`
2. `test_cross_consent.ConsentTests.test_cleanup_requires_both_flags`
3. `test_cross_consent.ConsentTests.test_cleanup_local_plan_and_partial_failure`
4. `test_cross_consent.ConsentTests.test_cleanup_refuses_links`
5. `test_cross_consent.ConsentTests.test_burp_open_is_not_network_consent`
6. `test_cross_consent.ConsentTests.test_burp_status_has_no_side_effects`
7. `test_cross_consent.ConsentTests.test_burp_verify_explicit_url`
8. `test_cross_consent.ConsentTests.test_burp_stop_pins_owned_identity`
9. `test_cross_consent.ConsentTests.test_menu_cancel_and_coordinator_exclusions`

`cross_module_cases.json` closed schema: `version: 1`,
`selector: --cross-consent`, `case_ids: [the ordered nine above]`, and:

```text
grant = explicit-user-new-synthetic-disposables-only
scope = registered-current-case-fixture-only
required_observer = landlock-abi3-current-case-worker
disposable_states = new-synthetic-intermediate-states
```

No IDs were added to `automation_preservation_cases.json`; its bytes are
unchanged from BASE. Other new25-plan grants are NOT enabled here.

Four unprivileged contracts added to existing UNIT_MODULES discovery:

- `test_automation_sandbox_boundary.SandboxBoundaryTests.test_cross_selector_is_closed`
- `test_automation_sandbox_boundary.SandboxBoundaryTests.test_cross_grants_are_selection_bound`
- `test_automation_sandbox_boundary.SandboxBoundaryTests.test_cross_root_and_protected_paths_remain_blocked`
- `test_automation_sandbox_boundary.SandboxBoundaryTests.test_suite_excludes_cross_modules`

These use doubles for authority/metadata and blocked-fork assertions; they do
not fork, install isolation rules or add probes. They cover unknown selectors,
changed/missing/duplicate IDs, crossed09 grants, false grants, substituted roots,
protected paths and the unchanged legacy discovery prefix.

## Selection and receipt flow

The only new host/inside selector is `--cross-consent`. All UNIT_MODULES execute
first. Only after unit success is the fixed nine-ID map loaded and checked for
exact ID/grant equality; no cross-module glob or arbitrary command API exists.
Every functional case uses the existing worker and `selection_outcome` aggregate.
Actual failures/errors dominate later prerequisite blocks; no missing test/core
is silently omitted or turned into PASS/SKIP.

Cross receipts: `cross-consent-sandbox-units.json`,
`cross-consent-selection.json`, `cross-consent.json` under that fresh run's
`/evidence`. Existing `probes.json`, `inside-result.json`, per-case
`case-NNNNN.{registry.json,result.json,stdout.log,stderr.log}` and unique outer
run directory are reused. Case numbering is monotonic in that controller and
each selector gets a fresh outer run, so suite/race receipts are not overwritten.

Budgets retained: host900s, boundary10s, selection600s, case60s, NPROC256;
historical races240s unchanged. Fixture leaf subprocess timeout15s is a tighter
test-local bound, not a new supervisor or isolation fallback. No changes to
Bubblewrap arguments, seccomp, mount policy, Landlock mask/rules or source RO.

## Exact fixture sources / doubles / persistent artifacts

Paths below are relative to `CyberSecurity-Framework/`. The fixture copies
exact existing sources from `/source`, checked against the source manifest,
using existing exclusive no-follow copying. No missing-source fallback.

`SOURCE_FILES` (13):

```text
06_PostExploitation/cleanup/logs_cleaner.sh
03_Scanners/web_scanners/burpsuite/burp_launcher.sh
03_Scanners/run_all_scanners.sh
06_PostExploitation/run_all_post.sh
00_Config/lib/scanners_menu.bash
00_Config/lib/postexploitation_menu.bash
00_Config/lib/scanner_runtime.bash
00_Config/lib/scans.bash
00_Config/lib/session.bash
00_Config/lib/postexploitation_runtime.bash
00_Config/lib/web_target.bash
00_Config/lib/prompt.bash
00_Config/lib/params.bash
```

`COORDINATOR_LEAVES` (12):

```text
03_Scanners/network_scanners/nmap/nmap_smart.sh
03_Scanners/network_scanners/masscan/masscan_scan.sh
03_Scanners/web_scanners/nikto/nikto_scan.sh
03_Scanners/web_scanners/nuclei/nuclei_scan.sh
06_PostExploitation/privilege_escalation/linpeas.sh
06_PostExploitation/privilege_escalation/suid_check.sh
06_PostExploitation/privilege_escalation/capabilities_check.sh
06_PostExploitation/privilege_escalation/cron_check.sh
06_PostExploitation/credential_access/linux_creds.sh
06_PostExploitation/credential_access/history_parser.sh
06_PostExploitation/loot/file_collector.sh
06_PostExploitation/loot/screenshot_collector.sh
```

The coordinator test archives these copied leaves plus copied Burp/cleaner as
`.retained-source` before installing inert dispatch recorders in their place.
It exercises real coordinators, not the real sensitive leaves. Other functional
tests exercise real leaf/core consent/result logic with operation/transport
doubles only. `files.truncate_regular` will exercise real file handling solely
on newly created synthetic files, links, directory and FIFO.

All backend doubles are NEW files in the case fixture bin: `curl`, `ss`, `sudo`,
`burpsuite`, `sleep`, `last`, `xdotool`, `xwininfo`, `whoami`, `record-dispatch`;
the coordinator test additionally creates `nmap`. Sudo always refuses; doubles
never delegate to real binaries. Curl records argv and returns a synthetic200;
ss simulates a listener after initial observation, without sockets.

PATH is only the new fixture bin plus `/usr/bin:/bin` **inside the fixed staged
runtime**, never host PATH. HOME, history sentinel, scope, targets and optional
session are created from literal synthetic data. No original configuration,
session, evidence, notes, credentials or bodies were read. Product source code
named `session.bash` is source, not persisted session data.

`harness-output/<invocation>/` retains stdout/stderr/argv/rc. `processes.jsonl`
retains double calls. Snapshots examine only this new synthetic tree, excluding
the fixture's own receipts. No artifact deletion or finalizer is registered;
unittest cleanup only removes temporary **in-memory** sys.path entries.

## Minimal downstream contracts chosen for Tasks2–4

No downstream production files were created or modified. Proposed helper imports
remain inside test methods. Later tasks must explicitly add their newly existing
consent sources to BOTH fixture SOURCE_FILES and sandbox source manifest; no
placeholder modules or automatic directory copying are allowed.

Where the plan left types/transport details open, the tests choose:

- `consent.files.truncate_regular(path: Path)`: real no-follow regular-file
  truncation; link/directory/FIFO raises OSError/ValueError, preserving referents.
- `CleanupOps.perform(operation, report_root)`: the only operation transport
  injection; apply_cleanup owns consent-independent plan iteration/result policy.
  Result `.rc` and `.operations` contain per-row `.success: bool` and `.error: str`.
  Seven plan entries: four fixed logs, history, child-history, snapshot; exact
  paths/kinds asserted literally in tests. Failed syslog operation remains visible
  with rc1 and remaining per-operation results.
- Burp receipt `instance.json`: version1, instance_id, pid, start_ticks, uid,
  boot_id; private instance directory and0600 receipt. BurpOps transport methods:
  identity(pid)->dict, pidfd_open(pid)->fd, pidfd_send_signal(fd, signal),
  wait(fd, timeout)->bool (False means still alive), close(fd). Stop observations
  assert identity→pin→revalidate→TERM→wait5→KILL(same fd)→close, with forged,
  reused, legacy and unavailable-pidfd rejection. No real process receives a signal.
- Verification argv literal: `--request GET --max-time 5 --noproxy '' --proxy
  http://127.0.0.1:8080 --output /dev/null --write-out '%{http_code}' -- URL`.
  Query secrets must not appear in frontend diagnostics. Missing independent
  flags, userinfo, controls, missing scheme and out-of-range port are negative cases.
- Menu06.7 test chooses submenu2 for explicit local application, no/EOF cancels;
  menu03.6.2 takes URL, port and separate consent. The recorded manager dispatch
  uses `--prepared` followed by public leaf flags. Opening03.4 does NOT carry
  network flags. These are minimal test contracts for later consumers, not Task1
  production behavior or a newly authorized operation.

## Files changed / manifest reconciliation

All implementation paths are under `CyberSecurity-Framework/tests/`:

- NEW: `cross_module_selection.py`, `cross_module_cases.json`,
  `cross_module_fixture.py`, `test_cross_consent.py`.
- Selection/boundary: `automation_suite_selection.py`, `automation_case_scope.py`,
  `automation_case_worker.py`, `automation_sandbox_inside.py`,
  `automation_sandbox_launch.py`; `automation_test_guard.py` docstring only.
- Manifests/runtime: `automation_sandbox_sources.json`,
  `automation_sandbox_manifest.json`, `automation_sandbox_prepare.py`.
- Existing contracts: `test_automation_sandbox_boundary.py`,
  `test_automation_sandbox_prepare.py`, `test_automation_sandbox_policy.py`,
  `test_automation_landlock.py` (outcome consumer now includes cross label).
- This report is the only additional documentation artifact committed.

Source manifest adds exactly the four NEW paths above:261→265 entries. Existing
production sources were already staged; no placeholders, operator data, later
group tests or future production packages were added. Only cross JSON was added
to `_SOURCE_DATA`. No source baselines were refreshed. BASE comparisons confirm
`automation_preservation_cases.json`, `automation_operational_baseline.json`, and
`automation_sandbox_policy.py` unchanged.

## Runtime ordinary sources / static provenance

Manifest adds exactly these five source→destination pairs, identically bound
in `CROSS_RUNTIME`; no real curl/ss/sudo/Burp or generic host directory:

```text
/usr/bin/mawk  -> /usr/bin/awk
/usr/bin/cut   -> /usr/bin/cut
/usr/bin/seq   -> /usr/bin/seq
/usr/bin/sleep -> /usr/bin/sleep
/usr/bin/tee   -> /usr/bin/tee
```

Preparation requires exact no-follow regular root-owned executable sources,
no setid/group-or-other write, stable named metadata, no new canonicalized alias.
Missing/invalid files block; existing static ELF closure/resolution and staged
identity/hash reconciliation remain mandatory. No loader/ldd/version command.

File-only inspection observed all five root-owned0755 regular files. DT_NEEDED
closure is eight exact files: mawk needs libm/libc; other four need libc; libm
needs libc/loader; libc needs loader; loader has no dependencies. Interpreter
is `/lib64/ld-linux-x86-64.so.2`, canonical
`/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2`. No RPATH/RUNPATH or dynamic
filter/audit dependency tags observed in this closure.

SHA256 observations (ordinary runtime/source-dependency data, NOT executed):

```text
/usr/bin/mawk  094cdcbd065029bf296201180c2ca69fa4ce61b06f61d09d2c70a01800d99a80
/usr/bin/cut   9d291e430710678aa8e0d72f3d17b0a26eb58c748b9cec34c8dcccaa533cf334
/usr/bin/seq   5ed4a159e8f6e05ae77d401f3ae569b9fe2943beba85535e265bf7a4617f4565
/usr/bin/sleep 83c0db85657e2cd1799b5e113317252d7865dd78157148d8757fab0ede52b1db
/usr/bin/tee   16eff7ee37b38d7154bdeb78ed4820b66767a00b3d97101d16cf3eb8e37dc653
/usr/lib/x86_64-linux-gnu/libm.so.6
  00fad4dad07623ce38fb65d3289d203316b2405bd20389d2cf87cd08d61a9f98
/usr/lib/x86_64-linux-gnu/libc.so.6
  d43c8fe19b66c7f8685119c3723d01329e8b4e93323a6494b5d0780e944b3ee5
/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
  e86468e559f821b104c633ade3ead2e4c790b0b65644014f6bc3a87b5594dc01
```

These are current documentary observations, not pinned universal package hashes;
the actual preparer/closure/launcher have NOT RUN.

## Static commands / real results

Only Git, ordinary source reads, standalone stdlib data parsing and Bash syntax
checking were used. Inline `python3 -I -B - <<'PY'` commands imported only stdlib,
not repository modules; complete command bodies/output are in this session's
tool transcript. Their operations/results:

1. `git status --short` and `git rev-parse --short HEAD`: initially clean,96cc823.
2. `git diff --check`, then `git diff --cached --check`: rc0, no diagnostics.
3. Inline `ast.parse` of all14 changed Python sources and `json.loads` of four
   manifests: rc0. Last preimplementation-commit repetition also rc0.
4. Inline AST/JSON-only ID comparison: exactly nine ConsentTests, all four
   required boundary methods, disjoint unchanged25 inventory. Source paths265
   unique/existing; fixture13+12 exact paths belong to source manifest: rc0.
5. AST-only constant extraction of both run_menu drivers (no fixture import or
   builder execution); `subprocess.run(['/bin/bash', '-n'], input=literal_driver,
   text=True, capture_output=True)` for each: rc0, **empty stderr**. Neither
   driver was run, sourced, nor used to invoke a leaf.
6. Separate inline stdlib struct/pathlib/hashlib inspection of only the exact
   five runtime files and their transitive canonical ELF dependencies: rc0;
   eight regular root-owned files and the dependencies/hashes above. No runtime
   target executed, no repository ELF resolver imported.
7. `git diff 96cc823 --exit-code --` followed by the exact three unchanged paths
   listed in manifest reconciliation: rc0, empty diff.
8. `git diff 96cc823 -- <changed infrastructure/manifests>` and
   `git diff --cached -- <new selection/fixture/downstream tests>` reviewed.
9. Commits used `git -c core.hooksPath=/dev/null commit ...` so no repository
   hook/helper ran incidentally.

**Runtime suite, RED, GREEN, probes, launcher, all product/backends: NOT RUN.**
No test counts, runtime receipts or green safety claims are fabricated.

## Concerns, deviations and next gate

- Controller-approved safety gate overrides generic skills' runtime instructions,
  reviewer dispatch and workspace deletion. Tests-first is evidenced by24297e8,
  but it is not experimentally validated TDD until controller-authorized runs.
- Independent static review must assess the COMPLETE range from96cc823 through
  final report SHA, including fixture/stubs/ID checks/manifests/runtime provenance.
- Then controller must separately authorize exact commands: first existing
  `python3 -I -B CyberSecurity-Framework/tests/automation_sandbox_launch.py --suite`,
  then the same path with `--cross-consent`. These are proposed gate commands,
  **not authorization** and not commands executed by this agent.
- Future consent core files are intentionally absent: later tasks must add their
  actual sources explicitly; absent imports currently remain observable method
  errors. Nine functional cases are expected to expose missing behavior, but no
  particular RED outcome is claimed without a run.
- Minimal newly chosen operation/receipt/menu contracts above need downstream
  consumers to follow or explicitly reconcile them under review. They do not
  authorize production bypasses or system-destination overrides.
- Existing limitations remain: ABI3 metadata/ioctl gaps, no hostile-kernel or
  realtime/cgroups-per-tree certificate, no Windows/Docker/operational Burp
  compatibility, no legal custody, no Task9/global closure or whole-branch green.
- Fixtures, receipts/logs, previous runs and operator artifacts remain preserved;
  no cleanup/install/download/GUI/network/sudo/merge/push occurred.

## Fix round1/5 — FIX_BASE52b2fda — STATIC NOT RUN

Requested review: `task-1-static-review.md`, Important **I1/I2/I3** and Minor
**M1**. User ruling includes M1 in this round; none of these findings is deferred.
This section supersedes the earlier incomplete exception-retention description
and refines the still-unimplemented downstream contracts below. Earlier report,
review, commits and artifacts are preserved, not rewritten or removed.

Status: **DONE_WITH_CONCERNS, source corrections delivered for independent static
re-review only**. No observed RED/GREEN, test pass, runtime receipt or independent
approval is claimed. All runtime/TDD execution remains **NOT RUN**.

### I1 — remote-session menu cancellation and explicit local dispatch

Covering existing ID:
`test_cross_consent.ConsentTests.test_menu_cancel_and_coordinator_exclusions`.

- New cancellation fixtures contain the literal NEW session
  `remote.example.test`. Cleanup sequences explicitly enter06.7 application
  option2 before `no`, EOF or `0` at the local application confirmation. Separate
  submenu0 and Burp cancellation variants remain covered.
- The shared `ask_confirm` input/UI double marks an actual confirmation request
  with `CONSENT_PROMPT:` and preserves its question. Application-cancellation
  variants require a LOCAL-marked confirmation question, not merely a return to
  the parent menu. Thus the supplied `no`/EOF/0 reaches a confirmation request.
- Cancellation may dispatch no cleaner at all, or only the exact inert
  `--prepared --preview` dispatch. An unflagged historical cleaner dispatch,
  any application flags, session-derived argument or unrelated dispatch fails
  the oracle; scanner cancellation permits no leaf dispatch.
- Accepted local application still requires exactly one dispatch with only
  `--prepared --execute --confirm-local-cleanup`. The session is not an argument.
- Both rejected and accepted local flows assert session bytes/mode unchanged
  and equality of the entire synthetic-tree snapshot (excluding harness output
  and backend-call log). Snapshot now also compares inode/device, size,
  mtime/ctime and link count, not just bytes/mode. No actual menu leaf executes:
  only the real menu's dispatch/consent logic plus inert dispatch transport.

### I2 — configurable listener transport, identity and public stop gate

Covering existing IDs:

- `test_cross_consent.ConsentTests.test_burp_open_is_not_network_consent`
- `test_cross_consent.ConsentTests.test_burp_status_has_no_side_effects`
- `test_cross_consent.ConsentTests.test_burp_stop_pins_owned_identity`

`CrossModuleFixture.configure_ss(responses)` now stores a nonempty sequence of
literal stdout strings as an exclusive NEW0600 JSON transport file under harness
output. The ss double selects by prior ss-call count and repeats the last response.
Defaults retain free-first/listener-later behavior; occupied-port cases explicitly
return a realistic ss header and listener **on the first observation**. The
`CROSS_SS_RESPONSES` environment value is only a scratch data-file path consumed
by the double: no permission token, product override, host fallback or socket.

The open case supplies a foreign synthetic owner/PID as response data, requires
occupied-port rejection before GUI/curl, and requires explicit unknown ownership
and unverified capture. Status cases supply an occupied listener without an
administrative identity (including legacy and missing-ss cases); they require
unknown ownership/unverified capture and reject positive Burp/capture attribution
across stdout AND stderr. The numeric foreign PID is never signalled or adopted.

Stop Ops now independently varies UID and boot ID, both before pinning and in
the pin→revalidation interval. Every mismatch must reject without a signal.
Existing start-tick, forged-instance, legacy, absent-pidfd and same-fd signal
assertions remain. No identity/process transport double delegates to the OS.

The public wrapper is tested without `--execute` and without any stored PID:
rc2, no backend calls, unchanged synthetic tree. A second test calls the SAME
public argument-parser entry with a real synthetic receipt and injected Ops:
missing `--execute` returns2 without even observing/signalling a process; adding
`--execute` returns0 with the literal pin/revalidate/TERM/wait5/KILL/close sequence.
All accepted stop transport is injected; no actual process receives a signal.

### I3 — retain invocation evidence before launch and on exceptions

Covering existing ID:
`test_cross_consent.ConsentTests.test_cleanup_nonexecution_is_inert` (additional
focused fixture-transport assertions inside this same ID, no new grant).

`_run` now exclusively allocates its0700 invocation directory,0600 `argv.json`
and `started.json`, and exclusive0600 stdout/stderr files **before subprocess
launch**. Streams go directly to retained files rather than memory-only capture.
An exclusive final `result.json` is attempted in `finally`, recording:

- `DONE`, argv and actual returncode on normal completion (including nonzero rc);
- `TIMEOUT`, timeout15, null returncode and error type on TimeoutExpired;
- `LAUNCH_ERROR`, null returncode, errno and error type on OSError;
- `INTERRUPTED` and error type for other unwinds when Python/E/S permits.

Timeout/launch exceptions are re-raised, never converted to success or retried.
Normal callers still receive CompletedProcess with retained stdout/stderr text.
No process supervisor, new Popen path, fallback, budget increase or cleanup was
introduced: the existing subprocess.run15s bound and existing worker/outer
supervision remain. No receipt is promised after KILL or impossible E/S.

Written transport-double assertions cover DONE(rc7), timeout and launch failure:
argv/start/stream artifacts must already exist when transport is invoked; partial
stdout and stderr, final state/rc and private modes must remain afterward. A
forced invocation-number collision must fail before transport and preserve all
previous artifact bytes. These assertions DO NOT launch a real timed-out child,
run any product leaf or add a supervisor.

### M1 — pure plan and private/exclusive report output

Covering existing IDs:

- `test_cross_consent.ConsentTests.test_cleanup_local_plan_and_partial_failure`
- `test_cross_consent.ConsentTests.test_cleanup_requires_both_flags`

Pure plan now has full synthetic before/after snapshots around `plan_cleanup`.
The operation adapter must receive a business-allocated0700 per-invocation child
of the synthetic `scans/cleanup` root; it does not allocate that directory itself.
Child-history transport clears only a synthetic in-memory child-history list.
Snapshot transport returns literal bytes; BUSINESS must exclusively publish them
as0600 `last_access.txt` inside the new per-invocation report directory.

Core application is requested twice: distinct UUID report directories are
required; the previous report's bytes/mode/device/inode must remain unchanged.
The existing partial-syslog-failure oracle remains rc1 with truthful seven-row
results. A preexisting synthetic UUID report is also preserved. The public cleaner
case checks exactly one NEW UUID directory,0700 directories/0600 regular output,
the last-double snapshot bytes, and prior report bytes/mode/inode unchanged even
when synthetic sudo refuses operations. None of this reads actual system logs.

### Explicit reconciliation for downstream Tasks2–4 (not implemented here)

These refinements replace only the earlier underspecified test-internal details;
they do not add public modes, source placeholders, grants or system-path overrides:

1. `apply_cleanup(plan, report_root, ops)` interprets report_root as the
   `scans/cleanup` BASE, exclusively allocates a fresh UUID child before operation
   execution, passes that child to `ops.perform`, and exposes it as
   `CleanupResult.report_dir: Path`. `perform(snapshot, child)` returns `bytes`;
   core owns exclusive/private `child/last_access.txt` publication. Other
   operation transports return None or raise; existing rc/operation rows remain.
2. `consent.burp_cli.main(argv, *, framework: Path, ops: BurpOps) -> int` is the
   public parser/dispatch function, with an internal injectable process adapter.
   Missing public execution consent returns2 BEFORE effects. Production wrapper
   and tests use that parser; dependency injection is a Python interface only,
   not an environment/CLI test flag, arbitrary destination or production bypass.
3. Unknown listener observation renders `Propietario: NO_DETERMINADO` and
   `Captura: NO_VERIFICADA`; opening an explicitly occupied port also renders
   `Puerto ocupado: 8080` for this input and returns nonzero without GUI/curl.
   This is a negative ownership/capture result, not an operational certificate.
4. Cleanup menu option2 is explicit local application; the LOCAL-specific
   confirmation uses the existing shared ask_confirm UI/input boundary. Rejecting
   that confirmation cannot become an unflagged cleaner call. Automatic inert
   previews are accepted in cancellation paths only with the literal preview
   flags. Accepting local application dispatches its two leaf flags only.

All consent production packages are STILL absent intentionally. Later tasks must
explicitly stage/copy their actual files, reconcile these documented APIs under
review, and retain missing-module failures inside methods until implemented.

### Scope, static commands and actual output

Only `CyberSecurity-Framework/tests/test_cross_consent.py`,
`CyberSecurity-Framework/tests/cross_module_fixture.py` and this append-only report
changed in this round. Source/runtime manifests, exact nine IDs, historical25,
selector/worker/scope/supervision/budget policies and source allowlists are unchanged.

Real commands executed (only source/Git/data parsing and permitted Bash syntax):

- `git status --short`: initially empty.
- `git diff --check`: rc0, empty output.
- `git diff 52b2fda --stat`: focused two-file diff before report append.
- `git diff 52b2fda --exit-code --` followed by the exact paths
  `cross_module_cases.json`, `cross_module_selection.py`,
  `automation_preservation_cases.json`, `automation_sandbox_sources.json`,
  `automation_sandbox_manifest.json`, `automation_sandbox_policy.py`,
  `automation_sandbox_inside.py`, `automation_sandbox_launch.py`,
  `automation_case_worker.py`, `automation_case_scope.py`,
  `automation_suite_selection.py` under `CyberSecurity-Framework/tests/`:
  rc0, empty output (all unchanged).
- Standalone inline `python3 -I -B - <<'PY'` imported only stdlib ast/json/
  subprocess/pathlib. It ast.parsed both changed sources; compared the nine
  method IDs to fixed JSON; ast.literal_eval-compared source allowlists to
  `git show 52b2fda:CyberSecurity-Framework/tests/cross_module_fixture.py`;
  extracted generated strings with a CLOSED AST-data visitor (only constants,
  string addition, bound literal names/log path and repr/str of those data).
  It ast.parsed eleven generated backend strings; passed sixteen literal menu/
  recorder variants to `/bin/bash -n` with captured stderr. No builder/helper was
  imported or invoked, and no extracted string was executed/sourced.

Actual output of the final expanded static parsing command:

```text
AST OK: 2 changed Python sources; no repository imports
IDs OK: exact 9 existing authorized methods
Fixture source allowlists identical to FIX_BASE: 13 + 12 paths
AST-extracted Python backend strings: 11 parse OK, none executed
Bash -n AST-extracted drivers/recorders: 16 rc0, empty stderr, none run/sourced
STATIC ONLY; all repo helpers/imports/tests/launchers/probes/product/backends and RED/GREEN NOT RUN
```

Source/diff self-review performed after edits. Tests were strengthened BEFORE the
fixture implementation edits in this fix round; no failing/passing test execution
is claimed. Fix is committed with repository hooks disabled, preserving previous
commits/evidence. Independent static re-review of this exact fix SHA, then separate
controller authorization of --suite and --cross-consent, is STILL REQUIRED.

Final inline `python3 -I -B - <<'PY'` data-only scope check used Git name listing,
AST parsing, JSON ID count and a bytes-prefix comparison against the report at
FIX_BASE; rc0, output:

```text
Final static scope: exact 2 Python sources + appended report; original report bytes preserved
Final AST: 2 OK; fixed grant inventory: 9 IDs; tests/runtime/TDD RED/GREEN NOT RUN
```

Bookkeeping: the first explicit `git add` returned1 with an ignored-parent warning
for `.superpowers/sdd/...` although status showed all three exact tracked files
staged. `git ls-files --error-unmatch` confirmed the report is tracked. No commit
ran on that failed command chain; explicit report staging and staged diff checks
precede the final commit. No file was removed, reset or discarded.
