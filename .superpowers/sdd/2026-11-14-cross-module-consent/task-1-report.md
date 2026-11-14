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
