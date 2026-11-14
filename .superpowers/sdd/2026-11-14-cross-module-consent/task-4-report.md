# Task4 — consent menus/docs/integration: STATIC DONE_WITH_CONCERNS

Date: 2026-11-14. Base: `316d70d`. Implementation: `b9841ae`.
Fixture fidelity follow-up: `c6b7eb4`. This report is a subsequent doc-only commit.

**Amended tests NOT RUN. Independent static review and exact controller runtime
authorization remain required. No Task4/block/Task9/global closure or GREEN claim.**
No imports/helpers/tests/probes/launcher/product/backends, even stubs, were run.
No agents/reviewers, GUI, network, sudo, install/download, cleanup, merge, push,
reset, or artifact deletion. No operator config/keys/evidence/notes were read.

## Inputs and prior RED (data only)

Read task-4-brief first, task-1-context intro/global constraints/menu contracts,
binding design §§5/6/12–14, Task2 report including no automatic sudo/current
credentials/partial failure, and Task3 report including its fix appendix.
The appendix's **curl --disable FIRST** contract supersedes its historical argv.
Tasks1–3 APIs/policy implementations were consumed, not reimplemented.

Read only the controller's synthetic `cross-consent.json` and
`case-00009.stderr.log` at:
`/tmp/opencode/automation-isolated-127731d42493465baa1a846085f93043/evidence/`.
The JSON records9 cases,0errors,1failure, no blocked/skipped; the eight cleanup/
Burp cases PASS. Ninth stderr lines7–27 shows unflagged cleaner dispatch where
`--prepared --preview` was required. This is prior RED, not this delivery's run.
Controller supplied65 sandbox units for that run. Its separate historical suite
at `/tmp/opencode/automation-isolated-33ab6d25198d41299677182577c8db91/evidence/`
was supplied as65+179,0failures/errors,1pwsh SKIP; not rerun or used to infer
amended-code acceptance. All historical receipts/artifacts remain preserved.

## Files, interfaces and source-contract provenance

Paths below are framework-relative unless prefixed `docs/`. Every implementation
change is scoped by `git diff 316d70d..c6b7eb4 -- <path>`. No baseline refresh.

| File | Intentional source/contract delta and provenance |
|---|---|
| `00_Config/lib/scanners_menu.bash` | Task4 brief/interface: retain03.0–5, add03.6 and fixed `scanners_burp_menu`; local input/validation, separate GET and stop confirmations; only reviewed public CLI flags |
| `00_Config/lib/postexploitation_menu.bash` | Task4/§5:06.7 selection, explicit preview default, LOCAL UID/impacts and application consent before both flags; all other entries and aliases retained |
| `03_Scanners/README.md` | Task3 final public CLI/argv, four Burp operations, private instances, legacy preservation, Community/ownership/daemon limits, separate runtime gates |
| `06_PostExploitation/README.md` | Task2 actual credentials/partial failure contract; preview/application, child-history limit, snapshot/legacy migration and coordinator exclusion |
| `tests/automation_menu_inventory.py` | Add data-only extraction of03/06 main and `03.burp`/`06.cleanup` namespaces via existing fail-closed source parsers; no discovery/runtime change |
| `tests/test_automation_contract.py` | Amend only existing `test_every_menu_option_explained`: exact submenu rows, flag fragments, row-deletion mutations and source replacement mutations removing known option/adding99; existing full leaf/menu inventory remains |
| `tests/test_cross_consent.py` | Amend only ninth existing ID: actual menu policy through dispatch recorders, cancellation/EOF/no, previews, GET/state/stop argv, session/synthetic-tree preservation, and local warnings; eight existing cleanup/Burp method ASTs unchanged |
| `tests/cross_module_fixture.py` | Add only already-allowlisted `cyber_framework.sh` to scratch copy for extracting actual `ask_confirm` function; do not source manager initialization. Replace prior yes/no classifier double with production function source; explicitly reject manager via `run_leaf` |
| `tests/run_tests.sh` | Replace exactly two unsafe obsolete Burp blocks with explicit non-counted migration notice mapping to four existing confined IDs; no invocation of confined runner or addition of legacy test execution |
| `docs/MENU-OPCIONES.md` | Eight row additions only, zero row removals; reconcile03.4/06.7/two leaves and99 exclusions against reviewed interfaces; no new product actions |
| `docs/MANUAL-GESTOR.md` | Same menu/gate/CLI/legacy distinction; correct old prose implying99 acquires cleanup/Burp actions instead of changing coordinator behavior |

`automation_operational_baseline.json` does not contain the edited menus/leaves/
docs/tests and remains unchanged. Source/runtime manifests, selection/case files,
worker/scope policy and the historical25 grants remain unchanged. Manager is
already an exact RO source entry: no new source allowlist, runtime, ID, grant,
selector or executable permission was added. `run_leaf` explicitly refuses the
new source-only fixture copy rather than making manager a dispatch destination.

Source hash prefixes below are SHA-256 (before316d70d → deliveredc6b7eb4);
full values were printed by actual static commands in this session. Git commits
retain exact content/diff provenance, not a blanket acceptance baseline.

| File (abbreviated as above) | Before → after SHA-256 prefix |
|---|---|
| postexploitation_menu.bash | d479c329400298df → 1128d81aabdc2782 |
| scanners_menu.bash | 51c0a379a5e33d73 → ca1fdab09180d5c3 |
| 03 README | 66e41f8cf8758abd → 997f7d9e378a723b |
| 06 README | d631d61376ca07c6 → 3f87e7345af10d73 |
| automation_menu_inventory.py | 35300626229308a1 → 7dd7406c43d42213 |
| cross_module_fixture.py | 8bc1d421c71bc708 → c3d7ad8d2560ead5 |
| run_tests.sh | 3315acc7df1a0f62 → 749cc3c9e003224b |
| test_automation_contract.py | 6c169855f2368fcd → 2423cf29408c3105 |
| test_cross_consent.py | 5a987f747a59394f → 783ccc61e93a7ec4 |
| MANUAL-GESTOR.md | 1b665d186bf26a18 → afafefe0582fdbc2 |
| MENU-OPCIONES.md | bc03f081be253eef → bafbf6231de4d0c0 |

## Options delta and capability matrix (written behavior, NOT RUN)

| Interface/capability | Before | Delivered consumer |
|---|---|---|
|03.0–3/5|Existing checks/basic/web/advanced|Unchanged entries/capabilities and original ten-script list|
|03.4|GUI open|Unchanged opening dispatch/manual guide; never grants verification permission|
|03.6|Absent|Control menu, no action merely on entry|
|03.burp.0|Absent|Return/EOF without dispatch|
|03.burp.1|Leaf status available, no guided route|`--prepared --estado`; no URL or consent flags|
|03.burp.2|Explicit leaf verification, no guided route|Explicit validated URL and proxy port, own network confirmation, `--verificar URL --proxy-port N --execute --confirm-network`|
|03.burp.3|Explicit leaf stop, no guided route|Explicit ID and own signal confirmation, `--parar --instance ID --execute`; leaf accredits own identity/pidfd|
|06.7|Unflagged dispatch|Enter/1 explicit `--preview`,0/! cancels; EOF returns without application|
|06.cleanup.2|No guided local-specific gate|LOCAL UID/four logs/history/snapshot/current-credentials warning; only acceptance passes `--execute --confirm-local-cleanup`|
|06 other entries/aliases|Escalation/credentials/loot/persistence/lateral/flow/list/viewer|Unchanged; no capability removal or new coordinator permissions|
|Coordinators/99|Burp/cleanup excluded|No source changes/new actions; exclusions still tested using inert child transport recorders|

No sensitive leaf is invoked to gather help/parameters. Preview is an explicitly
selected inert operation, not parameter discovery. URL has no session default;
cleanup never receives a session/IP destination. Rejection/EOF does not dispatch
application/GET/stop. Generic manager confirmation may still be additional; it
does not replace the specific menu consent or leaf gates. Menu stop intentionally
requires ID, whereas the reviewed leaf also permits one unambiguous new instance.

## Amended tests and legacy migration — NOT RUN

Same nine cross IDs and same12 contract test IDs. No additions/renames/skips.
Ninth cross case runs real menu dispatch/consent policy and the real manager
`ask_confirm` classifier, extracted from copied source with a unique-shape guard.
Only clear/pause and execute/list dispatch are transport doubles. No manager main
or sensitive leaf runs in that menu test. Coordinator actual exclusion logic is
unchanged and uses existing inert child recorders, not a fake coordinator.

Written assertions cover0/EOF/no at opening, URL, port, network prompt, stop ID/
prompt and cleanup prompt; explicit preview via Enter/1; accepted opening then
denied verification; exact state/GET/stop/cleanup argv; LOCAL/UID/no-sudo/child-only
history warnings; remote session bytes/mode and synthetic tree preservation.
Existing coordinator assertions and all eight cleanup/Burp test bodies remain.

Old legacy Burp tests used real socket listeners/sleeps, PATH fallback with
possible real curl, shared legacy config/PID paths and recursive scans/burp
deletion. They are not safe equivalents of the current reviewed policy. The
replacement notice does NOT count PASS/SKIP or launch tests. Coverage is mapped:
open→wrapper/config/port/guide/private instances, status→inert observation,
verify→explicit consent and exact first-argument `--disable` argv,
stop→receipt identity/pidfd/TERM/wait/KILL and artifact preservation. Obsolete
`--project-file`, shared PID deletion and capture-by-HTTP assertions are not kept
as false product requirements. Git preserves their original source. Unrelated
legacy tests remain intact and the legacy runner was **never executed**.

## Actual static commands and output

1. `git status --short`, `git rev-parse --short HEAD`: clean base316d70d.
   Scoped `git diff --stat`, `git diff -- <eleven paths>` and final fixture/test
   diff were read for self-review. No source execution through these reads.
2. Three inline `python3 -I -B - <<'PY'` commands imported only stdlib
   `ast, hashlib, json, re, subprocess, pathlib.Path` (subsets per command).
   They used `git show 316d70d:<path>`/`git diff --name-only` as captured Git
   subprocesses; parsed source data, never imported repo modules. Actual final
   checks/outputs:
   - `ast.parse(data, filename=name)` and LF assertions:4Python files OK
     (inventory, fixture, cross test, contract test).
   - `subprocess.run(['bash','-n',name], capture_output=True,text=True)` for
     both menus and legacy run_tests: each `0 '' ''` (rc/stdout/stderr).
     Stderr captured and checked, not inferred from exit status.
   - `ast.dump` comparison of test methods to316d70d:
     `UNCHANGED TEST IDs test_cross_consent.py 9 changed only ['test_menu_cancel_and_coordinator_exclusions']`;
     `UNCHANGED TEST IDs test_automation_contract.py 12 changed only ['test_every_menu_option_explained']`.
   - `json.loads` plus exact byte comparisons: `JSON UNCHANGED` for sources,
     runtime manifest, operational baseline, preservation cases and cross cases.
   - `ast.literal_eval` SOURCE_FILES comparison: only `cyber_framework.sh`
     added/no removals; exact name already in source manifest.
   - Exact byte comparisons: cross selection, suite selection, worker and scope
     `POLICY UNCHANGED`.
   - SHA-256 before/after printed for all11 source/doc paths (table above).
   - Regex/data-only row comparison: `DOC ROW KEYS 358 -> 366 eight additions/no deletions`.
     Added keys exactly03.6,03.burp.0–3,06.cleanup.0–2. Earlier data-only
     manifest-name/doc comparison printed `LEAF NAMES: exact unchanged inventory 130`.
     These are structural keys, not a semantic-coverage certificate or the old
     historical217-row review count.
   - Captured `git diff --check` and `git diff 316d70d --check`: each `0 '' ''`.
     Every inline command exited0. The final command explicitly printed
     `STATIC ONLY; no repository imports/helpers/tests/product/backends executed`.
3. Scoped staging and commits used
   `git -c core.hooksPath=/dev/null -c commit.gpgsign=false commit -m ...`
   to avoid unreviewed hook/signing execution; no persistent Git config change.

Self-review checked all changed diffs, untouched capabilities, parser/consent
ordering, no session-derived destinations/permissions, exact reviewed flags,
no parameter-discovery leaf execution, no coordinator changes, actual classifier
fixture fidelity, precise source deltas and truthful migration/limits. This is
implementer self-review, **not independent static review**.

## Remaining concerns and handoff gate

- Runtime imports, Bash prompt/EOF behavior, extraction/driver construction,
  confined execution and changed mutation oracles have not been observed on
  this code. AST/syntax/data checks are not functional GREEN.
- Full manager execute_script plumbing is not executed by the menu test: it is
  a transport recorder boundary, while production menus and confirmation policy
  remain real. Existing generic manager argument printing can expose verification
  URL/query; menu/guide warn against secrets. No end-to-end redaction claim.
- Actual GUI/Community listener/config behavior, pidfd/process-tree limits and
  hostile same-user/kernel guarantees remain as documented in Task3. HTTP code/
  occupied port is not capture/ownership proof; GUI itself may generate traffic.
- Cleanup operates with existing credentials, not automatic sudo. Partial errors
  are truthful, not grounds to retry as root. Child history never clears parent
  memory. Old snapshots/legacy Burp/PID/config/logs and all artifacts are preserved.
- No new runtime IDs/grants/selectors or global baseline update was needed.
  The25historical preservation cases and separate cross selection retain meaning.
- Next: independent whole-block static review of `c6b7eb4` plus report; only
  after exact separate controller authorizations may the controller run
  `python3 -I -B CyberSecurity-Framework/tests/automation_sandbox_launch.py --cross-consent`
  and separately the same launcher with `--suite`. These prospective commands
  are **NOT RUN and NOT authorized by this report**. Keep pwsh SKIP explicit if
  its reviewed runtime remains absent. No block/global closure, branch-green,
  compatibility/Windows/Docker/legal-custody certificate, merge or push implied.
