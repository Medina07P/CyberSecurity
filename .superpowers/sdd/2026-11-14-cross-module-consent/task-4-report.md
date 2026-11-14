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

## Final fix wave — I1 manager URL display, basee239855

Implementation commit: `039d7fb`. **STATIC DONE_WITH_CONCERNS; runtime NOT RUN.**
This appendix supersedes the earlier acceptance of generic-manager query output
as a mere warning/limitation and the earlier unchanged-manager-baseline statement.
The original delivery/history is preserved above. The full finding list in
`final-static-review.md` is exactly one Important I1, no Critical/Minor findings;
the complete review and I1 were read verbatim before editing, along with the
original Task4 brief and binding design §§5/6/12–14. No next-plan work was added.

### I1 source fix and exact scope

The review correctly traces raw `${argv[*]}` in the actual manager consumer,
before the redacting leaf. A warning about secrets did not satisfy the output
requirement. `cyber_framework.sh` now calls its own `script_arguments_summary`
display policy with the original array. For Burp it never echoes raw arguments:
verification shows GET, validated local proxy port and destination **origin**
only (scheme/host/optional port), not path/query/userinfo. Invalid/ambiguous
display input produces a constant NO_DETERMINADO summary without echoing input.
The policy's Python uses existing Python/stdlib only; no new runtime is staged.
This display calculation neither authorizes nor sends a request.

The helper consumes only its own positional arguments. The actual leaf invocation
continues to use the original `"${argv[@]}"`, unchanged. Existing PSExec credential
concealment is moved intact into the same display policy; ordinary non-Burp
display/direct-call behavior remains. Menu consent flags, public leaf CLIs,
coordinators, full inventory and all original capabilities are unchanged.

Exactly six implementation paths changed:

| Framework-relative path | I1-specific provenance |
|---|---|
| `cyber_framework.sh` | Actual output-consumer policy extraction and Burp origin-only summary; untouched backend argv |
| `tests/cross_module_fixture.py` | Extract both actual `ask_confirm` and actual display policy; source-shape/closing guards, no manager initialization. Execution recorder calls real display policy before recording the unchanged dispatch |
| `tests/test_cross_consent.py` | Only ninth existing granted method amended with literal path/query-secret and PSExec concealment oracles plus real dispatcher wiring/source assertions |
| `tests/automation_operational_baseline.json` | Exactly one existing manager SHA value changed; no other hashes/keys/version changed |
| `00_Config/lib/scanners_menu.bash` | Replace inaccurate UI warning with route/query omission plus truthful residual process-argv visibility |
| `03_Scanners/README.md` | Same narrow output-policy correction; process inspection remains a distinct limitation |

Before/after SHA-256 provenance (basee239855 →039d7fb), printed by actual static
inspection; these are source identities, not runtime evidence:

| Path | Before | After |
|---|---|---|
| `cyber_framework.sh` | `874f7a3ac11c3ade3519ad827f7832fb2cdfe5492b78bd1a62509fbfc98df223` | `67f004780ea6a9356e3e7db0370f9c90874acf5c8579b90f5c29795fec2c691f` |
| `tests/automation_operational_baseline.json` | `ea35a1e6f05db5a92d806fb912a3f3dfd6efa6479c381a2c71523544297bb30e` | `4f7ec871987f73a13af1620fea61c75673c9befa40c481c25102441c14f6e44a` |
| `tests/cross_module_fixture.py` | `c3d7ad8d2560ead559ff60940c317797346d7755a0ecdc27133335878f629ad5` | `dca5cead28c31363caee98a51ed4d29eb08acb99d917731ae65d6a3f8dffbb9c` |
| `tests/test_cross_consent.py` | `783ccc61e93a7ec45a577c86e4cbbd13988297b04709b75020fea44151009438` | `7cc413402ce2a9a960fa90ca267f39e341b2d512ac0fbb4dbd7c337644225999` |
| `00_Config/lib/scanners_menu.bash` | `ca1fdab09180d5c37ba0cf83634d4476ffa0ee010bda7c85d489b9a9040c2081` | `5eb0a7283b427669703faa099134c2ad3036a26d946fc605bd0a4a778df455cc` |
| `03_Scanners/README.md` | `997f7d9e378a723b312067167bac353f3401004c72277d4769dfcfc894fa30e2` | `ab117f4c850c101463858a9d5f8d02f273d2749e97e218637717e331c43187e4` |

The old manager pin was checked against `git show e239855:...` **before** its
single JSON-field update; the new pin was checked against actual manager bytes.
This is explicit reconciliation of the intentionally edited manager, not a
baseline refresh or removal of preservation assertions. No source/runtime
manifest, fixture SOURCE_FILES, nine IDs, historical25 grants, selector, worker/
scope policy, inventory extractor or full inventory contract was changed.

### Written regression oracles — NOT RUN

Within existing `test_menu_cancel_and_coordinator_exclusions`:

- Accept verification of the literal URL
  `https://example.test:9443/private-path-secret?token=literal-query-secret`.
  Use actual menus, confirmation classifier and manager display function; only
  display clearing/pausing and execution/list transport are doubled, not the
  output-redaction policy. Assert both stdout and stderr omit the path secret,
  query secret and `token=`; assert GET, proxy127.0.0.1:8080 and destination
  https://example.test:9443 remain visible. Assert recorder receives the exact
  unmodified URL plus original flags/positions.
- Assert actual manager `execute_script` calls the extracted display helper with
  the original array, no longer contains raw `${argv[*]}`, and still dispatches
  the original array to the shell leaf. No manager initialization is executed.
- Exercise existing PSExec menu dispatch through the same display policy and
  recorder; assert its literal password is absent on both channels, concealment
  message remains, and all five original positions/password/command are intact.
  No PSExec source/backend is executed or newly copied; this protects the
  existing credential-concealment branch affected by the display extraction.

These are amended, unexecuted oracles, not observed runtime assertions. Prior
RED/source review was not replayed. All eight other cross-case method ASTs and
the complete inventory tests remain unchanged.

### Actual static commands and outputs

Initial `git status --short`: empty at e239855. Read the complete scoped six-file
`git diff -- ...` for self-review. Two standalone `python3 -I -B - <<'PY'`
commands imported stdlib only. The first printed the old pin and newly computed
manager hash (the manager pair in the table), asserting the old pin matched
base source. The final command below was actually run before implementation
commit; no repository imports/helpers were used:

```python
import ast, hashlib, json, re, subprocess
from pathlib import Path
base='e239855'
paths=subprocess.check_output(['git','diff','--name-only'],text=True).splitlines()
for name in paths:
    data=Path(name).read_bytes()
    before=subprocess.check_output(['git','show',base+':'+name])
    assert b'\r' not in data
    print('SHA256',name,hashlib.sha256(before).hexdigest(),'->',hashlib.sha256(data).hexdigest())
    if name.endswith('.py'):
        ast.parse(data,filename=name)
        print('AST/LF OK',name)
    if name.endswith(('.sh','.bash')):
        p=subprocess.run(['bash','-n',name],capture_output=True,text=True)
        print('BASH-N',name,p.returncode,repr(p.stdout),repr(p.stderr))
        assert (p.returncode,p.stdout,p.stderr)==(0,'','')
manager=Path('CyberSecurity-Framework/cyber_framework.sh').read_text()
embedded=manager.split("<<'PY'\n",1)[1].split('\nPY',1)[0]
ast.parse(embedded,filename='manager:display-heredoc')
print('AST OK embedded display Python; not executed')
policies=''
for function in ('ask_confirm','script_arguments_summary'):
    header='\n'+function+'() {\n'
    assert manager.count(header)==1
    body,closing,_=manager.split(header,1)[1].partition('\n}')
    assert closing
    policies+=function+'() {\n'+body+'\n}\n'
p=subprocess.run(['bash','-n'],input=policies,capture_output=True,text=True)
print('BASH-N extracted policy SOURCE',p.returncode,repr(p.stdout),repr(p.stderr))
assert (p.returncode,p.stdout,p.stderr)==(0,'','')
name='CyberSecurity-Framework/tests/test_cross_consent.py'
def methods(data):
    return {n.name:ast.dump(n) for n in ast.walk(ast.parse(data)) if isinstance(n,ast.FunctionDef) and n.name.startswith('test_')}
b=methods(subprocess.check_output(['git','show',base+':'+name])); a=methods(Path(name).read_bytes())
assert len(a)==9 and a.keys()==b.keys() and {n for n in a if a[n]!=b[n]}=={'test_menu_cancel_and_coordinator_exclusions'}
print('TEST AST: nine unchanged IDs; only existing ninth body amended')
name='CyberSecurity-Framework/tests/automation_operational_baseline.json'
b=json.loads(subprocess.check_output(['git','show',base+':'+name])); a=json.loads(Path(name).read_bytes())
key='CyberSecurity-Framework/cyber_framework.sh'
assert a.keys()==b.keys() and a['version']==b['version'] and a['sha256'].keys()==b['sha256'].keys()
assert {n for n in a['sha256'] if a['sha256'][n]!=b['sha256'][n]}=={key}
assert a['sha256'][key]==hashlib.sha256(Path(key).read_bytes()).hexdigest()
assert b['sha256'][key]==hashlib.sha256(subprocess.check_output(['git','show',base+':'+key])).hexdigest()
print('BASELINE: manager hash only; keys/other hashes/version unchanged; before/after match source')
for filename in ('automation_sandbox_sources.json','automation_sandbox_manifest.json','automation_preservation_cases.json','cross_module_cases.json','cross_module_selection.py','automation_suite_selection.py','automation_case_worker.py','automation_case_scope.py','automation_menu_inventory.py','test_automation_contract.py'):
    name='CyberSecurity-Framework/tests/'+filename
    data=Path(name).read_bytes()
    if name.endswith('.json'): json.loads(data)
    assert data==subprocess.check_output(['git','show',base+':'+name])
print('UNCHANGED: source/runtime manifests, grants, cases, selectors, worker/scope, full inventory/contracts')
name='CyberSecurity-Framework/tests/cross_module_fixture.py'
def source_files(data):
    return next(ast.literal_eval(n.value) for n in ast.parse(data).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SOURCE_FILES' for t in n.targets))
assert source_files(Path(name).read_bytes())==source_files(subprocess.check_output(['git','show',base+':'+name]))
print('FIXTURE SOURCE_FILES unchanged')
p=subprocess.run(['git','diff','--check'],capture_output=True,text=True)
print('DIFF-CHECK',p.returncode,repr(p.stdout),repr(p.stderr))
assert (p.returncode,p.stdout,p.stderr)==(0,'','')
print('STATIC ONLY: no repo imports/helpers/tests/product/backends executed')
```

Final script exited0. Hash output is reproduced in the six-path table. Remaining
output: two `AST/LF OK` files (fixture/cross test); `AST OK embedded display
Python; not executed`; Bash-n for manager, scanner menu, extracted policy source
each `0 '' ''`; `TEST AST: nine unchanged IDs; only existing ninth body amended`;
`BASELINE: manager hash only; keys/other hashes/version unchanged; before/after
match source`; unchanged-policy/manifests/inventory and fixture SOURCE_FILES lines
as printed above; `DIFF-CHECK 0 '' ''`; final `STATIC ONLY` line. All Bash stderr
was explicitly captured/checked. The extracted source was **syntax parsed only**,
not run. `git diff --cached --check` also returned0/empty before scoped commit.
Commit used hooksPath=/dev/null and commit.gpgsign=false for this invocation,
as in the original delivery, without persistent configuration changes.

### Final-wave handoff

I1 is addressed in source and written integrated oracles, not certified at
runtime. Focused independent re-review of039d7fb and this appendix is still
required, followed by exact separate controller authorizations for cross-consent
and suite. No helper/import/test/probe/launcher/product/backend, even sandboxed
or stubbed, was run. No operator config/keys/evidence, subagents, sudo/network,
GUI, installation/download, cleanup, merge/push/reset or artifact deletion.
Original reports and all artifacts are preserved. No green branch, block/Task4/
Task9/global closure, operational certificate or new authority is asserted.
