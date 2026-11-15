# Task2 — static delivery, pending independent review / runtime gate

2026-11-14; base `2e3529a`. **Implementation written, NOT runtime verified.**
No Task2 GREEN, Task1 completion, Task9/global closure or operational claim.
Read task-2-brief, task-1-context Global Constraints/Task2 contracts, the Task1
generation appendix, design §§8/12–14, AGENTS and historical cleanup document.
No sibling plan workspace was written; no subagents spawned.

## Prior RED, read as data before implementation

Existing root (unchanged):
`.superpowers/sdd/isolated-runtime-runs/automation-isolated-47890d0eccc9435fbc0986ebc7d2c7ad/evidence/`.
Read `case-00003.stderr.log`, `case-00004.stderr.log`, then `cross-local.json`
and `cross-local-sandbox-units.json` as text/JSON only.

- Units:65, successful=true,0failures/0errors/0skips.
- Local selection:12, successful=false,8failures/2errors/0skips, blocked={}.
  The first two generation workers recorded PASS; this is prior controller
  evidence, not verification of this new combination.
- SMB/PSExec IDs failed `public source changed during invocation` on their FIRST
  inert call: confined source mode0500 became0700 and SHA changed. Preserved
  original source hashes were respectively `6401ac1e…` / `20aee013…`.
  Original receipts/reference sources were not modified or repaired.

## Exact public API / modes

Framework-relative public paths are unchanged:

```text
04_Enumeration/smb/enum_smb.sh HOST [PREFIJO] [--execute]
06_PostExploitation/lateral_movement/ps_exec.sh HOST DOMINIO USUARIO PASS COMANDO [--execute]
either-leaf --help
either-leaf --preview
either-leaf <positions> --preview
either-leaf --generate DESTINO
```

Default/noargs/help/preview are inert, with no backend, generation, output tree,
download or source mutation. Execution mode is a FINAL `--execute`, not inserted
by the leaf. Generation accepts ONLY `--generate DESTINO`; no positions, execution
flag or additional modes. Existing/linked/colliding/inside-framework destinations
are rejected by the reviewed emitter. The generated launcher is not executed.
It embeds neither framework root, target, credentials nor grants, and requires
`--framework-root DIR` plus explicit public mode when subsequently invoked.

`00_Config/lib/consent/stable_tools.py` exports:

```python
run_smb(host: str, prefix: str | None) -> int
run_psexec(host: str, domain: str, user: str, password: str, command: str) -> int
validate_host(host: str) -> None
validate_smb(host: str, prefix: str | None) -> str
validate_psexec(host, domain, user, password, command) -> None
```

Validation raises ValueError with fixed safe diagnostics. CLI validation/generation
rejection returns2; OS backend-start failure/missing PSExec returns1. PSExec backend
rc0/1/2 is forwarded unchanged. SMB returns aggregate success/failure, not a claim
that denied access is a successful backend invocation.

Hosts: explicit IPv4 or ASCII DNS names, no options, whitespace, controls, malformed
numeric IP, URL/CIDR or IPv6 literal. No silent normalization of credentials/command.
SMB prefix: `[A-Za-z0-9_-]+`, default `smb_enum`; option-like `--` prefixes rejected
at the public parser. Domain/user: nonempty, no controls/whitespace or `/\\:@`;
domain cannot start `-` (backend option ambiguity). Password: nonempty, no controls
or `@` host delimiter; literal colons/slashes/backslashes/spaces are preserved.
Command: nonempty, no controls; spaces/metacharacters and option-looking commands
are passed as ONE literal backend argument. A command equal to a mode token must
be followed by its own explicit final mode to remove syntactic ambiguity.

## Files / consumer capability matrix

| Source / consumer | Before | Written behavior (NOT RUN) |
|---|---|---|
| public enum_smb.sh | first invocation rewrote source | stable self-locating Bash → isolated Python parser; RPC null users, optional enum4linux, shares list, NSE availability/scan and ADMIN$/IPC$/C$/public/share/documents/backup retained |
| public ps_exec.sh | first invocation rewrote source, lost positions | stable parser; five positions retained; `psexec.py DOMAIN/USER:PASS@HOST COMMAND`, fallback impacket-psexec; no eval/shell interpolation |
| consent/stable_tools.py (new) | absent | typed validation/dispatch; fixed SMB Bash driver reuses genuine enumeration_services/runtime/evidence, not a replacement classifier |
| consent/stable_cli.py (new) | absent | closed smb/psexec modes; reviewed `generate.emit_launcher(kind, Path(destination), framework)` consumed unchanged |
| enumeration_runtime.bash | classified DENEGADO could mask nonzero rc | new opt-in `ENUM_STRICT_RC=1` set by stable SMB driver aggregates backend rc as failure; default other consumers unchanged; this variable grants no action |
| enumeration_menu.bash 04.4 | advanced SMB route without seven common tests | stable enum_smb path with final --execute through existing manager confirmation; full list remains16 entries; label no longer claims all are generators |
| postexploitation_menu.bash 06.6.3 | typed positions delivered to rewriting source | same prompts/hidden read and positions, final --execute through existing sensitive manager gate; unset pass afterward |
| manager / params / dangerous | PSExec arguments hidden by exact public path; SMB/PSExec sensitive | unchanged; stable sources no longer match generator detector; all original public entries remain |
| run_all_enum / automation SMB adapter | advanced SMB service | unchanged; no new flags, shares, calls or grants from coordinators |
| run_all_post / cleanup / Burp / Linpeas | prior contracts | unchanged; no added PSExec execution, permission, download, cleanup or Task3 business logic |
| tests/automation_sandbox_sources.json / cross_module_fixture.py | closed source map/local31 | append ONLY two existing new helpers; local33; no future-source placeholder |
| tests/test_cross_local.py | original12 methods | existing SMB/PSExec IDs strengthened; no deletion/skip/weakening, IDs/grants unchanged |
| tests/cross_local_backend_double.py | Nmap default omitted report header | add genuine `Nmap scan report for <requested target>` header; existing real classifier requires it; explicit programmed stdout/rc still controls responses |

No new runtime/root/backend/utility/mount/permission entry or broad hash baseline
refresh. Manifest retains all original source entries/order after filtering exactly
the two additions. Source wrappers retain original host mode0775 (git100755);
new Python modules are0664, not generated executables. Patching initially recreated
wrappers0664; source-only metadata edit restored0775 before delivery.

## Privacy and capability limitations

CLI errors/help never echo argv. PSExec creates no product log or generated file
containing credentials. Captured backend stdout/stderr are forwarded to their
original streams with literal password bytes replaced by `[oculto]`; original
credential target and command are delivered unchanged to the backend. There is
**no promise of hidden OS argv or universal backend redaction** (transformed or
encoded secrets are not covered). Raw synthetic harness argv evidence is retained,
not redacted to fake privacy.

Backend output is buffered until process completion, in memory, with no new output
file. This changes output timing and is not a realtime/interactive-terminal or
bounded-output guarantee. Backend operational compatibility and arbitrary backend
diagnostic privacy remain unverified. Source-path dispatch retains normal
self-location; no hostile concurrent source replacement/kernel guarantee is made.

## New assertions — all NOT RUN

Within the SAME two existing IDs, retain original repeated-path/hash/mode/backend
argv/rc tests and add: inert help/preview; public generation/new collision unchanged;
mixed generate/execute/positions rejected; no embedded root/target/password;
access-denied nonzero backend rc still fails SMB; ambiguous host/credentials/control
command rejected before any backend; literal backend password echoes suppressed;
option-looking command stays one argument; literal complex password format retained;
fallback backend rc2 and missing-both rc1 with no transport. New fallback tests rename
ONLY fresh synthetic doubles to retained names, never delete a source or artifact.
The original product privacy mutant/oracle and source-reference checks are intact.

## Actual static verification (no repository import/execution)

All commands below were source/data-only or Git. No helper, test/discovery, launcher,
probe, product, double, backend, rm/ls/rmdir, network/GUI, sudo/install/download,
cleanup, reset, merge or push was executed. No new runtime tree was created.

1. `git status --short`: initially empty on base2e3529a.
2. Standalone `python3 -I -B -` using only stdlib ast/json/pathlib/hashlib/stat and
   subprocess for **Git reads and Bash-n only**: AST parsed both new helpers plus
   test_cross_local.py/cross_local_backend_double.py/cross_module_fixture.py;
   parsed exact-source JSON; compared source tuples/IDs/manifests against
   `git show 2e3529a:<exact-path>`; read existing controller JSON as data.
   Actual output, rc0:
   `STATIC AST/JSON OK; exact 2-source manifest/copy delta; local33; same12 IDs; selectors/grants/runtime/root/policy/launcher/worker unchanged`.
   The unchanged comparisons cover cross_module_cases/selection, sandbox runtime
   manifest/preparation/policy/inside/launch and automation_case_worker.
3. `/bin/bash --noprofile --norc -n <each-file>` via captured subprocess, on both
   public wrappers and enumeration_menu/enumeration_runtime/postexploitation_menu:
   **five rc0, each captured stderr empty**. No sourcing or script execution.
4. Same Bash-n on stdin containing ONLY `ast.literal_eval` of `_SMB_DRIVER`:
   **rc0, stderr empty**. No driver/repository import or execution.
5. Standalone stdlib SHA-256 reads of changed/new source, with prior bytes from
   `git show 2e3529a:<path>`; exact key provenance below. No test-baseline refresh.
6. `git diff --check` / staged check and final scoped AST/Bash-n recheck are recorded
   in the final appended delivery note below, before the scoped commit.

| Framework-relative source | Base SHA-256 | Delivery SHA-256 |
|---|---|---|
|00_Config/lib/consent/stable_tools.py|NEW|71cc709371d8a28e6a6ebe0c416450721a7b98ecd07b75f9017f70fc3b9c7607|
|00_Config/lib/consent/stable_cli.py|NEW|03c4f202bd8cd5b8013609f7f6a96da05cbf1555f815ab0c4bb4cd1a4642d9f3|
|04_Enumeration/smb/enum_smb.sh|6401ac1e6796e103b5f486ce56cd77410513d9fcbd5173a4c559ebea3db4547e|9407bb9df83ca258c21f76d08af1a964656e9c364eb0a38d18e358d998efad4e|
|06_PostExploitation/lateral_movement/ps_exec.sh|20aee013eafe69f6876dbbc6af3e241409ad3bbb9c5e44a2b52f195a6e97759e|1e3bea34b389547a2f02a5c48640530330b8d26115303122827026d07db54e0f|

Existing-source edits are limited to the matrix above; all are based on current
2e3529a source, not stale rewritten payloads or a sibling plan. Task1 generate.py,
consent/files.py, reviewed manager privacy/consent/Burp and Task3 source are intact.

## Self-review / next gate

Reviewed shell argument boundaries, path depth, optional prefix validation before
any output, strict aggregate rc, exact five-position credential grammar, constant
generation, manager privacy route, retained capabilities and exact two-file source
registration. Found/fixed option-looking command rejection during source review;
command/password values are now positional data, not scanned as flags. Found/fixed
default Nmap transport header mismatch without changing production classification.

**Pending:** independent static review of this exact source/fixture/test combination,
then controller authorization of exact command/SHA before ANY runtime. Full-list
generator marks, 06 escalation/Linpeas selections and coordinator omission contract
will remain pending Task3; full local12 is not expected GREEN at this Task2 gate.
Legacy test-oracle reconciliation and broader docs belong to Task6, not silently
approved here. No real operations, global approval, push or merge authorized.

Final delivery note: `git diff --check` returned0/empty output. Scoped force-add
included exactly12 files (eleven sources/tests/maps plus this ignored report).
Final standalone `python3 -I -B -` AST/JSON/Bash-n/Git-byte-comparison command
returned0 and printed:
`FINAL STATIC: exactly12 staged files; Python AST/JSON OK; 5 Bash-n rc0/stderr empty; Task1 emitter/files + manager/params/dangerous + Task3/coordinators unchanged. Tests NOT RUN.`
`git diff --cached --summary` shows only three new100644 files (this report and
two helpers), no public-wrapper mode changes. The scoped commit disables hooks
and signing; no helper or runtime verification is inferred from committing.

## Task2 fixwave1 — base181dae0 — STATIC / NOT RUN

2026-11-14. Read `task-2-static-review.md` **verbatim**, including I1/I2/I3.
Specification and quality verdicts **NEEDS CHANGES** are not approval. This
appendix supersedes the earlier backend argv/consumer claims where corrected;
historical delivery, hashes and controller RED evidence above remain intact.
No new runtime/RED/GREEN was observed, nor is Task2/Task9/global closed.

### I1: real option-parser boundary, not just one argv element

Read `/usr/share/doc/python3-impacket/examples/psexec.py:590–649` as TEXT ONLY.
Its parser has target, command `nargs='*'`, help/debug/Kerberos/connection options
and `parse_args()`. No backend was imported, launched, copied or probed.

`run_psexec` now dispatches exactly:

```text
[selected_backend, DOMAIN/USER:PASS@HOST, "--", COMANDO]
```

Five public positions, target credential grammar, validation, one literal command,
backend selection/fallback and rc0/1/2 propagation are retained. `--` terminates
backend option parsing; `--help`, `-debug`, `-k`, `-target-ip` are command DATA,
not help/debug/auth/connection grants. No eval or shell interpolation was added.
Product no-log/literal-secret filtering and all privacy limitations above remain.

The EXISTING transport double now includes a **synthetic argparse oracle** for
the relevant inspected grammar: target, command nargs*, help, -debug, -k,
-target-ip and -c. It writes raw invocation first as before, then a separate
parsed-meaning receipt in NEW `harness-output/psexec-parser.jsonl`, before its
programmed stdout/stderr/rc. No real backend import or business substitute.
Help/error may terminate parsing before that second receipt: absence matters.

Inside the SAME PSExec ID, retain source/privacy/generation/rc assertions and
strengthen raw argv expectations to include `--`. Require parsed command `[COMANDO]`
and debug/k=false, target_ip/copy=None. For each option-shaped command, a synthetic
old-shape mutant `[double, target, command]` must fail command preservation:
help returns0 without a command receipt, debug/k set backend flags, target-ip
returns2 for its missing value. Protected dispatch must retain the exact command
with all backend-option fields inactive. Fallback rc2 also retains parsed command.
These are written oracles, **NOT RUN**; no observed mutant rejection is claimed.

### I2: actual full-list consumer, explicit modes, no slot relaxation

Public CLI contracts remain the same. Wrapper `Uso:` now lists ONLY its two/five
positions; a separate comment describes CLI modes. The unusable optional
`[--execute]` slot is removed, not accepted by weakening generic validation.

`params_mode(script, optional_relative_path)` returns `stable` ONLY for the exact
canonical public SMB/PSExec paths; other none/manual/slots logic is unchanged.
Actual `prompt_for_slots(script, relative_path)` selects the closed adapter:

| Full-list choice | Exact argv delivered to existing manager dispatch |
|---|---|
| empty /1 | `--preview` (no credentials requested) |
|2 | actual params_slots positions followed by explicit `--execute` |
|3 + destination | `--generate DESTINO` only, no target/credential/mode mixture |
|0/! / invalid / EOF | cancellation/error to manager, zero child dispatch |

The adapter reads actual params slot definitions and requires exactly2 SMB/5
PSExec slots; host may use existing session default, optional SMB prefix may be
omitted. Execution positions are requested only AFTER choice2. Generic slot
validation remains unchanged, including rejection of option-like generic values.
Only this closed adapter accepts leading `-` in password/command; leaf validation
remains authoritative. No downloaded source, new scope authority or environment
grant. The unchanged manager sensitive confirmation still precedes the adapter;
it does NOT select mode2 automatically. Guided menu behavior is preserved.

The fixture now extracts actual manager `ask_confirm`, `script_arguments_summary`,
`execute_script` and `run_module_scripts` definitions as source (shape checked).
Only the exact final `./"$rel_path" "${argv[@]}"` external-process boundary becomes
the existing transport recorder. No manager initialization/main is sourced and
no params/prompt/consent/business decision is mocked. Execute/generate tests also
select the real inventory entry; other cases exercise that same extracted
execute_script consumer directly to avoid needless repeated listing work.
Actual params mode/count and continued generic rejection are asserted as well.
No manager source or pinned manager baseline was changed/refreshed.

### I3: non-echoing literal secret input, bounded claim

New `_prompt_read_literal(type, destination_variable)` uses **`IFS= read -r -s`**
for CONTRASENA and `IFS= read -r` otherwise. It performs no whitespace trim,
splitting, unescaping or output of entered values. Full-list password and command
values preserve accepted literal line content; controls/empty invalid values are
rejected, not transformed. Cancellation/EOF never dispatch partial credentials.
The guided PSExec route already uses `IFS= read -rs pass`; it remains unchanged.
Exact-path summary hiding is retained, including for the new full-list path.
No echoing manual credential-entry fallback was introduced for these consumers.

Within the SAME existing LocalMenu ID, an input-boundary observer records the
actual `read` **flags, IFS and destination NAME only**, then delegates to actual
`builtin read`. It records no entered secret value. Assert actual full-list
password read (fourth of five fields) has empty IFS and both -s/-r; likewise assert
the actual guided `pass` read. Both dispatches must retain the exact password
with leading/trailing spaces, colon/slash and backslash, plus single command.
Pipe-output privacy assertions and the product-root oracle are retained, but
are explicitly **NOT PTY/terminal-echo verification**. No PTY/syscall probe, real
TTY or backend is used by the written oracle, and none was run here.

### Ordering, preservation and exact source scope

- Task2 full-list/guided checks now precede pending Task3 menu checks. Linpeas
  cancellation/source-choice/marks/sensitive-classifier/coordinator assertions
  remain, each in independent subtests where necessary so a known pending failure
  cannot prevent later contracts from being reached. No skip or pending check
  was deleted/relaxed; coordinator counters/omission reason remain required.
- Exactly the original12 test method IDs and their grants/selectors remain.
  Only the existing PSExec and LocalMenu test methods change; the other10 method
  ASTs are identical to181dae0, including SMB, generation and all Task3–5 methods.
- Source manifest/local33 tuple, runtime manifest/closure/root, launcher, worker,
  policy and prior selectors/grants are byte-identical. No new source file or
  executable alias is needed; the observer/parser live in already registered
  exact fixture/double sources. New receipts remain within existing case scratch.
- Production scope: stable_tools.py, params.bash, prompt.bash, SMB/PSExec usage
  comments. Tests: cross_local_backend_double.py, cross_module_fixture.py,
  test_cross_local.py. This appended report is the only documentation edit.
- `generate.py`, `files.py`, actual manager, guided04/06 sources, both coordinators
  and Linpeas production source are byte-identical to181dae0. **No Task3 business
  implementation**, sibling workspace writes, global baseline refresh or new grant.

### Actual static commands / output

1. `git status --short`: empty at fixwave start on181dae0.
2. Tool source reads, including entire review and inspected backend parser text;
   no imports/execution. Standalone `python3 -I -B -` using stdlib AST/pathlib and
   subprocess ONLY for Git reads and Bash-n parsed the four changed Python files
   and ran `/bin/bash --noprofile --norc -n <path>` on params.bash, prompt.bash,
   enum_smb.sh, ps_exec.sh. **rc0; four Bash-n rc0, stderr exactly empty**.
3. Standalone restricted AST string renderer (Constant/Name/Add/IfExp and only
   substitution of the observer's constant string; no eval/compile/repo helper)
   reconstructed actual fixture driver expressions with extracted manager source.
   Bash-n on stdin checked2 full-list/direct drivers,12 guided/list/read-observer
   combinations and1 params-mark driver. **15 rc0; captured stderr empty**.
4. Standalone stdlib AST/hash/Git comparison command: **rc0**, actual output:
   `STATIC AST/BASH-N OK: 4 Python + 4 shell sources; four rc0/stderr empty; no repository imports`
   and
   `UNCHANGED: exact12 IDs/grants/selectors; source manifest/local33; runtime/root/policy/launcher/worker; manager/emitter/files/guided menus/coordinators/Linpeas. Only two existing test methods changed; no baseline refresh.`
5. `git diff --check`: **rc0, no output**. Final staging/static checks are appended
   below before commit. Git hooks/signing remain disabled for the scoped commit.

Exact source provenance (SHA-256; base181dae0 → fixwave delivery):

| Framework-relative source | Old | New |
|---|---|---|
|00_Config/lib/consent/stable_tools.py|71cc709371d8a28e6a6ebe0c416450721a7b98ecd07b75f9017f70fc3b9c7607|3abd2405a45c5dc5cebeef7a4d5873778d4fad2738ba6f21408485a365d1415d|
|00_Config/lib/params.bash|7348a14ab9922bedb4891ca34c93a8ba89503f53f2f12a490406b4aee5cefa48|55532c719062446e18888be79aec8ffbf1758233b28299280ae554dbbfb95765|
|00_Config/lib/prompt.bash|43ca7f780cc2bc39834154c86a1d62a9844a3f5d94e67c522c66deb43f1c1f55|3399f4e9053106e358aa59d5709f12ef10ef441a108f21a2c29b3722e98147a0|
|04_Enumeration/smb/enum_smb.sh|9407bb9df83ca258c21f76d08af1a964656e9c364eb0a38d18e358d998efad4e|97a2a0baec18ece5c62e42b20bd5f2195761eefaa4e30dac24b09de8a33d8e8e|
|06_PostExploitation/lateral_movement/ps_exec.sh|1e3bea34b389547a2f02a5c48640530330b8d26115303122827026d07db54e0f|f649aef36491a1b62f7af197a681ef4b1fd3737f6016829fe0c9affde5f90387|
|tests/cross_local_backend_double.py|ccc62d12dd28ec458a5dac917a0729af16c4e1dda6864716f6f9c3ae8a5c982c|87fd87ff45baad671a4074c9f5b02aaec0f7b14317ef4fad386729a906622845|
|tests/cross_module_fixture.py|9adcc434f0d6ecd8835d364085d49a09f04a431a298db91f7dbeb6e20da83fb6|2390b779b5680b1fa6da74e0858ae7263c16fed9eb8e30b947d6fbae5ca84e20|
|tests/test_cross_local.py|90c8cf5cfda04d051da736ff0d6e44159f147c72108d9541da105854f850997b|dfb3dc99ca0e2aad8288656ba5bd13158a3bc2c0fafbff871cd01b85310605ac|

Host shell modes remain0775, Python0664, no source-mode change. Manager SHA-256
unchanged: `67f004780ea6a9356e3e7db0370f9c90874acf5c8579b90f5c29795fec2c691f`.
No pinned-source baseline was edited because the manager was not changed.

### Self-review / concerns / next gate

Reviewed end-of-options placement, actual parser state vs raw receipts, exact
public-mode adapter routing, argv line boundaries, secret read dynamic scope,
summary hiding, EOF/cancellation and test ordering. Corrected a missing string
concatenation in a fixture driver during source review; restricted rendering then
confirmed its syntax without importing/running it. No original capability, seven
SMB shares, five PSExec positions, command value or real rc was removed.

All new production/oracle code is **NOT RUN**. Existing 60-second case limit and
15-second fixture-invocation timeout are unchanged; extended consumer coverage
has no timing guarantee until authorized runtime. Output buffering/redaction and
backend-version limitations from the initial report still apply. No terminal
echo behavior, backend compatibility or kernel containment is newly certified.

Independent re-review of this exact diff/SHA is required, then controller exact
command authorization before any import/helper/test/probe/launcher/product/double.
Full local12 remains pending Task3–5; subtest failures must remain visible, not
silently become GREEN. **No runtime, real backend, PTY/syscall probe, subagent,
network/GUI, sudo/install/download, cleanup/artifact deletion, merge/push or reset**
was performed; no operator configuration/data or unrelated evidence was read.

## Task2 fixwave1 takeover — STATIC / NOT RUN (second agent)

2026-11-14. The implementer of the appendix above died on a service usage limit.
The Git index held nine staged, **untrusted candidate** files. Provenance: the
preserved snapshot `.superpowers/sdd/2026-11-14-cross-module-local/
task-2-fixwave1-interrupted-181dae0.wip.patch` was compared byte-for-byte with
`git diff --cached --binary` of that index: **identical**. The patch file is
kept (git-ignored) and nothing was deleted, reset or reverted. I re-verified
every hunk against I1/I2/I3 before keeping it, rewrote exactly one hunk
(below), and added nothing else.

### I1 — option-parser boundary (verified, kept)

`run_psexec` dispatches `[backend, 'DOMINIO/USUARIO:PASS@HOST', '--', COMANDO]`.
Read as text only: `/usr/share/doc/python3-impacket/examples/psexec.py:590-677`
declares `target`, `command nargs='*'`, `-c`, `-path`, `-file`, `-ts`, `-debug`,
`-codec`, `-hashes`, `-no-pass`, `-k`, `-aesKey`, `-keytab`, `-dc-ip`,
`-target-ip`, `-port`, `-service-name`, `-remote-binary-name` and calls
`parse_args()`, so `--` is the correct end-of-options boundary for every
option-shaped command (`--help`, `-debug`, `-k`, `-target-ip`). Five positions,
one literal command argument, no eval/shell interpolation, backend rc0/1/2
returned unchanged, missing backend rc1, no product log, literal password
filtering and the no-universal-redaction disclaimer are retained.

The recording double gained a **synthetic argparse oracle** (same grammar subset:
target, `command nargs='*'`, `--help`, `-debug`, `-k`, `-target-ip`, `-c`) that
writes raw argv first and then a separate parsed-meaning receipt to
`harness-output/psexec-parser.jsonl`. Inside the existing PSExec ID the test now
requires `command == [COMANDO]` and `debug/k is False`, `target_ip/copy is None`
for each option-shaped command, and requires an old-shape mutant
`[double, target, command]` to fail to preserve it (help → rc0 without a command
receipt, `-debug`/`-k` → backend flags set, `-target-ip` → rc2). No real backend
is imported or launched.

### I2 — full-list consumer, modes without slot relaxation (verified, kept)

Shell `Uso:` lines now list only their positions; the `[--execute]` token that
the generic parser treated as a sixth optional slot is gone (this also restores
`params_slot_count ps_exec.sh == 5` for `tests/run_tests.sh:111`, which the
180dae0-style line broke). CLI contract unchanged: `--preview` (default),
`<positions> --execute`, `--generate DESTINO`, `--help`.

`params_mode(script[, rel])` returns the new closed value `stable` only for the
two exact canonical relative paths; `prompt_for_slots` routes only that pair to
`_prompt_stable_tool`:

| full-list choice | argv handed to the real `execute_script` |
|---|---|
| empty / `1` | `--preview` (no credential prompt) |
| `2` | the real `params_slots` positions, then a final `--execute` |
| `3` + destination | `--generate DESTINO` only |
| `0` / `!` / invalid / EOF | cancel (1) or EOF (2); zero child dispatch |

The adapter reads the real slot definitions, requires exactly 2 (SMB) / 5
(PSExec) slots, keeps `_prompt_validate`/`_prompt_universal_ok` untouched for
everything else, and lets leading `-` through only for that closed pair (the leaf
stays authoritative). Nothing is executed by selecting an entry: the existing
dangerous-path `ask_confirm` still precedes the adapter and the default is
preview. EOF/cancel codes keep the documented 0/1/2 contract, which
`execute_script` maps to "Cancelado"/"Entrada cerrada" with rc0 and no dispatch.

The fixture no longer keeps a private copy of the manager policies: it extracts
`ask_confirm`, `script_arguments_summary`, `execute_script` and
`run_module_scripts` as source (shape-checked) and replaces only the final
`        ./"$rel_path" "${argv[@]}"` process boundary with the recorder, so the
real list, params, prompt, confirm and argv reconstruction run. Execute/generate
cases also select the real inventory entry; other cases drive the same extracted
`execute_script` directly.

### I3 — non-echoing, byte-preserving secret input (verified, kept)

`_prompt_read_literal` uses `IFS= read -r -s` for `CONTRASENA` (`PASS` derives
`CONTRASENA` from `params_type_of`) and `IFS= read -r` otherwise, with no trim,
split, unescape or echo of the value. The full-list password and the command are
therefore byte-preserved (leading/trailing spaces, `:`, `/`, `\`), and the guided
06.6.3 route keeps its unchanged `IFS= read -rs pass`. Exact-path argument
summary hiding and the product-root privacy oracle are retained. The new oracle
records only the flags, `IFS` and destination **name** of the real `read` call
(4th of 5 fields for full-list, `pass` for guided) and is explicitly documented
as *not* PTY/terminal-echo verification.

### Rewrite applied to the candidate

Only `_prompt_stable_tool`: the session target was substituted invisibly for an
empty first field. It is now displayed as `[target]` before the read, exactly
like the generic slot prompt and the guided menus, and the entered-empty case is
assigned from that displayed default. Prompt text is not asserted by any test,
`bash -n` rc0/stderr empty afterwards, and no other behavior changed.

### Static checks performed by this session (no import/execution)

1. `git status --porcelain -uall`, `git diff --name-status HEAD`,
   `git diff --cached --summary`: nine staged **modifications** only (8 code +
   this report), no new file, no mode change, working tree equal to the index.
   Therefore `cross_module_selection` (12 IDs / 11 grants / 1 pure),
   sandbox runtime manifest/preparation/policy/launch/worker, the 279-entry
   source manifest (contains both consent helpers and both libraries),
   `generate.py`, `files.py`, `cyber_framework.sh`, guided menus 04/06, both
   coordinators, Linpeas, Labs and the CIDR sources are byte-identical to
   `181dae0`; Linpeas/Labs/CIDR untouched; no new ID, grant, selector, runtime,
   root, mount, backend or executable alias.
2. AST inventory of `tests/test_cross_local.py` vs `181dae0`: 12 IDs before and
   after, none added/removed, and only the two IDs
   `StableToolTests.test_psexec_preserves_argv_and_secret_privacy` and
   `LocalMenuTests.test_modes_marks_and_coordinator_omissions` differ; the rest
   of the module (constants incl. `ORIGINAL_ENTRIES`, helpers, the other ten
   methods) is AST-identical (`REST IDENTICAL: True`).
3. Helper assumptions read in source: `_prompt_label` (prompt.bash:52),
   `_prompt_universal_ok` (:70), `_prompt_validate` (:97), `params_slots` shape
   `pos|nombre|obligatorio|tipo`, `params_type_of('PASS')=='CONTRASENA'`,
   `params_type_of('COMANDO')=='TEXTO'`, `session_target` (session.bash:41;
   value on stdout only), `ask_confirm` (s|S|si…), and
   `run_module_scripts`/`execute_script` closing braces resolved exactly once by
   the fixture extractor.
4. `params_mode` closure: the only callers comparing its value are
   `cyber_framework.sh:451` (`== manual`; a fourth value changes nothing) and
   `prompt_for_slots` (new `stable` branch). `tests/run_tests.sh:87` iterates
   **absolute** paths (never matches the closed case); `run_tests.sh:111/119`
   use `params_slot_count`/`params_slots`. No third caller of
   `params_mode`/`prompt_for_slots` needs adaptation.
5. Manager trace statically followed: `run_module_scripts` → `execute_script`
   → `prompt_for_slots "$rel_path" "$script_path"` → `params_mode "$script"
   "$rel"` → `stable`; `find` order (run_all first, then lexicographic) equals
   `ORIGINAL_ENTRIES`; the source manifest holds exactly 16 `.sh` per module and
   no `.py`/`.ps1`, so the computed menu index selects the intended leaf; both
   leaves are in `dangerous.txt`, so `ask_confirm` precedes the adapter.
6. `git diff --check` and `git diff --cached --check`: rc0, no output.
   `/bin/bash --noprofile --norc -n` on `params.bash`, `prompt.bash`,
   `enum_smb.sh`, `ps_exec.sh`: **4 rc0, captured stderr empty**. Python `ast`
   parse of the five changed/new Python files: OK. No sourcing, no helper, no
   test, no launcher, no double, no backend, no probe, no network.

SHA-256 / host mode of the delivered code files (this takeover; the appendix
above stays as history — its `prompt.bash` value is superseded by this one):

| Framework-relative source | SHA-256 | mode |
|---|---|---|
|00_Config/lib/consent/stable_tools.py|3abd2405a45c5dc5cebeef7a4d5873778d4fad2738ba6f21408485a365d1415d|664|
|00_Config/lib/params.bash|55532c719062446e18888be79aec8ffbf1758233b28299280ae554dbbfb95765|775|
|00_Config/lib/prompt.bash|60fb6b68be38f7c9c7ca2d1dd7aa85056ec8ea4410436b66d25a133f46c2b17a|775|
|04_Enumeration/smb/enum_smb.sh|97a2a0baec18ece5c62e42b20bd5f2195761eefaa4e30dac24b09de8a33d8e8e|775|
|06_PostExploitation/lateral_movement/ps_exec.sh|f649aef36491a1b62f7af197a681ef4b1fd3737f6016829fe0c9affde5f90387|775|
|tests/cross_local_backend_double.py|87fd87ff45baad671a4074c9f5b02aaec0f7b14317ef4fad386729a906622845|664|
|tests/cross_module_fixture.py|2390b779b5680b1fa6da74e0858ae7263c16fed9eb8e30b947d6fbae5ca84e20|664|
|tests/test_cross_local.py|dfb3dc99ca0e2aad8288656ba5bd13158a3bc2c0fafbff871cd01b85310605ac|664|

### NOT RUN / residual risks

**Everything runtime is unverified**: no RED/GREEN, no case worker, no launcher,
no double, no backend, no import of repository code, no execution of the read
observer, no argv/rc/trace equality, no source hash/mode check at runtime, no
TTY echo, no argparse-oracle behaviour. The `--` boundary and the `IFS=`
prefix-assignment visibility inside a shell function are asserted from the
documented CLI-language behaviour and the inspected parser text, and must be
confirmed by the authorized runtime.

- `params_mode` now returns a fourth value (`stable`) that AGENTS.md's contract
  table does not list; the manager's listing marks are unaffected. Docs remain
  Task6.
- An absolute or `./`-prefixed script path falls back to generic parsing, which
  can only reach preview; conservative but not announced.
- The adapter cancels (does not re-prompt) on an invalid mandatory value, and
  `0`/`!` stay cancel tokens, so a literal password/command equal to those is
  unusable from this route.
- The synthetic parser oracle models a reviewed subset of the Impacket grammar,
  not the backend: other versions' option meanings and rc are unverified, and
  OS argv exposure plus non-universal backend redaction still apply.
- Full local12 stays pending Task3–5; the new subtests keep pending failures
  visible instead of hiding them. No re-review, controller authorization,
  GREEN, Task9/global closure, push or merge follows from this appendix.

## Task2 fixwave2 — M1/M2/M3 (STATIC / NOT RUN)

Base/HEAD `958f00d`. Only the three Minor observations of
`task-2-static-rereview-1.md` were addressed; nothing else was touched.

### Exact changes

**M1 — synthetic session in the full-list driver.** `cross_module_fixture.py`
adds `FULL_LIST_TARGET = 'session-target.example'` and
`set_full_list_session()`, which writes that value into the fixture's own new
scratch `00_Config/.session` (exclusive `_new_text`, 0600) and rejects an
existing file with a different value. No operator config, credentials or scope
is read. `run_full_list()` calls it; the driver now sources `session.bash`
explicitly and is fail-closed (`exit 94` if `session_target` is undefined,
`exit 95` if it reads empty) before any policy runs. `test_cross_local.py`
asserts, for both leaves, that the prompt shows `[session-target.example]` and
that leaving the first field empty dispatches that value as `argv[1]`.

**M2 — closed consumers never reach the echoing generic secret read.**
Policy chosen: **strictly lexical canonicalization AND explicit refusal**.
- `params.bash`: `_params_stable_identity` strips ONE leading `./` and collapses
  repeated `//` (pure Bash, no realpath/symlink/`..` resolution);
  `params_mode` matches `stable` only on that form. `params_is_stable_identity`
  recognizes the same two closed consumers under any other prefix (absolute or
  foreign) so the caller can refuse rather than degrade.
- `prompt.bash`: if `mode != stable` but the identity is one of those two
  consumers, it prints a stderr notice and returns 1 (contract: cancelled);
  `execute_script` maps that to "Cancelado", rc0 and zero dispatch. No generic
  validator relaxation, no silent fallback, no new `params_mode` value.
- Why both: canonicalization alone would still route `/<abs>/…/ps_exec.sh` to
  the generic loop (echo + trim); refusal alone would discard the unambiguous
  `./` and `//` spellings. The only remaining generic route is an identity
  without the module component (bare basename), which the manager never emits.

**M3 — parse receipts by offset + explicit label.** `test_cross_local.py` no
longer uses `psexec_parsed()[-1]`: each dispatch captures
`len(psexec_parsed())`/`len(records())` first and asserts the whole new slice is
exactly one expected row (`backend`, `target`, `command`, flags), so a stale row
cannot satisfy it. The old-shape mutant oracle is untouched and still
discriminating (`--help`/`-target-ip` write no parse row; `-debug`/`-k` flip
flags).

### Static verification (commands + results)

- `bash -n` with captured stderr on `00_Config/lib/params.bash`,
  `00_Config/lib/prompt.bash`, `04_Enumeration/smb/enum_smb.sh`,
  `06_PostExploitation/lateral_movement/ps_exec.sh`: 4× rc0, stderr empty.
- stdlib `ast.parse` (no import) of `tests/cross_module_fixture.py` and
  `tests/test_cross_local.py`: OK (22 / 21 functions).
- `git diff --check` empty; `git status --porcelain -uall` lists only the four
  intended files. `git diff -U0` shows no added/renamed `class`/`def test_`, so
  the 12 case IDs / 11 grants / 1 pure selection, the source manifest and the
  cases JSON are unchanged; Linpeas, Labs and CIDR sources untouched; the I1–I3
  hunks are intact.

### Runtime NOT RUN

Nothing was imported, sourced or executed: no case worker, launcher, fixture,
double, backend, test, suite or probe, not even in sandbox. The new assertions
on session display/adoption, refusal routing and offset slices are
**unverified at runtime**; no PTY/terminal, kernel or backend guarantee is
claimed.

### Residual risks / superseded notes

- An absolute or otherwise non-canonical identity no longer degrades silently to
  preview: it is refused with a notice (previous bullet superseded). A bare
  basename still reaches the generic prompt; the manager never produces it.
- `params_mode` keeps the fourth value `stable` that AGENTS.md does not list
  (Task6), and `tests/run_tests.sh` would classify the two leaves as `stable`
  if it ever iterated relative paths.
- The adapter still cancels instead of re-prompting; `0`/`!` remain cancel
  tokens, so those literal secrets stay unusable from this route.
- The synthetic parser oracle remains a grammar subset; other backend versions,
  OS argv exposure and non-universal redaction stand.

SHA-256 / mode of the files changed by fixwave2:

| Framework-relative source | SHA-256 | mode |
|---|---|---|
|00_Config/lib/params.bash|ece553fe91a0695c4f97b58fe160b17411aa03d3508fb8ec6c1c03e1bea5000b|775|
|00_Config/lib/prompt.bash|cca403984d972fc2180dfb216d23990e2c103f2792c8c500e4b3a4fbd58bb8ba|775|
|tests/cross_module_fixture.py|e2dd5df4ac0917a939d312a03ad5e4e9839d2b69099adeef1b9966a5974665d8|664|
|tests/test_cross_local.py|aab1ea55d3c54a32f779cdce7ba8e80e7f26629920e88cc0e3d10f06423ee2f8|664|
