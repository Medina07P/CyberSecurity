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
