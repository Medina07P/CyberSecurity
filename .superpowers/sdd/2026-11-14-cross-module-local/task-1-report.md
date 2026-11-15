# Task1 INITIAL — DONE_WITH_CONCERNS / pending independent static gate

2026-11-14. **Task1 NOT COMPLETE. Tests NOT RUN; RED/GREEN NOT OBSERVED.**
Base `cc79715c735e33ac4bbd7998b34e970d75e8bd5b`; initial test/infrastructure
commit `1876a8b` (`test(local): stage twelve closed synthetic contracts without running`).
This report is documentation of the initial phase, not approval to run anything.

## Delivered scope and exact selection

`CyberSecurity-Framework/tests/test_cross_local.py` contains all twelve methods
before any first RED. `cross_module_selection.py` and `cross_module_cases.json`
agree exactly, without arbitrary IDs, prefix grants, discovery or profile union.
Fixed selector: `--cross-local` only. Future command (NOT AUTHORIZED/NOT RUN):

```text
python3 -I -B CyberSecurity-Framework/tests/automation_sandbox_launch.py --cross-local
```

Full IDs below have prefix `test_cross_local.`; every row is **pending RED**:

| Class.method | Fresh synthetic disposables grant |
|---|---|
| GenerationTests.test_generation_is_exclusive_and_inert | yes |
| GenerationTests.test_generated_launcher_requires_root_and_mode | yes |
| StableToolTests.test_smb_keeps_all_methods_without_source_mutation | yes |
| StableToolTests.test_psexec_preserves_argv_and_secret_privacy | yes |
| StableToolTests.test_linpeas_requires_explicit_source_and_sudo | yes |
| StableToolTests.test_linpeas_failures_preserve_artifacts | yes |
| LabTests.test_five_templates_preserve_existing_notes | yes |
| LabTests.test_lab_roots_names_and_menu_cwd | yes |
| LabTests.test_lab_links_and_partial_failure | yes |
| ReconTests.test_ping_target_parser | **NO: pure** |
| ReconTests.test_ping_cli_records_only_selected_targets | yes |
| LocalMenuTests.test_modes_marks_and_coordinator_omissions | yes |

All twelve remain selected, including later-task contracts. No skip decorator,
placeholder business module, conditional omission or artificial partial GREEN.
The pure parser method does not construct a mutable fixture or launch a process;
its future module import occurs inside the method after worker-scope validation.
Future generation/Labs imports likewise occur inside methods, not discovery.

## Interfaces and actual synthetic business coverage

- Future `emit_launcher(kind, destination, framework) -> Path`: three closed kinds;
  exclusive new0700/outsideFW, collisions including empty/file/link/dangling/dir,
  missing/symlink parents, unknown kind, no backend/embedded operator data.
  Generated CLI `--framework-root DIR ...`: absent/invalid root and absent mode
  must not dispatch; safe new sentinel leaves record exact argv without implied
  `--execute`, interpolation or eval. Original framework sources remain intact.
- Real public SMB/PSExec/Linpeas paths are called in confined copies, never host.
  SMB asserts RPC, enum4linux, list/NSE and seven common shares, repeated SAME
  path/argv, validation and aggregate failure. PSExec asserts command ONE argument,
  synthetic credential formatting/privacy, missing/invalid arguments, repeated
  same public path and backend rc0/1/2. Raw synthetic argv evidence is intentionally
  not redacted; product stdout/stderr and generated product files must not leak it.
- Linpeas asserts inert/default/incomplete gates, local file vs download choice,
  no cwd adoption/link acceptance, actual selected synthetic script copied into a
  new run, explicit sudo transport, curl/wget error/partial preservation, fallback
  only when curl absent, private outputs, sudo rc2 and selected-script rc7.
  The sudo double removes privilege only: runs a selected synthetic run script
  with `/bin/bash`, validates it under new case `scans/linpeas`, never elevates.
- All five real Labs wrappers: original template sections, custom roots, default
  category roots, unrelated cwd, Unicode/spaces, invalid names, full/empty notes
  bytes+mode, partial trees, link/dangling/dir/FIFO, ancestor link, failure to create,
  no permission, concurrent exclusive initialization. Actual Labs menu exercises
  creation, listing, editor target and EOF; no replacement initializer/no-op.
- Pure Recon parser has literal expected tuples for host, three-octet prefix,
  normalized host-bit /24, defaults and explicit0–255, and invalid CIDR/ranges.
  Real CLI is checked against recording ping/host, invalid zero-backend/zero-output,
  same-path repeat/history preservation and missing/error backend failure.
- Guided04/06 menus use real menu sources and extracted real manager consent/
  argument-summary policies, transport-only dispatch recorders, 0/EOF/cancel,
  full-list transport, explicit execution flags and PSExec privacy. Actual
  `params_is_generator`/`params_is_dangerous` classify marks. Real run_all_post
  runs against inert child transports to assert no implicit Linpeas/PSExec grants.

Production interfaces `stable_tools.py`, `stable_cli.py`, `labs_runtime.py`,
`recon_targets.py` and `consent/generate.py` are **not implemented**. All existing
business wrappers/menus/coordinators and config/data are untouched.

## Fixture, sources and runtime provenance

Modified only tests/infrastructure plus this delivery documentation. The existing
fixture enforces exact current controller selector + case ID + selection-bound
grant + configured worker. Existing Bubblewrap/seccomp/Landlock, per-case pinned
scratch and no-fallback worker path stay in force. Local pure case has no grant.

`cross_module_fixture.LOCAL_SOURCE_FILES` is the authoritative exact **30-file**
copy allowlist (all files already exist and already belong to the staged RO source
manifest). It consists of manager, reviewed libraries/metadata, three legacy
wrappers, two coordinators, five Labs setups/main/setup_lab/run_all_labs and ping
leaf. No actual config, session, credentials, notes, output or evidence body is
copied. Synthetic HOME/config/session and sentinels are created exclusively anew.
Each copied source has a retained `source-reference/<exact-relative-path>` image
(0400); live scratch code is0500. Those modes describe NEW copies, not host modes.
Original `/source` remains RO. Legacy self-rewriting generators are NEVER run on
host, even with `--help`; future RED can only affect their confined new copies.

The staged manifest adds only two actual new source files:
`tests/test_cross_local.py` and `tests/cross_local_backend_double.py`.
Absent future helpers have NO placeholder manifest/copy entries. Their source
registration must be a narrow reviewed change when their task actually creates
them; their current missing-file ERROR is intentional pending RED, not discovery
failure. No allowlist auto-glob or refresh of unrelated baselines.

Mandatory transport double basenames (all new copies of the staged double):
`smbclient`, `nmap`, `rpcclient`, `enum4linux`, `psexec.py`, `impacket-psexec`,
`curl`, `wget`, `sudo`, `ping`, `host`, `ip`, `nano`, `editor`, `record-dispatch`,
`clear`, `whatweb`, `ffuf`, `gobuster`, `nc`, `openvpn`, `pkill`.
No actual backend/network/GUI/editor/sudo invocation took place. The executable
PATH is new double directory plus the EXISTING exact sparse sandbox `/usr/bin`
and `/bin`, never host inherited PATH or permission fallback. Cosmetic clear and
execution/list/editor transport recorders do not replace business functions.

No runtime utilities/backends or mounts added. `automation_sandbox_prepare.py`
and `automation_sandbox_manifest.json` are byte-identical to base. Existing
reviewed ordinary runtime, including user-approved rm, remains unchanged. Double
implementation uses standard Python and selected synthetic Bash only.

For every local leaf invocation, source hash+mode BEFORE/AFTER is saved even on
failure to a new `harness-output/sources-N.json`. `_run` exclusively records argv,
cwd/PATH/HOME, STARTING, retained stdout/stderr (including partial output), and
final/interrupted/error receipt, with no finalizer cleanup. Backend argv is
appended before parsing/writing/launching. Retained coordinators replace only
new synthetic child transports; protected loot bodies are never read/copied.
All fixture trees, reference code, logs and partials remain, no final cleanup.

## Static verification performed (NOT runtime evidence)

Only source/data reads/searches, Git and standalone standard-library AST/JSON
analysis were used. **No repo imports, helper execution, discovery, tests, probes,
launcher, backend/double, rm, network, GUI, install or sudo.** No Bash files were
modified or executed; no Bash-n was needed/claimed. Git commits disable hooks
(`core.hooksPath=/dev/null`) and signing to avoid unauthorized hook programs.

1. `git status --short` / `git rev-parse HEAD`: clean starting tree, basecc79715.
2. `python3 -I -B -` standard-library AST/JSON-only analysis of changed source:
   output `AST/JSON OK: 14 test/infrastructure files; no repo imports/discovery/runtime`.
   Final analysis after commit: `Final AST/JSON OK: 14 files at 1876a8b; NOT RUN`.
3. Same static data analysis: exact method AST IDs match JSON, twelve unique cases,
   eleven grants and pure parser excluded; consent9/9 and web7/5 maps unchanged
   against `git show cc79715:...`; all30 local copy sources exist and are already
   in the RO manifest; all five future business helpers absent/no source entries.
4. `git diff --check` and `git diff --cached --check`: rc0, no output.
5. Static byte comparison against base: historical25 inventory, runtime manifest
   and runtime preparation unchanged. SHA-256 respectively:
   `a7f39bd21aecc9e2ca339fde86c2ba2edbbcc93173c3d0bdf864036a96f3c881`,
   `68992f36a0a45ebcb4c0b042d253570f37c13249214c7e868da9137f7a1b3199`,
   `223908551b6cafb6193074238c9d221b74aaf2d29ef9eb1ccf88e9a02ef4e720`.

Static unchanged public source provenance (current mode0775; bytes equal base):

| Framework-relative source | SHA-256 |
|---|---|
|04_Enumeration/smb/enum_smb.sh|6401ac1e6796e103b5f486ce56cd77410513d9fcbd5173a4c559ebea3db4547e|
|06_PostExploitation/lateral_movement/ps_exec.sh|20aee013eafe69f6876dbbc6af3e241409ad3bbb9c5e44a2b52f195a6e97759e|
|06_PostExploitation/privilege_escalation/linpeas.sh|4e4ba9d30185a171037f781c142ac43c25790c9ba92429a1b49e915ceeeeb149|
|02_Recon/scripts/ping_sweep.sh|d017b616f003c0569e7826a1d994cbe52635d5947660a06a9e09361186d18bd0|

These are static measurements, NOT observations of a before/after test run.

## Self-review, concerns and required next gate

- Self-review updated all fixed selector/inside/worker/scope/grant paths. Boundary
  negatives now accept approved local, still reject unreviewed/unknown selectors,
  arbitrary/duplicate/missing IDs, cross-profile grants, prefix grants, pure-case
  grants and unvalidated worker identity before fork. Local root/protected path
  denial and pure no-destructive diagnostic coverage are written NOT RUN.
- Historical25, consent9 and web7(5grants) are preserved; no upstream closed
  implementation was redone and no sibling plan workspace was read/written.
- **Ordinary dependency blockers found statically; NOT added or faked:** Labs
  `main.sh`/`run_all_labs.sh` use `ls`, absent from reviewed runtime. Existing
  `enumeration_runtime.bash` EXIT trap uses `rmdir`, also absent. Proposal for
  controller decision: separately review exact `/usr/bin/ls -> /usr/bin/ls` and
  `/usr/bin/rmdir -> /usr/bin/rmdir` ELF/dependency closure/provenance plus matching
  runtime tests, or decide a genuine business implementation avoiding an unnecessary
  dependency. No generic mount/PATH widening and no no-op ls/rmdir. These are
  pre-existing downstream runtime gaps, not observed failures or granted expansion.
- Missing future helpers must yield explicit case errors at authorized initial
  RED; later tasks cannot be omitted to make the generation subset look green.
  Full initial selection intentionally remains red for pending business work.
- Independent reviewer must check test contracts, allowlists, backend behavior,
  coordinator recorders, exact permission maps, dependency blockers and receipts.
  No independent review has occurred in this subagent session.
- Controller then authorizes exact command **and SHA**; no run may be inferred
  from this commit/report. Only AFTER independent gate and authorized observed
  RED may Task1 resume its **generation phase only**; other business implementation
  still belongs to Tasks2–6. Register actual helper source narrowly at that phase.
- No claim of tests passed, sandbox certification, operational compatibility,
  Task1/Task9/global closure, merge/push or authority for real operations.
