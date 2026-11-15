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

## INITIAL fixwave1 — base b3576b8, 2026-11-14 (STATIC / NOT RUN)

Read `task-1-static-review.md` verbatim including I1–I4/M1. The initial verdict
NEEDS_CHANGES is not treated as approval. This appended section supersedes the
earlier claims where corrected below; the original report/measurements remain.
No production business helpers, wrappers, menus or coordinators were modified.

### Review corrections written, pending independent re-review

- **I1:** moved the invalid `se reemplaza por` assertion from the preserved
  historical reference to the live SMB source, before coordinator-only recorders
  are installed. The real `params_is_generator`/dangerous classifier assertions
  remain. Separately capture bytes from the **original staged RO /source** for
  every local source and compare reference bytes both before and after menu and
  coordinator calls. Capture/compare reference type/hash/mode/errors as well.
  References are never repaired/replaced. The historical-text assertion was the
  only inherently invalid preservation requirement and was replaced, not silently
  weakened: correct live code and untouched original reference are now independent
  requirements. All other prior assertions are retained or strengthened.
- **I2:** the coordinator-only fixture now names Linpeas explicitly (rather than
  relying on its transitive presence in COORDINATOR_LEAVES); retain the new copied
  source as `linpeas.sh.retained-source`, then install exact child-dispatch
  recorder. The earlier Linpeas business cases still exercise the genuine leaf
  with transport doubles; they are never replaced with no-ops. The menu/coordinator
  case now captures live Linpeas hash+mode, verifies its retained source, requires
  coordinator rc0, forbids both Linpeas and PSExec child dispatch, requires a
  Linpeas explicit-selection-required omission reason, and asserts counters
  **Executed6 / Failed0 / Omitted2** plus six actual ordinary child dispatches.
  The two omissions are Linpeas and screenshot with capture tools absent. Thus
  merely calling an inert Linpeas preview and counting it as execution cannot pass.
- **I3:** replaced the framework-only privacy traversal with a reusable oracle
  over all designated synthetic product roots: framework, canonical sibling
  **repo/scans**, and synthetic HOME. Raw `harness-output`, backend `processes.jsonl`
  and source references remain separate retained harness evidence, never redacted.
  Within the SAME existing PSExec ID, create an explicit new synthetic password
  leak in `repo/scans/privacy-oracle/synthetic-leak.log`, require the same oracle
  to raise AssertionError, and verify leaked sentinel bytes remain afterward.
  This is a written mutation/oracle assertion, **not an observed rejection**.
- **I4:** independent literal inventories pin the **sixteen original04 and sixteen
  original06 paths** from cc79715 (including protected loot path names, not bodies).
  The test checks each name in the staged source inventory. For actual full-list
  behavior a SEPARATE fresh local fixture creates only missing inert scratch child
  sources and extracts the REAL manager `run_module_scripts` function; it loads
  real module_intro/params/menu policies and checks every original relative path
  in actual list output, rc0 and zero dispatch. It does not substitute a prepared
  listing. Missing protected child bodies are NEVER read/copied. Existing full-list
  transport assertions remain, but are no longer presented as exhaustive evidence.
  Real guided06 menu affirmative paths now require exact Linpeas local selection
  (`--binary <new-selected-file> --execute --allow-sudo`) and download selection
  (`--download --execute --allow-sudo`) through the transport recorder, with exact
  `--prepared` frontend convention and no actual curl/wget/sudo calls. Source menu
  contract pinned: escalation option2 -> source choice1/local,2/download,0/cancel;
  local source path next. Cancel/EOF at both source choice and local path require
  rc0 and no Linpeas dispatch. No business menu decision is overridden.
- **M1:** source observation walks every ancestor with no-follow directory FDs,
  observes leaf existence/type/mode via no-follow stat, and hashes only a regular
  file opened O_NOFOLLOW|O_NONBLOCK after identity validation. Missing/unreadable/
  special/link paths yield per-path records/errors rather than aborting the whole
  receipt. Before observations are saved **before launch**; after observations
  are saved **before integrity assertions**. Source mutation still fails the case
  when launch returns normally. If launch raises, retain/re-raise that same
  exception; observation/receipt failures add a note instead of masking it.
  This does not promise successful receipt persistence under arbitrary E/S failure.
  In the existing menu ID, a new observation oracle retains regular/dangling/
  directory/missing sentinels and persists observations before its assertions.
  No reference restoration, partial deletion, additional ID or cleanup was added.

### Additive explicit runtime authority and exact provenance

During this fixwave the controller relayed the user's explicit **«Sí, lo autorizo.»**
for exactly `/usr/bin/ls` and `/usr/bin/rmdir` plus their closed dependencies,
independent static review before execution and only approved synthetic cases.
That supersedes their earlier *proposal-only* status, but is **NOT permission to
execute them/tests/probes now**. They were not executed, even with --help.

Changed only:

- `tests/automation_sandbox_prepare.py`: append exact source=destination pairs
  `/usr/bin/ls -> /usr/bin/ls` and `/usr/bin/rmdir -> /usr/bin/rmdir` to CROSS_RUNTIME.
  Both use the existing ordinary-file identity validator: root-owned no-follow
  regular executable, non-setid, no group/other write, stable fd/named identity.
- `tests/automation_sandbox_manifest.json`: matching two exact executable rows;
  no other fields/aliases/runtime entries changed.
- Existing `Preparation.test_consent_runtime_is_exact_ordinary_files_without_backend_aliases`
  retains its ID and now includes both pairs and identity negatives for both names;
  also rejects changed inode and no-follow opener failure. No new test IDs/grants.
- **Unchanged** bounded `automation_sandbox_elf.py` supplies dependency closure;
  no generic mount, executable search, aliases, PATH widening or fake utility.

Provenance file: `task-1-runtime-provenance.json` next to this report. Standalone
standard-library Python read only ELF64 bytes and no-follow file metadata, with
SHA-256 and before/fd/after named identity comparison. No repo imports/helpers,
ldd, readelf, loader or utility execution. The measured dependency graph is:

```text
ls -> libselinux.so.1, libc.so.6; interpreter /lib64/ld-linux-x86-64.so.2
rmdir -> libc.so.6; same interpreter
libselinux.so.1 -> libpcre2-8.so.0, libc.so.6, ld-linux-x86-64.so.2
libpcre2-8.so.0 -> libc.so.6
libc.so.6 -> ld-linux-x86-64.so.2; same interpreter
loader -> no DT_NEEDED
```

Exact canonical pcre source is `libpcre2-8.so.0.14.0`, destination SONAME
`libpcre2-8.so.0`; loader canonical source is under `/usr/lib/x86_64-linux-gnu`,
with the existing resolver's interpreter and DT_NEEDED destinations. Six canonical
files/seven destinations; all root-owned regular, non-setid/non-group-other-writable,
stable identity. ls/rmdir modes0755, shared SELinux/pcre libraries0644, no
RPATH/RUNPATH. Nothing was guessed from package names or inspected via execution.
All exact sizes, identities and SHA-256 values are retained in the JSON.

### Actual static commands/results and limitations

- `git status --short`: clean at start on baseb3576b8.
- `git ls-tree -r --name-only cc79715 CyberSecurity-Framework/04_Enumeration
  CyberSecurity-Framework/06_PostExploitation`: source path names only; verified
  independent literal inventories match sixteen `.sh` entries in each module.
- `python3 -I -B -` standalone AST/JSON source/data analysis (no repository imports):
  **rc0**, `STATIC AST/JSON OK: 5 changed test/infrastructure files`;
  `STATIC exact12/11 + selectors/source manifest/grants/ELF resolver UNCHANGED from b3576b8`;
  `SCOPE OK: no production business/helper/wrapper changes`.
- Standalone standard-library file-only ELF provenance command: first attempt
  **rc1 AssertionError** because it incorrectly demanded executable bits on shared
  libraries; no repository code/runtime ran. Read-only metadata confirmed roots
  ls/rmdir root-owned0755. Corrected the *standalone reader* to require executable
  bits only on the two executable roots: **rc0**, complete6-file/7-destination
  graph and identities output. Repository ELF resolver/ordinary policy unchanged.
- Subsequent standalone JSON/hash/identity cross-check: **rc0**,
  `STATIC provenance JSON/hash/identity cross-check OK: 6 canonical ELF files,
  7 destinations; no executable invoked`.
- Static runtime-manifest comparison against `git show b3576b8:...`: **rc0**,
  `Runtime delta EXACT ls/rmdir only, no aliases; existing closure resolver untouched`.
- Standalone AST string-expression rendering (Constant/Name/Add/IfExp only, no
  eval/compile/repo import) of the real menu fixture driver's write expression,
  followed by `/bin/bash --noprofile --norc -n` on stdin for both04/06 and both
  real_list false/true: **four rc0, captured stderr empty**. Source-only syntax
  checks; no generated driver, sourced library or product/helper executed.
- `git diff --check`: **rc0**, empty output. Source AST/JSON and Bash-n checks are
  not tests. No production Bash source modified or executed.
- Final staged source/data check: **rc0**, `FINAL STATIC AST/JSON/SCOPE OK:
  7 staged files; repo runtime NOT RUN`; exact12/11 and prior maps/source allowlist/
  historical25/bounded ELF resolver unchanged; exact authorized ls/rmdir delta.
  `git diff --cached --check`: **rc0**, no output. The ignored documentation paths
  were explicitly force-added after plain scoped git-add reported the ignore;
  no unrelated ledger or artifacts were staged.

All twelve cases remain selected and **NOT RUN / pending RED**. Neither backend
privacy/receipt oracles nor affirmative menu behavior nor the new utility closure
has been exercised. Exact fixwave SHA still needs independent static re-review,
then controller authorization of the exact command/SHA before any runtime. Only
after authorized observed business RED can Task1 generation-phase implementation
resume. Task1/Task9/global are not complete; no real operation, cleanup, merge or
push authorization is inferred. Historical artifacts and the initial report are
preserved; this wave creates no runtime tree to clean.
