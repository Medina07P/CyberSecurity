# Task3 Burp — STATIC DONE_WITH_CONCERNS

Date: 2026-11-14. Base: `74d4139`. Implementation commit: `fcac367`.
This report is committed separately after the implementation; its commit is the
subsequent documentation-only commit in this worktree's history.

**Pending independent static review and exact controller authorization. Amended
tests, imports, helpers, launchers and backends: NOT RUN. No GREEN claim.**
Task4 menu integration remains pending; Task3 does not resolve or conceal its
existing failure. No Task9/global closure, compatibility certificate, merge/push
or authorization to perform a real Burp operation is implied.

## Scope and interfaces

Read the task brief, task1 intro/global constraints and Burp downstream
contracts, binding design §§6/12–14, AGENTS instructions and task1 report
lines455–479 before implementation. Task1/2 logic was not reimplemented.

Files changed (relative to `CyberSecurity-Framework/`):

| File | Change |
|---|---|
| `00_Config/lib/consent/burp.py` | GUI/config/receipt allocation, passive observation, explicit GET and pinned stop business functions; production `BurpOps` OS boundary |
| `00_Config/lib/consent/burp_cli.py` | Single public parser used by wrapper and injected tests |
| `03_Scanners/web_scanners/burpsuite/burp_launcher.sh` | Stable executable wrapper, `Uso`/example retained; delegates using `/usr/bin/python3 -I -B -X utf8` |
| `tests/automation_sandbox_sources.json` | Exactly two actual source additions: `consent/burp.py`, `consent/burp_cli.py`, at their full framework-relative paths |
| `tests/cross_module_fixture.py` | Exactly the same two source additions to `SOURCE_FILES` |
| `tests/test_cross_consent.py` | Refinements only inside the four existing Burp methods; no case/grant/selector additions |

`consent/files.py`, cleanup implementation/tests, menus, coordinators, the
runtime manifest, sandbox policy, the historical25 grants and all baselines
remain unchanged. No new module/helper responsibility outside Task3 was added.
File helpers are reused through `directory()` without modifying their cleanup
semantics. Burp-specific receipt publication/read validation stays in `burp.py`.

Public functions:

* `start_burp(framework: Path, port: int | None, ops: BurpOps) -> BurpInstance`
* `observe_burp(root: Path, instance_id: str | None, ops: BurpOps) -> BurpObservation`
* `verify_proxy(url: str, port: int, authorized: bool, ops: BurpOps) -> int`
* `stop_burp(root: Path, instance_id: str | None, ops: BurpOps) -> int`
* `consent.burp_cli.main(argv, *, framework: Path, ops: BurpOps) -> int`
  (framework/ops have production defaults; tests pass them explicitly).

Injection is Python-only. There is no CLI/environment operation override,
alternate executable/root flag, global consent flag or legacy-PID bypass.
Argument rejection returns2 before operational adapters run. Parser errors do
not echo rejected arguments, including potentially secret URL queries.

## Capability and consent matrix

| Capability | Before (`74d4139`) | Written Task3 behavior (NOT RUN) |
|---|---|---|
| GUI/manual Community | Public `[puerto]`, config, optional Start Burp click and manual guide | Same public opening; port1–65535, or first observed free8080–8099; normal `burpsuite` wrapper retained, no install. `ss` absence fails closed rather than socket probing |
| Opening and target | Opening could send session-derived curl GET and overwrite shared config/log/PID | No curl/request from opening. Optional fixed `.session` metadata configures only an escaped exact GUI scope; never determines a verification URL/permission. No session setter/registration; no environment session alias |
| GUI assistance | Optional confirmation then click using first matching window | Separate TTY phrase `INICIAR GUI`, one unambiguous numeric window, original geometry-based Start click retained. No click on refusal/EOF/ambiguous window; manual browser/CA/Repeater/export/injection guide remains |
| Observation/help | State calculation created `scans/burp`; fallback could connect TCP | `--help`, `--estado [--instance ID]` create no files/directories and open no sockets. Status reads only new administrative metadata and runs local `ss -ltn`; legacy artifacts are ignored/preserved. Unknown observation prints `NO_DETERMINADO`, never adopts a PID |
| Occupied port | Could be called a listening Burp/capture | Explicit occupied port returns nonzero before GUI/files, with `Puerto ocupado: N`, `Propietario: NO_DETERMINADO`, `Captura: NO_VERIFICADA`. An occupied TCP port never proves Burp ownership |
| Verification | Implicit session-derived HTTP request, insecure TLS and overstated success | Only `--verificar URL --proxy-port N --execute --confirm-network`, or `--execute` plus exact TTY `ENVIAR GET`. Full HTTP(S) URL, explicit port, no userinfo/controls/whitespace/fragment or curl URL expansion. Reject/EOF/generic yes sends nothing |
| Response claim | HTTP code treated as proxy/capture proof | Reports only observed HTTP code; does not certify origin, listener owner or capture. Transport error reports classified failure, not raw stderr/argv |
| Stop | Legacy numeric PID TERM/KILL; PID file removed | `--parar [--instance ID] --execute`; fresh private matching receipt, precheck identity, pidfd, recheck identity, TERM, wait5s, KILL only on that same fd if not exited; finally close. No receipt deletion, process-name/group/numeric-PID signals or daemon descendant adoption |
| Artifacts | Shared legacy config/log/PID/project paths | Fresh exclusive `scans/burp/instances/burp-<32 lowercase hex>/` with private config/log/receipt. Prior namespaces and all legacy objects are untouched |
| Coordinators/menu | Existing exclusions and old menu behavior | Unchanged here. No new automatic calls or offensive/scanning capabilities; Task4 owns menu integration/documentation |

Verification argv is exactly the reconciled test contract:

```text
curl --request GET --max-time 5 --noproxy ''
     --proxy http://127.0.0.1:N --output /dev/null
     --write-out %{http_code} -- URL
```

No redirects/retries/`-k` are added. For the curl child only, `CURL_HOME`,
`XDG_CONFIG_HOME` and `HOME` point to `/dev/null` so operator curlrc files cannot
silently enable extra requests/options; no directory is created. This is fixed
transport hardening, not a consent/environment bypass. stdout/stderr omit the
query/path and raw transport errors; the explicit URL necessarily exists in the
curl argv and can be visible to local process inspection, not claimed secret
storage. Response bodies are discarded rather than published as evidence.

## Receipt, filesystem and identity details

New config/log/receipt names are fixed and created with O_EXCL/O_NOFOLLOW/0600.
The namespace is an exclusive UUID-derived directory, explicitly0700; only newly
created parents are requested0700. Existing ancestors are not chmodded/adopted.
Every path component is opened using the existing no-follow directory helper.
Receipt/config publication is fsynced and never replaces an existing file.
Logs are private direct child stdout/stderr, not cross-instance append logs.

`instance.json` contains version1, matching instance_id, pid, start_ticks, uid,
boot_id and selected port. Receipt reads require owner=current user,
instance-directory0700, file0600, regular/single-link file, bounded16KiB,
positive integer PID/start ticks, integer UID and bounded nonempty boot ID.
O_PATH pins the leaf before regular-file validation; reads reopen only its
procfd, never a fresh leaf lookup. Symlinks/special objects and mismatched
namespace/schema fail closed. Session scope metadata is likewise pinned,
regular/single-link, bounded2KiB and used solely on opening, not status/help.

Production identity reads Linux `/proc/<pid>/{stat,status}` and current boot ID;
starttime parsing accounts for parentheses/spaces in comm. Real/effective/saved/
filesystem UIDs must all equal the caller. The direct Popen child handle remains
retained during initial receipt creation. If initial identity is unavailable
(e.g. wrapper already exited), config/log remain, managed=False is disclosed,
and no authoritative receipt or adopted descendant is invented.

Stop's exact success transport order is preserved from task1:

```text
identity(pid), pidfd_open(pid), identity(pid),
pidfd_send_signal(fd, SIGTERM), wait(fd, 5),
pidfd_send_signal(fd, SIGKILL) [only if wait returned false], close(fd)
```

All four identity fields must match on both observations. Missing pidfd, receipt
or identity/reused PID fails closed; no kill(0), kill(pid), pkill or killpg.
No-ID selection requires exactly one new namespace; multiple candidates
(including invalid receipts) block instead of choosing the first. Existing
receipt bytes remain unchanged after stop. Success means signal dispatch/wait
policy completed, not an independently observed terminal receipt or a claim
that every Burp descendant exited.

## Prior RED provenance — read as data only

Controller evidence on **74d4139**, not this amended code:
`/tmp/opencode/automation-isolated-e577873c6ac140329989a44d41ebb1c1/evidence/`.
Read only the Burp case registry matches and the four corresponding stderr logs;
no old run/helper was repeated.

| Existing Burp suffix | Prior log | Observed assertion |
|---|---|---|
| `test_burp_open_is_not_network_consent` | `case-00005.stderr.log` | line310: unexpected curl in `['ss','ss','burpsuite','ss','curl']` |
| `test_burp_status_has_no_side_effects` | `case-00006.stderr.log` | line343: snapshot changed; new scans/burp directories |
| `test_burp_verify_explicit_url` | `case-00007.stderr.log` | line364: invalid/missing-consent invocation returned0 |
| `test_burp_stop_pins_owned_identity` | `case-00008.stderr.log` | line383: missing --execute returned0 instead of2 |

The controller supplied65 sandbox units PASS, four cleanup PASS and four Burp
plus one menu assertion failures/zero errors for that selection. Its separate
`--suite` evidence at
`/tmp/opencode/automation-isolated-933c67b8cc984441a34c818c4ca32f27/evidence/`
was supplied as65+179, zero failures/errors, one pwsh SKIP. That second run was
not inspected/repeated here and neither historical run verifies Task3 changes.

## Amended test coverage — NOT RUN

All existing assertions retained. Added assertions inside only the same four IDs:

* Open: private instance artifacts, GUI scope retained without traffic, real
  business receipt publication through synthetic launch/identity transport, two
  independent namespaces and preservation of the first namespace bytes/inodes/modes.
* Status: inert help/unknown/conflicting modes/invalid instance, unchanged
  synthetic filesystem and no backend calls for parser-only modes.
* Verify: reject curl URL expansion; exact public TTY refusal/EOF/generic yes
  versus phrase acceptance using only a recorded request transport; no query
  exposure; real curl argument/environment construction with subprocess doubled.
* Stop: ambiguous no-ID selection and symlink receipt fail without even identity
  transport calls; original receipt preserved. Existing exact order, identity
  mutation before/after pin, unavailable pidfd, legacy and namespace forgery
  assertions remain.

No new IDs, grants, selectors, runtime utilities or general baseline refresh.
Cleanup and menu test AST bodies are identical to74d4139. This does not assert
the new tests pass or that imports/dependencies work in the selected runtime.

## Actual static verification and self-review

Only data-only AST/JSON/Git and Bash syntax checks were performed. No repository
module was imported, no product or double executable started, and no privileged
or network action was used. The wrapper's original tracked0755 mode was restored
after patch replacement; all other edits used patch.

Commands actually run:

1. `git status --short`, `git rev-parse --short HEAD`, `git diff --stat`,
   `git diff --summary` and scoped `git diff` for wrapper/manifests/fixture/tests,
   plus direct source reads of both new modules, for self-review.
   Initial tree clean at74d4139; only the six listed paths changed before report.
2. Two inline scripts invoked as `python3 -I -B - <<'PY'` with only stdlib
   AST/JSON/path reads and subprocesses for Git/Bash-n. The final script:
   - `ast.parse(Path(name).read_bytes(), filename=name)` on burp.py,
     burp_cli.py, cross_module_fixture.py and test_cross_consent.py; rejects CR.
   - `json.loads` source manifest; unique names, exact two additions and zero
     removals versus `git show 74d4139:<manifest>`.
   - `ast.literal_eval` of fixture SOURCE_FILES; exact same two additions only.
   - `ast.dump` of test method ASTs versus `git show 74d4139:<test>`: same nine
     method IDs, changed bodies exactly the four Burp names above.
   - validates wrapper LF/0755; runs `subprocess.run(['bash','-n',wrapper],
     capture_output=True,text=True)` and `git diff --check` the same way.
   Final output: four `AST/LF OK`; `JSON OK: exactly two additions, no
   removals/duplicates`; `FIXTURE OK: same two exact sources only`;
   `TEST AST OK: only four existing Burp bodies changed; same nine IDs`;
   `BASH-N: 0 '' ''`; `DIFF-CHECK: 0 '' ''`. Stderr captured and empty, not
   inferred from bash exit status alone. Both scripts exited0.
3. `git diff --cached --check`: rc0, empty output before implementation commit.
   Commit used `git -c core.hooksPath=/dev/null -c commit.gpgsign=false commit`
   to avoid executing unreviewed hooks or external signing during static-only work.

Manual source review checked parser-before-effects, no session-derived request,
fixed explicit GET argv, no numeric/name/group signal fallback, exact pidfd
sequence, bounded/pinned administrative reads, exclusive private publication,
unchanged cleanup/policy and no premature capture/terminal-exit assertions.
This is implementer self-review, NOT the required independent review.

## Concerns and next gate

* **Independent static review and exact controller execution authorization are
  still mandatory.** Neither `--cross-consent` nor `--suite` has been run on
  fcac367. The Task4 menu failure remains explicit and its integration untouched.
* Runtime import behavior, Python process startup scheduling, real/stub GUI
  execution and Linux pidfd behavior on amended code are unobserved here.
* Receipts are private same-user administrative metadata, not cryptographic
  provenance against malicious same-UID writers, privileged attackers, or an
  attacker controlling ancestors. No hostile-user/kernel certificate.
* Port observation is racy and not ownership proof; status always keeps owner
  NO_DETERMINADO and capture NO_VERIFICADA. No socket fallback or listener
  owner inference was introduced to hide this limitation.
* Burp may perform its own application traffic. No guarantee that GUI invocation
  makes the entire third-party application network-inert, or that Community
  honors the listener config. Optional geometry-based GUI assistance remains
  fallible/manual, and only a single unambiguous window is eligible.
* No process-tree/daemon control guarantee. Initial identity unavailable means
  no usable stop receipt; KILL dispatch does not certify full application exit.
* Legacy --parar now requires --execute and a new accredited receipt. Legacy
  paths/bytes remain untouched. Old BURP_LAUNCHER_ESPERA is not consumed; listener
  observation uses a fixed60s limit, not an environment execution/test bypass.
  The ignored Community --project-file argument was dropped; the in-memory
  project/history limitation and manual export remain disclosed.
* Source-specific old menu/baseline contracts may need intentional Task4
  reconciliation; none were broadly refreshed to anticipate a passing suite.
* No real operator configuration, evidence, logs or client data was inspected.
  No installs, sudo, cleanup, network/download, merge, push or workspace removal.
  All supplied historical evidence and all existing artifacts are preserved.

## Fix round1/5 — I1 Important and M1/M2 Minor, base99d00c0

**STATIC DONE_WITH_CONCERNS; amended tests NOT RUN.** Read the complete
`task-3-static-review.md` (71 lines) before this amendment. The controller
explicitly ruled that the single-request requirement overrides the incomplete
earlier exact-argv contract. This appendix supersedes the earlier argv and the
claim that `/dev/null` environment homes alone disable curl configuration;
the earlier delivery text is preserved as historical provenance, not silently
rewritten or treated as a valid guarantee.

### Findings addressed in source and covering oracles (unexecuted)

* **I1:** `BurpOps.request` now passes `--disable` as the FIRST argument after
  `curl`, explicitly disabling default configuration discovery, including its
  passwd-home fallback. The fixed environment values remain defense in depth,
  not the configuration-disabling boundary. Both the mandatory curl-double
  wrapper assertion and the real request-construction/subprocess-double
  assertion now require the complete updated argv, including first-position
  `--disable`. No operator curlrc/passwd-home files were inspected and curl was
  not executed. Independent review's manual evidence was read in the review
  document, not reproduced with backend execution.
* **M1:** Within `test_burp_open_is_not_network_consent`, added transport-only
  assertions through the actual `BurpOps.assist_gui`: TTY EOF, refusal and generic
  yes cause zero subprocess calls; a non-TTY exact phrase also causes none;
  exact consent with absent/ambiguous windows causes only the window search;
  accepted unique-window data exercises geometry parsing and asserts the exact
  search/xwininfo/raise/activate/mousemove-click sequence. Only stdin/stderr,
  executable availability and subprocess transport are doubled; GUI business
  functions are not replaced. No real display/executable/process was invoked.
  Within `test_burp_stop_pins_owned_identity`, added wait=True through the real
  public parser and stop function: exact identity/open/identity/TERM/wait5/close
  sequence with no KILL, and receipt bytes unchanged. Existing wait=False/KILL
  assertions remain; all identity/signal/wait/close transport stays synthetic.
* **M2:** After wait and optional assistance the CLI now passively reobserves,
  reports `Listener local: NO_OBSERVADO` or `NO_DETERMINADO` when applicable,
  warns Community may ignore the requested port, and gives Settings → Proxy →
  Proxy settings plus an instance-specific `--estado` command. A positive
  observation says only `OCUPADO`; it still does not establish owner/capture.
  No socket/curl fallback or additional wait loop is introduced. The manual
  browser/CA/Repeater/export guidance remains. Within the existing opening ID,
  actual parser/start/receipt/observation business logic is exercised with
  synthetic launch/identity/listener/wait/assistance transports: assert passive
  post-assistance observation order and output for absent, unknown and occupied
  final listener, actionable advice on negative/unknown results, retained
  Repeater guide and NO_VERIFICADA capture statement. The fixture's real/stub
  GUI and production60s wait are not needed by these new assertions.

Updated argv (supersedes the earlier reconciled argv in this report):

```text
curl --disable --request GET --max-time 5 --noproxy ''
     --proxy http://127.0.0.1:N --output /dev/null
     --write-out %{http_code} -- URL
```

No redirects/retries/`-k`, URL expansion, session-derived permission or new
requests were added. URL argv visibility and all previous same-UID receipt,
daemon/process-tree, GUI geometry, Linux/procfd/pidfd and operational-compatibility
limits remain. This is a written implementation correction, not an observed
single-request runtime certificate. GUI assistance tests describe local UI
transport behavior, not a guarantee that third-party Burp itself is network inert.

### Exact static commands and results

Only three source paths amended: `consent/burp.py`, `consent/burp_cli.py` and
`tests/test_cross_consent.py`, plus this report. No menus, selectors, case IDs,
runtime/source manifests, fixture grants, permissions or baselines changed.
Existing artifacts and the independent review are preserved.

Actual commands in this round:

* `git status --short`: initial output empty at the supplied base.
* Scoped `git diff -- CyberSecurity-Framework/00_Config/lib/consent/burp.py
  CyberSecurity-Framework/00_Config/lib/consent/burp_cli.py
  CyberSecurity-Framework/tests/test_cross_consent.py`: read the entire patch
  for self-review, including first-argument ordering, listener observation
  sequence, transport-only GUI oracles and graceful wait fd closure.
* Data-only inline script: `python3 -I -B - <<'PY'`, importing only stdlib
  `ast`, `json`, `Path`, `subprocess`; no repo imports or product execution.
  It ran these exact checks:
  - `ast.parse(data, filename=name)` and `assert b'\r' not in data` on the
    three amended Python sources: all three `AST/LF OK`.
  - `git show 99d00c0:CyberSecurity-Framework/tests/test_cross_consent.py`
    via captured subprocess; compare test function names and `ast.dump` bodies:
    nine unchanged IDs, changed bodies exactly opening/verification/stop.
    Output: `TEST IDS OK: nine unchanged IDs; only open/verify/stop bodies amended`.
  - Locate `BurpOps.request` and its subprocess.run first argv AST list;
    `ast.literal_eval` of its first two elements equals `['curl','--disable']`.
    Output: `ARGV AST OK: curl --disable first; no module import/execution`.
  - `json.loads` both `automation_sandbox_sources.json` and
    `automation_sandbox_manifest.json`; compare bytes against captured
    `git show 99d00c0:<path>`: unchanged. Output:
    `JSON OK: source/runtime manifests unchanged`.
  - Captured `bash -n CyberSecurity-Framework/03_Scanners/web_scanners/burpsuite/burp_launcher.sh`:
    rc0, stdout `''`, stderr `''`.
  - Captured `git diff --check`: rc0, stdout `''`, stderr `''`.
  The inline script exited0. Bash stderr was explicitly captured, not inferred
  from rc alone. These checks parse source data, not execute test assertions.

No repo imports/helpers/tests/probes/launcher/product/backends/stubs were run,
even sandboxed. No network, display, real process signal, sudo, installation,
download, cleanup, subagent, merge or push. Self-review is not independent
rereview. All three findings are addressed in source and covering written
oracles; **runtime correctness remains unverified** until independent static
rereview and separate exact controller authorization. Task4 remains untouched
and pending. No GREEN or global closure is asserted.
