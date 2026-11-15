# Task3 — static delivery, pending independent review / runtime gate

2026-11-14; base `93805a6`. **Implementation written, NOT runtime verified.**
No Task3 GREEN, Task1/Task2 completion, Task9/global closure or operational claim.

## Exact public API / flags

Framework-relative public path unchanged:

```text
06_PostExploitation/privilege_escalation/linpeas.sh
  --binary FILE --execute --allow-sudo
  --download --execute --allow-sudo
  --preview (default)
  --help
  --generate DESTINO
```

`00_Config/lib/consent/stable_tools.py` exports:

```python
run_linpeas(binary: Path | None, download: bool, allow_sudo: bool, root: Path, ops: LinpeasOps | None = None) -> int
class LinpeasOps(run_id, run_dir, source_path, download_path, stdout_path, stderr_path, backend)
```

Rules: no source without explicit `--binary` or `--download`; no execution without both
`--execute` and `--allow-sudo`; `--binary` and `--download` are incompatible; invalid,
missing or symlinked local paths are rejected; `linpeas_real.sh` is never adopted from
cwd. Download uses only fixed HTTPS URL, curl if present else wget only when curl is
absent, 60s and 16MiB limits, no install/new URL. Downloaded output is not presented
as authenticated.

New data is created under `scans/linpeas/<uuid>/` with directories 700 and files 600.
A local selected source is copied explicitly into the run directory; execution uses
`sudo /bin/bash <copied source>` with argv and private stdout/stderr files, preserving
the backend rc. Partial download/selected artifacts are retained on failure.

## Consumer matrix

| Source / consumer | Written behavior (NOT RUN) |
|---|---|
| public linpeas.sh | stable self-locating Bash -> isolated Python parser; no self-materialization |
| consent/stable_tools.py | typed `run_linpeas`, private run dirs, explicit source validation, curl/wget selection, argv execution |
| consent/stable_cli.py | closed linpeas modes and `--generate` |
| postexploitation_menu.bash 06.2 | explicit local/download/cancel subselection before linpeas; dangerous remains |
| run_all_post.sh | omits linpeas with reason "selección explícita requerida"; counts 6 executed, 0 failed, 2 omitted |
| dangerous.txt | linpeas already present |

## Prior RED read as data

Read the two Task3 linpeas oracles from `test_cross_local.py` before implementation:
`test_linpeas_requires_explicit_source_and_sudo` and
`test_linpeas_failures_preserve_artifacts`. They define no-args/preview/generation,
incompatible source flags, missing permissions, invalid/link paths, curl/wget/sudo
failure preservation, modes and partial artifacts. No runtime RED was executed here.

## Actual static verification (no repository import/execution)

1. `/bin/bash --noprofile --norc -n` on `linpeas.sh`, `postexploitation_menu.bash`,
   `run_all_post.sh`: rc0, stderr empty.
2. `python3 -m py_compile` on `stable_tools.py` and `stable_cli.py`: rc0.
3. `git diff --check`: rc0, empty.
No helper, test, discovery, launcher, probe, product, double, backend, network/GUI,
sudo, install, download, cleanup, reset, merge or push was executed. No runtime tree
was created.

## Source provenance

| Framework-relative source | Base SHA-256 | Delivery SHA-256 |
|---|---|---|
| 06_PostExploitation/privilege_escalation/linpeas.sh | 4e4ba9d30185a171037f781c142ac43c25790c9ba92429a1b49e915ceeeeb149 | 2c73c188a5d068bb244378e102dafcfdf123a01e1b68741a1b5eb6ef2152de6d |
| 00_Config/lib/consent/stable_tools.py | NEW (appended) | 80e9514806b1e0ca62eb057d3b98425e2688cc9b48096dabdd68474bc70bcd1c |
| 00_Config/lib/consent/stable_cli.py | 03c4f202bd8cd5b8013609f7f6a96da05cbf1555f815ab0c4bb4cd1a4642d9f3 (Task2) | 8d9b29a4599cb617c89a9a5c0153e7bfae73bdf7080cb3e8c1e8bad3908017ca |
| 00_Config/lib/postexploitation_menu.bash | current base | 559c7a97fc43bdb4aa5f9a1e2e506ac75531491f3c8759858f095590ac93d94b |
| 06_PostExploitation/run_all_post.sh | current base | 38f10b32a37594d869ad683b2b62fc19bee3fd2ebf1f52df37fb76e1667c5447 |

## New runtime NOT RUN

No runtime, tests, coordinator, sandbox, backend, sudo or download execution was performed.
Independent review and controller authorization are still required.
"""
## Fixwave1 (static) — 2026-11-15

Base e25d276. Applied only Critical 1–3 plus narrow Important items; runtime NOT RUN.

Changes:
- stable_tools.py: added `import os` (Critical 1). `_valid_local_binary` now rejects non-absolute paths (no cwd adoption) (Important).
- postexploitation_menu.bash: local branch now `--prepared --binary "$linpeas_binary" --execute --allow-sudo` (Critical 2).
- tests/test_post_run_all_pending.py: removed linpeas from LEAVES (8→7); `Ejecutadas: 7 | Fallidas: 7`; screenshot case `Ejecutadas: 6 | Fallidas: 0 | Omitidas: 2`; calls 7→6 (Critical 3).
- wget fallback: product already uses `shutil.which('curl')` at runtime and only wget when curl absent; documented, double unchanged (Important).
- download ops paths: recorded as minor provenance loss; final stdout/stderr paths computed before run (Important).

Static commands/results:
- bash -n postexploitation_menu.bash linpeas.sh run_all_post.sh: rc0, stderr empty.
- python3 -m py_compile stable_tools.py stable_cli.py: rc0.
- git diff --check: rc0, empty.
No tests/helpers/probes/backends/executables/runtime run; no push/merge.
