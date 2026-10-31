# AGENTS.md

Red-team / pentest framework: 114 Bash scripts plus a few Python helpers, targeted at Kali Linux. `README.md` is the pitch; this file is the working knowledge.

## Current state (2026-10-31)

Read `docs/CLEANUP-2026-10-30.md` before changing anything: it records the cleanup session (44 files quarantined outside the repo, 8 bugs fixed, every absolute path replaced with self-location) and the evidence backing it. Both tasks it left open are done, same day: the scan-output convention was unified in `docs/SCANS-PATHS-2026-10-30.md` (every script now writes to `<repo>/scans/<tool>/`, resolved from its own location — the two `scans/` trees were merged) and `12_Knowledge_Base/cheatsheets/linux_priv_esc.md` was expanded to parity with the Windows sheet. The interactive manager was then rebuilt around a session target and a `Uso:` parser (`docs/GESTOR-2026-10-30.md`). Session state is also stored in `ck` (`/ck:resume CyberSecurity`).

On 2026-10-31 the framework ran for real on Kali against the local host. Nine bugs appeared and were fixed — including the outputs that depended on the caller's `cwd` — plus the `:8443`-is-not-HTTP scheme assumption. `docs/PATHS-KALI-2026-10-31.md` has the symptoms, causes, fixes and evidence; read it before touching any output path.

The same day the framework was pointed at a real web app (`el-objetivo-del-engagement`), which exposed a different class of defect: tools reporting "findings" that were only their own echo, and failures that looked like clean results. Eleven fixes followed — the shared `scans.bash` library (paths, slugs, catch-all baseline, ffuf hit counting), zsh-safe library paths, `run_all_recon.sh` honouring its target, target-named outputs, `stderr` into `errores.log`, `splitext` for the JSON report, reports labelled as templates, and generated reports out of git. `docs/ARREGLOS-FRAMEWORK-2026-10-31.md` records each one with its evidence; the engagement report is `CyberSecurity-Framework/11_Reports/final_report/informe_objetivo_2026-10-31.md`.

## Where it runs

- On Kali it runs for real (this clone, `/home/kali/Documentos/CyberSecurity`). Tooling gaps as of 2026-10-31: `rustscan`, `volatility3`, `foremost` and `nmap-vulners` are not installed; `masscan` needs root; no WiFi/Bluetooth adapter.
- The Windows checkout cannot run it. Scripts need Linux tooling (`nmap`, `sudo masscan`, `dig`, `md5sum`, `apt`) that is not installed there. WSL has no distro; Git Bash (`C:\Program Files\Git\bin\bash.exe`) only enables syntax checks.
- Verification available without running a tool: `bash -n <file>` (all 114 framework `.sh` plus the 4 under `tests/` currently pass), `bash -n 00_Config/lib/*.bash`, and `python -m py_compile` for the `.py` files (all 6 pass). The four suites under `tests/` are the real check for the manager. Do not claim a scan or audit result you did not produce.
- `bash -n` exits 0 on an **unterminated heredoc** — it only prints a warning to stderr. Two scripts (`01_OSINT/scripts/social_media_search.sh`, `05_Exploitation/web/reverse_shell_php.sh`) were truncated that way until 2026-10-30. When verifying, capture stderr, not just the exit code.
- Keep `.sh`/`.py` LF — `core.autocrlf=true` is set in this clone.

## Layout: two layers

- `CyberSecurity-Framework/` is the product. `cyber_framework.sh` is the interactive manager (`00`–`13` modules, `99` runs every phase's `run_all_*.sh`); it discovers scripts recursively and must be started from the framework root.
- The root holds only documentation and generated data: `README.md`, `.gitignore`, `AGENTS.md`, the generated `scans/`, and `CyberSecurity-Framework/`. The 31 bootstrap files that used to live here were quarantined on 2026-10-30 (`MANIFEST.md` in `%TEMP%\opencode\cybersec-root-cleanup-20261030` explains each one and how to restore it). Two of them were ported rather than dropped: the old `run_all_enum.sh`'s `timeout`/closed-port handling now lives in `04_Enumeration/run_all_enum.sh`, and `readme03.sh` became `03_Scanners/README.md`. `project_manager.sh` and `workflow_orchestrator.py` were dead: nothing referenced them, both hardcoded `~/CyberSecurity-Framework`, and `cyber_framework.sh` is the only entry point (it does not manage projects — the `00_Config/projects/` + `status.json` concept had no consumer anywhere).
- The framework's own bootstrap generators were quarantined in a second batch (9 files removed; 7 are recoverable in the `framework-generators/` subfolder of the same quarantine — two `creacion.sh` copies were lost to a filename collision, see that folder's `MANIFEST.md`): `run.sh`, `converter.sh`, `05_Exploitation/creacion.sh`, `07_Wireless/creacion.sh`, `12_Knowledge_Base/creacion.sh`, `04_Enumeration/corregir.sh`, `10_Evidence/setup_10_evidence.sh`, `11_Reports/setup_11_reports.sh`, `13_Labs/setup_13_labs.sh`. Every file they wrote already existed. `run.sh` regenerated four `run_all_*.sh`; `converter.sh` rewrote every script in place; `corregir.sh` would have reintroduced the `scans/` path bug fixed in `show_results.sh`.
- Generated data, not source: `scans/` at the repo root (scan results) and, anchored to each module, `01_OSINT/{domains,emails,metadata,social_media,subdomains}`, `02_Recon/{dns,fingerprinting,host_discovery,screenshots}`, `06_PostExploitation/{loot,persistence}`, `07_Wireless/captures`, `08_Forensics/{analysis,recovered}`, `10_Evidence/{screenshots,pcaps,logs,proofs,findings,credentials}` and `11_Reports/{executive,technical,final_report}`; plus `captures/memory/` (memory dumps) and `02_Recon/recon_<target>_<timestamp>/` inside the framework. Do not delete or "tidy" them.
- Two directories inside the framework are not tools: `00_Config/lib/` (the manager's library, `.bash` extension so it never shows up as a runnable script) and `tests/` (four test scripts: the library, the end-to-end run, the smoke menu, and the config wizard). `run_all_config.sh` only iterates `scripts/*`, so it never executes the library, and it skips `config_wizard.sh` because that one waits for keyboard input.
- Git: branch `develop`, remote `https://github.com/Medina07P/CyberSecurity.git`. Since 2026-10-30 the framework is versioned in an initial import split by module. The root `.gitignore` excludes every generated tree (`scans/`, `loot/`, `captures/`, `dns/`, `fingerprinting/`, `02_Recon/recon_*/`, evidence, generated reports and payloads): those hold real IPs, banners and credential lists from past sessions and must not reach a public remote. `00_Config/.gitignore` covers credentials and the manager's `.session`. When you add a new output directory, add it there too.

## Generator wrappers are not the tool

These files are `cat > <path> << 'EOF' … EOF` heredocs that *write* the real script to a home-directory path:

- `04_Enumeration/smb/enum_smb.sh`
- `04_Enumeration/web/deepseeenum_web.sh` (writes `enum_web.sh` beside it)
- `06_PostExploitation/lateral_movement/ps_exec.sh`
- `06_PostExploitation/privilege_escalation/linpeas.sh`

These are the only wrappers left; more of them (and all the `creacion.sh` / `setup_*.sh` run-once generators) were removed in the 2026-10-30 cleanup.

`05_Exploitation/exploits/reverse_shell.py` and `09_Automation/python/auto_audit.py` used to belong to this list: they were bash wrappers that rewrote *themselves* into real Python on first run. On 2026-10-30 that payload was materialised directly, so they are now ordinary Python scripts and every `.py` in the framework passes `python -m py_compile`.

`01_OSINT/scripts/osint_harvester.sh` was the same case in bash: its `TARGET_FILE` was its own path, so the first run replaced the wrapper with its payload and the manager's `[generador]` mark disappeared with it. On 2026-10-31 it was materialised, like the Python pair. It is now an ordinary script, and `tests/run_smoke.sh` checks the `[generador]` mark in `06`.

Edit the body between the `cat` line and the closing `EOF`. Editing the wrapper changes what gets generated, and its target path points outside this repo.

## The manager and its library

`cyber_framework.sh` is the only entry point. Since 2026-10-30 it sources four files from `00_Config/lib/` (all `.bash`, so `find -name '*.sh'` never lists them as tools):

| File | Contract |
|---|---|
| `params.bash` | Reads each script's own `Uso:` line: `params_mode` → `none` / `manual` / `slots`; `params_slots` → `posicion / nombre / obligatorio / tipo`; `params_example_values` → defaults from `Ejemplo:` only when its token count matches the slot count |
| `session.bash` | `session_target` / `session_set_target` / `validate_target`, `targets_from_config`, `scope_allows` (best effort, warns rather than blocks). Persists in `00_Config/.session`, git-ignored |
| `phase_status.bash` | `phase_state` → `done` / `pending` / `na`, deduced from evidence on disk (files under `scans/`, `02_Recon/recon_*`, …) — no state file |
| `prompt.bash` | `prompt_for_slots` → **values on stdout, all UI on stderr**. That split is the fix for the original bug, where the prompt text was captured as the argument |
| `dangerous.txt` | One framework-relative path per line; those ask for confirmation and do not take `Ejemplo:` defaults |

Two rules worth keeping:

- Any function that returns a value to a caller must print **only** the value to stdout. This is the bug that made the manager unusable: it printed the prompt to stdout and the caller captured the whole block.
- A `Uso:` line with `--flags` or a bare first token (`monitor` in `interface_manager.sh`) is passed through in **manual mode**: the manager shows the usage and you type the whole argument line. It never guesses positions for those.

Verify with `tests/run_tests.sh` (library, 61 asserts), `tests/run_e2e.sh` (a script really receives the typed value, 11 asserts) and `tests/run_smoke.sh` (menu navigation with piped input). All three run on Windows/Git Bash without a terminal, and they pass in a clean clone (no `scans/` present) because the phase tests build their own fixture.

## Running a script

- Scripts self-locate: no result path depends on the `cwd`. Scan results resolve the repo root from `${BASH_SOURCE[0]}` and go to `<repo>/scans/<tool>/`, so `cd 03_Scanners && ./run_all_scanners.sh <TARGET>`, `bash 03_Scanners/run_all_scanners.sh <TARGET>` and a launch from `/tmp` all land in the same place. Module-owned artifacts (loot, captures, emails, evidence, reports) are anchored to their module with `MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"`, never to `$PWD`. `run_all_*` and `show_results.sh` additionally `cd` to their own directory, because they invoke siblings as `./hermano/...`.
- Contract: `run_all_*` take one positional target; leaf scripts add port/URL (`./enum_web.sh <IP> [PUERTO]`). Missing args print a `Uso:`/`Ejemplo:` block and `exit 1`.
- `cyber_framework.sh` detects the required parameter from the filename and the `Uso:`/`Ejemplo:` lines, so those lines are functional, not decoration.

## Orchestrators are dead code

- `09_Automation/python/orchestrator.py` resolves the framework root from its own location (`Path(__file__).resolve().parents[2]`), so it works wherever the repo is cloned. `09_Automation/workflows/*.yaml` are declarative only; nothing parses them (`yaml` is imported only by `orchestrator.py`; pyyaml is installed).
- `python3 09_Automation/python/report_generator.py --input <dir> --output <file>` is the one self-contained Python entrypoint.

## Config and data formats

- `00_Config/targets.txt`: `IP|PORT|PROTO|DESCRIPTION|PRIORITY` (C/A/M/B), `#` comments. `parse_targets.py` needs ≥3 pipe-separated fields; `02_Recon/run_all_recon.sh` greps for `|` and uses only the first 3 targets. `00_Config/scripts/config_wizard.sh` is the guided way to add entries: it writes the same format, offers to append (marking the batch with a dated comment) or to start a new list (the old one becomes `targets.txt.bak`), and never touches `scope.yaml`.
- `00_Config/scope.yaml`: project scope, allowed ports, rules of engagement, authorization. Parses with PyYAML and is LF-normalised (it used to be CR-only, so `wc -l` said 0 and `grep` saw one line).
- `00_Config/credentials/` exists with `README.md` + `.gitkeep`; `00_Config/.gitignore` ignores its contents but not those two files. `validate_config.sh` and `verify_00_config.sh` both pass with 0 errors.
- `README.md` no longer tells you to copy a `scope.yaml.example` (never existed; edit `scope.yaml` directly).
- Output names derive from the target (`:` and `/` become `_`), e.g. `scans/nuclei/nuclei_http___127.0.0.1.txt`.

## Writing new scripts

- Match the house shape: `#!/bin/bash`, header block with `Uso:` and `Ejemplo:`, argument validation with `exit 1`, results under `<repo>/scans/<tool>/` via `OUTPUT_DIR=$(scans_dir <tool>)`, Spanish user-facing messages.
- No script uses `set -e`. Prefer not to hide tool failures: in `03_Scanners/` each tool invocation writes `2>>"$OUTPUT_DIR/errores.log"` and the script announces the log when it is non-empty (`run_all_scanners.sh` lists the non-empty ones at the end). A discarded `2>/dev/null` turns "the tool failed" into "0 findings" — that ambiguity is what the `errores.log` convention exists to kill. Only probes (`command -v`, a `grep` over a file that may not exist) keep `2>/dev/null`.
- Output names carry the target: `SLUG=$(scans_slug "$TARGET")` and files go to `<tool>_${SLUG}.txt`. Without it two runs overwrite each other and the last target wins. Ports and schemes build the URL, the slug names the file.
- Use the shared library instead of hand-built paths. `source` `00_Config/lib/scans.bash` and use `OUTPUT_DIR=$(scans_dir <tool>)` (creates it), `scans_slug`, `scans_signature <url>` → `code:size`, `scans_ffuf_count <json>` → real hits from `results`, and `scans_baseline_size <url>` → the catch-all body size, `0` when the server 404s properly. Any fuzzing or injection probe must compare against a baseline first: against a SPA that answers `200` to everything, an unbaselined probe reports every candidate as a finding (90 false positives on the 2026-10-31 engagement).
- No script may hardcode a home path (`~/CyberSecurity-Framework`, `~/Documentos/...`). The library resolves the repo root from its own location, so `scans_dir` works from any `cwd`. If you must resolve a path by hand: `SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)/scans"` — one `..` per directory level between the script and the parent of `CyberSecurity-Framework/`, so `03_Scanners/<cat>/<tool>/x.sh` needs four, `<module>/<sub>/x.sh` needs three, `<module>/x.sh` needs two. Python uses `Path(__file__).resolve().parents[2]`. Every stale absolute path was removed on 2026-10-30 — do not reintroduce them.
- Library files are sourced, so they must resolve their own path without `BASH_SOURCE` alone: `${BASH_SOURCE[0]:-$0}`, because zsh leaves `BASH_SOURCE` empty and `$0` then holds the sourced file. Without it every library path silently becomes the framework root.
- Outputs that are not scan results (loot, captures, evidence, reports, emails) belong to their module: `MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"` for `<module>/<sub>/x.sh`, then `OUTPUT_DIR="$MODULE_DIR/<dir>"`. A raw `../loot` or `$(pwd)` depends on the caller's `cwd` and writes outside the ignored trees when the manager runs the script from the framework root (this was fixed on 2026-10-31; see `docs/PATHS-KALI-2026-10-31.md`).
- Slot names in the `Uso:` line are parsed as `pos|nombre|obligatorio|tipo`, so never put `|` inside `<...>` or `[...]`: use `<red>` and document the alternatives in a comment. `tests/run_tests.sh` asserts the slot count and types (`ping_sweep.sh` is the canary).
- The `nmap_smart.sh` duplicate is gone (2026-10-30): `03_Scanners/network_scanners/nmap/nmap_smart.sh` is the only copy and the one `run_all_scanners.sh` uses. The removed `nmap/scripts/nmap_smart.sh` was the older, `-Pn`-less variant. Beware `nmap_scripts.sh`: its `OUTPUT_DIR` is `$SCANS_DIR/nmap/scripts`, an output folder, not a script folder.

## Safety

All execution must stay inside authorized scope (`00_Config/scope.yaml`). `run_all_*` and menu option `99` chain brute-force, persistence and cleanup scripts against every configured target — never launch them as a casual smoke test.
