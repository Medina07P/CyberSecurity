# Offline PCAP/Windows adapters. Runtime owns copies, metadata and processes.
_FORENSICS_ADAPTER_SOURCE="${BASH_SOURCE[0]:-$0}"
source "${_FORENSICS_ADAPTER_SOURCE%/*}/forensics_runtime.bash" || return 2

forensics_offline_validate() {
    python3 -B - "$1" "${2:-file}" "${FORENSICS_ANALYSIS_ROOT:-$_FORENSICS_MODULE/analysis}/runs" <<'PY'
import os, pathlib, stat, sys
try:
    source = pathlib.Path(os.path.abspath(sys.argv[1]))
    root = pathlib.Path(os.path.abspath(sys.argv[3]))
    for path in (source, root):
        for part in (path, *path.parents):
            if part.is_symlink(): raise ValueError()
    mode = source.stat().st_mode
    if not (stat.S_ISREG(mode) if sys.argv[2] == 'file' else stat.S_ISDIR(mode)): raise ValueError()
    if not os.access(source, os.R_OK) or not mode & 0o444: raise ValueError()
    if root == source or root in source.parents or source in root.parents: raise ValueError()
except (OSError, ValueError):
    print('Entrada o destino forense no válido.', file=sys.stderr)
    sys.exit(2)
PY
}

# Parse only captured private files; stdout is a bounded control value, not data.
forensics_adapter_inspect() {
    python3 -B - "$@" <<'PY'
import os, pathlib, re, sys
mode, path, *args = sys.argv[1:]
if mode == 'symbols':
    sys.exit(0 if any(p.is_file() for p in pathlib.Path(path).rglob('*')) else 1)
text = pathlib.Path(path).read_text(errors='replace')
if mode == 'family':
    if args: text += pathlib.Path(args[0]).read_text(errors='replace')
    if re.search(r'Volatility(?: Foundation)? Volatility Framework 2\.', text): print('v2')
    elif re.search(r'Volatility 3 Framework [0-9]+\.', text): print('v3')
    else: sys.exit(1)
elif mode in ('has', 'vol_has'):
    if mode == 'vol_has': text += '\n' + pathlib.Path(os.environ['FORENSICS_VOL_HELP_ERR']).read_text(errors='replace')
    sys.exit(0 if all(re.search(r'(?<![\w.-])'+re.escape(x)+r'(?![\w.-])', text) for x in args) else 1)
elif mode == 'profile':
    match = re.search(r'Suggested Profile\(s\)\s*:\s*(Win[A-Za-z0-9_]+)(?=\s|,|$)', text)
    if not match: sys.exit(1)
    print(match[1])
elif mode == 'windows':
    sys.exit(0 if re.search(r'^\s*NTBuildLab\s+\S+', text, re.M) and not re.search(r'Linux version', text) else 1)
elif mode == 'not_linux':
    sys.exit(1 if re.search(r'Linux|Mac[A-Za-z]|Darwin', text) else 0)
elif mode == 'requirements':
    text += pathlib.Path(args[0]).read_text(errors='replace')
    sys.exit(0 if re.search(r'unsatisfied requirement|unable to validate.*requirement', text, re.I) else 1)
elif mode == 'capinfo':
    sys.exit(0 if 'File type:' in text and re.search(r'^Number of packets:\s*[0-9][0-9,. kMGT]*\s*$', text, re.M) else 1)
elif mode == 'tshark_version':
    sys.exit(0 if re.search(r'TShark \(Wireshark\) [1-9][0-9]*\.[0-9]+\.', text) else 1)
elif mode == 'stats':
    text += pathlib.Path(args[0]).read_text(errors='replace')
    sys.exit(0 if 'available statistics' in text.lower() and all(re.search(r'^\s*'+re.escape(x)+r'\s*$', text,re.M) for x in ('io,phs','conv,tcp','conv,udp')) else 1)
else: sys.exit(2)
PY
}

forensics_adapter_complete() {
    local name=$1 rc=$2 state=${3:-COMPLETADO} coverage=${4:-offline_evaluated}
    [[ ${_FORENSICS_FAILED:-1} = 0 && ${_FORENSICS_CANCELLED:-0} = 0 ]] || return 1
    if (( rc != 0 )); then state=FALLIDO; coverage=offline_tool_failed; fi
    forensics_complete_step "$name" "$state" "$coverage"
}

forensics_adapter_unavailable() {
    printf 'Cobertura offline no evaluable en esta instalación.\n' >&2
}

forensics_adapter_private_home() {
    # Preserve relative PATH entries before moving to the private backend cwd.
    PATH=$(python3 -B -c 'import os; print(os.pathsep.join(os.path.abspath(p) for p in os.environ["PATH"].split(os.pathsep)))') || return 1
    export PATH
    HOME="$FORENSICS_RUN_DIR/home"; XDG_CACHE_HOME="$FORENSICS_RUN_DIR/cache"
    XDG_CONFIG_HOME="$FORENSICS_RUN_DIR/config"; TMPDIR="$FORENSICS_RUN_DIR/tmp"
    export HOME XDG_CACHE_HOME XDG_CONFIG_HOME TMPDIR
    python3 -B -c 'import os,sys; os.umask(0o077); [os.mkdir(p,0o700) for p in sys.argv[1:]]' \
        "$HOME" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" "$TMPDIR" || return 1
    cd -- "$FORENSICS_RUN_DIR" || return 1
}

forensics_adapter_noeval() {
    forensics_capture "$1" forensics_adapter_unavailable || return 1
    forensics_adapter_complete "$1" 0 NO_EVALUABLE "$2"
}

# No output data: validated selection is returned in exported control variables.
# Must be called in the owner shell AFTER staging all sources.
forensics_volatility_detect() {
    local requested=${1:-auto} candidate path family rc index=0
    FORENSICS_VOL_FAMILY=; FORENSICS_VOL_COMMAND=; FORENSICS_VOL_HELP=; FORENSICS_VOL_HELP_ERR=
    for candidate in volatility vol vol.py; do
        path=$(command -v -- "$candidate") || continue
        [[ $path = /* ]] || path="$PWD/$path"
        (( index += 1 ))
        FORENSICS_VOL_COMMAND=$path
        export FORENSICS_VOL_COMMAND
        forensics_capture "backend_help_$index" forensics_volatility_command -h
        rc=$?
        family=
        if (( rc == 0 )); then family=$(forensics_adapter_inspect family "$FORENSICS_STEP_OUT" "$FORENSICS_STEP_ERR"); fi
        forensics_adapter_complete "backend_help_$index" "$rc" COMPLETADO backend_help_observed || return 1
        if [[ -n $family && ( $requested = auto || $family = "$requested" ) ]]; then
            FORENSICS_VOL_FAMILY=$family
            FORENSICS_VOL_HELP=$FORENSICS_STEP_OUT
            FORENSICS_VOL_HELP_ERR=$FORENSICS_STEP_ERR
            export FORENSICS_VOL_FAMILY FORENSICS_VOL_HELP FORENSICS_VOL_HELP_ERR
            return 0
        fi
    done
    FORENSICS_VOL_COMMAND=
    forensics_adapter_noeval backend unsupported_backend || return 1
    printf 'Backend Volatility solicitado no reconocido o incompatible.\n' >&2
    return 1
}

forensics_volatility_command() { "$FORENSICS_VOL_COMMAND" "$@"; }

# NAME is a fixed identifier; PLUGIN must have been advertised by captured help.
forensics_volatility_run() {
    local name=$1 plugin=$2 rc state=COMPLETADO coverage=offline_evaluated
    if ! forensics_adapter_inspect vol_has "$FORENSICS_VOL_HELP" "$plugin"; then
        forensics_adapter_noeval "$name" plugin_unavailable
        return 1
    fi
    if [[ $FORENSICS_VOL_FAMILY = v3 ]]; then
        forensics_capture "$name" forensics_volatility_command --offline \
            --symbol-dirs "$FORENSICS_VOL_SYMBOLS" --cache-path "$XDG_CACHE_HOME" \
            -f "$FORENSICS_VOL_WORK" "$plugin"
    elif [[ $plugin = imageinfo ]]; then
        forensics_capture "$name" forensics_volatility_command -f "$FORENSICS_VOL_WORK" imageinfo
    else
        forensics_capture "$name" forensics_volatility_command -f "$FORENSICS_VOL_WORK" \
            "--profile=$FORENSICS_VOL_PROFILE" "$plugin"
    fi
    rc=$?
    # The caller evaluates imageinfo/info before publishing that particular step.
    if [[ $name = imageinfo ]]; then return "$rc"; fi
    if (( rc == 0 )) && forensics_adapter_inspect requirements "$FORENSICS_STEP_OUT" "$FORENSICS_STEP_ERR"; then
        state=NO_EVALUABLE; coverage=plugin_requirements_unsatisfied
    fi
    forensics_adapter_complete "$name" "$rc" "$state" "$coverage" || return 1
    return "$rc"
}
