# Module 08: sequential single-owner runtime. Source, never execute as a leaf.
# Stage ALL inputs before captures; each analyzer must use its own run/copies.
_FORENSICS_SOURCE="${BASH_SOURCE[0]:-$0}"
_FORENSICS_LIB_DIR="$(CDPATH= cd -- "${_FORENSICS_SOURCE%/*}" && pwd)"
_FORENSICS_HELPER="$_FORENSICS_LIB_DIR/forensics_evidence.py"
_FORENSICS_MODULE="$_FORENSICS_LIB_DIR/../../08_Forensics"

_forensics_helper() {
    python3 -B "$_FORENSICS_HELPER" "$@"
}

_forensics_field() {
    python3 -B -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

forensics_require() {
    if ! command -v -- "$1" >/dev/null 2>&1; then
        printf 'Falta dependencia forense requerida.\n' >&2
        return 2
    fi
}

forensics_begin() {
    local metadata
    _FORENSICS_FAILED=1
    umask 077
    forensics_require python3 || return 2
    forensics_require setsid || return 2
    forensics_require bash || return 2
    FORENSICS_ANALYSIS_ROOT="${FORENSICS_ANALYSIS_ROOT:-$_FORENSICS_MODULE/analysis}"
    FORENSICS_RECOVERED_ROOT="${FORENSICS_RECOVERED_ROOT:-$_FORENSICS_MODULE/recovered}"
    FORENSICS_MEMORY_ROOT="${FORENSICS_MEMORY_ROOT:-$_FORENSICS_MODULE/../captures/memory}"
    metadata=$(_forensics_helper init --root "${3:-$FORENSICS_ANALYSIS_ROOT/runs}" \
        --operation "$1" --mode "$2") || return "$?"
    FORENSICS_RUN_DIR=$(printf '%s' "$metadata" | _forensics_field run_dir) || return 1
    export FORENSICS_RUN_DIR
    _FORENSICS_FAILED=0
    _FORENSICS_CANCELLED=0
    _FORENSICS_ACTIVE_PID=
}

_forensics_block() {
    _FORENSICS_FAILED=1
    _forensics_helper block --run "$FORENSICS_RUN_DIR" >/dev/null || return 1
}

forensics_stage() {
    local metadata status
    metadata=$(_forensics_helper stage --run "$FORENSICS_RUN_DIR" \
        --source "$1" --kind "${2:-file}")
    status=$?
    if (( status != 0 )); then
        _forensics_block || return 1
        return "$status"
    fi
    printf '%s' "$metadata" | _forensics_field work_path
}

# trap -p is shell-quoted; shlex decodes it without eval or executing its text.
_forensics_trap_body() {
    python3 -B -c 'import shlex,sys; s=shlex.split(sys.stdin.read()); print(s[2] if s else "")'
}

_forensics_restore_traps() {
    if [[ $_FORENSICS_HAS_INT = 1 ]]; then trap -- "$_FORENSICS_OLD_INT" INT; else trap - INT; fi
    if [[ $_FORENSICS_HAS_TERM = 1 ]]; then trap -- "$_FORENSICS_OLD_TERM" TERM; else trap - TERM; fi
}

_forensics_signal() {
    _FORENSICS_CANCELLED=$1
    # Only the session/process group we just created; never kill 0 or a caller group.
    if [[ -n $_FORENSICS_ACTIVE_PID ]]; then
        kill -TERM -- "-$_FORENSICS_ACTIVE_PID" 2>/dev/null || kill -TERM -- "$_FORENSICS_ACTIVE_PID" 2>/dev/null || :
        kill -KILL -- "-$_FORENSICS_ACTIVE_PID" 2>/dev/null || :
    fi
}

forensics_capture() {
    local name=$1 tool=$2 metadata status function_name monitor=0
    shift 2
    [[ ${_FORENSICS_FAILED:-1} = 0 && ${_FORENSICS_CANCELLED:-0} = 0 ]] || return 1
    _forensics_helper integrity --run "$FORENSICS_RUN_DIR" >/dev/null || { _FORENSICS_FAILED=1; return 1; }
    # tool is an identifier only; no argv is persisted. Absolute paths may be
    # invoked through an explicitly defined Bash function instead.
    metadata=$(_forensics_helper prepare-capture --run "$FORENSICS_RUN_DIR" --name "$name" --tool "$tool") || {
        _forensics_block; return 1;
    }
    FORENSICS_STEP_OUT=$(printf '%s' "$metadata" | _forensics_field stdout) || { _FORENSICS_FAILED=1; return 1; }
    FORENSICS_STEP_ERR=$(printf '%s' "$metadata" | _forensics_field stderr) || { _FORENSICS_FAILED=1; return 1; }
    _FORENSICS_OLD_INT=$(trap -p INT)
    _FORENSICS_OLD_TERM=$(trap -p TERM)
    _FORENSICS_HAS_INT=0
    _FORENSICS_HAS_TERM=0
    [[ -z $_FORENSICS_OLD_INT ]] || _FORENSICS_HAS_INT=1
    [[ -z $_FORENSICS_OLD_TERM ]] || _FORENSICS_HAS_TERM=1
    _FORENSICS_OLD_INT=$(printf '%s' "$_FORENSICS_OLD_INT" | _forensics_trap_body) || return 1
    _FORENSICS_OLD_TERM=$(printf '%s' "$_FORENSICS_OLD_TERM" | _forensics_trap_body) || return 1
    trap '_forensics_signal 2' INT
    trap '_forensics_signal 15' TERM
    # Export defined functions (including their pipeline dependencies), not an
    # interpolated command string. Arguments remain separate positional values.
    while read -r _ _ function_name; do export -f "$function_name"; done < <(declare -F)
    # With monitor enabled a background job is already a group leader; setsid
    # would fork, breaking the $! -> owned session mapping. Preserve caller mode.
    [[ $- != *m* ]] || monitor=1
    set +m
    setsid bash -c 'set -o pipefail; "$@"' forensics "$tool" "$@" \
        >"$FORENSICS_STEP_OUT" 2>"$FORENSICS_STEP_ERR" &
    _FORENSICS_ACTIVE_PID=$!
    (( monitor == 0 )) || set -m
    wait "$_FORENSICS_ACTIVE_PID"
    FORENSICS_STEP_RC=$?
    if (( _FORENSICS_CANCELLED != 0 )); then
        # wait can be interrupted by a trap; reap the owned leader afterwards.
        # Keep its actual wait status, NOT 128 + the signal sent to this wrapper.
        wait "$_FORENSICS_ACTIVE_PID" 2>/dev/null
        FORENSICS_STEP_RC=$?
    fi
    # Reap leader then remove any remaining descendants in our own group only.
    kill -KILL -- "-$_FORENSICS_ACTIVE_PID" 2>/dev/null || :
    _FORENSICS_ACTIVE_PID=
    local -a signal_flag=()
    # signal is the explicit cancellation received by the wrapper. The owned
    # process's wait rc stays intact even if forced teardown exits differently.
    if (( _FORENSICS_CANCELLED != 0 )); then
        signal_flag=(--cancelled)
        # A cancellation racing with successful command exit must not invent
        # a nonzero rc or claim the command was interrupted by a signal.
        if (( FORENSICS_STEP_RC != 0 )); then signal_flag+=(--signal "$_FORENSICS_CANCELLED"); fi
    fi
    _forensics_helper capture-result --run "$FORENSICS_RUN_DIR" --name "$name" \
        --rc "$FORENSICS_STEP_RC" "${signal_flag[@]}" >/dev/null
    status=$?
    if (( status != 0 )); then _forensics_block; fi
    _forensics_restore_traps
    if (( _FORENSICS_CANCELLED != 0 )); then
        forensics_finish || :
        # Previously installed handlers are preserved and receive the signal
        # after private streams/metadata are sealed. Default disposition is not
        # re-raised: the caller receives contractual failure (1).
        if { (( _FORENSICS_CANCELLED == 2 )) && [[ -n $_FORENSICS_OLD_INT ]]; } || \
           { (( _FORENSICS_CANCELLED == 15 )) && [[ -n $_FORENSICS_OLD_TERM ]]; }; then
            kill -s "$_FORENSICS_CANCELLED" "$$"
        fi
        return 1
    fi
    (( status == 0 )) || return 1
    return "$FORENSICS_STEP_RC"
}

forensics_complete_step() {
    _forensics_helper complete-capture --run "$FORENSICS_RUN_DIR" --name "$1" \
        --state "$2" --coverage-code "$3" >/dev/null || { _forensics_block; return 1; }
}

forensics_skip() {
    local status metadata state
    metadata=$(_forensics_helper step --run "$FORENSICS_RUN_DIR" --name "$1" --rc 0 \
        --state OMITIDO --coverage-code "$2")
    status=$?
    # step's rc1 is expected for a requested omission, but no JSON/metadata
    # failure may be mistaken for that semantic result.
    state=$(printf '%s' "$metadata" | _forensics_field state) || { _forensics_block; return 1; }
    [[ $state = OMITIDO && $status = 1 ]] || { _forensics_block; return 1; }
    return "$status"
}

forensics_finish() {
    local status
    _forensics_helper finish --run "$FORENSICS_RUN_DIR" >/dev/null
    status=$?
    (( status == 0 && ${_FORENSICS_FAILED:-1} == 0 )) || return 1
}
