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
    _FORENSICS_CONTROL_FD=
    _FORENSICS_CLEANUP_CALLBACK=
    _FORENSICS_CLEANUP_DONE=0
    _FORENSICS_CLEANUP_ACTIVE=0
}

# Explicit per-run opt-in, before the first step. A cleanup callback is a named
# shell function, never argv/eval text. It must publish its own receipts and may
# not start a nested capture or close the run. No opt-in: historical behavior.
forensics_register_cleanup() {
    local metadata
    [[ $# = 1 && $1 =~ ^[a-zA-Z][a-zA-Z0-9_.-]{0,63}$ &&
       ${_FORENSICS_FAILED:-1} = 0 && ${_FORENSICS_CLEANUP_DONE:-0} = 0 &&
       ${_FORENSICS_CLEANUP_ACTIVE:-0} = 0 && -z ${_FORENSICS_CLEANUP_CALLBACK:-} ]] || return 2
    declare -F -- "$1" >/dev/null || return 2
    metadata=$(_forensics_helper validate --run "$FORENSICS_RUN_DIR") || return 2
    [[ $(printf '%s' "$metadata" | _forensics_field finished) = None &&
       $(printf '%s' "$metadata" | _forensics_field steps) = '[]' ]] || return 2
    _FORENSICS_CLEANUP_CALLBACK=$1
}

_forensics_cleanup_signal() {
    if (( _FORENSICS_CANCELLED == 0 )); then _FORENSICS_CANCELLED=$1; fi
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

# Explicit root registration; safe in command substitution, like staging.
# NAME is recovered or captures. Existing roots/finished runs are never reused.
forensics_register_root() {
    local metadata parent
    case "$1" in
        recovered) parent=${2:-$FORENSICS_RECOVERED_ROOT} ;;
        captures) parent=${2:-$FORENSICS_MEMORY_ROOT} ;;
        *) return 2 ;;
    esac
    metadata=$(_forensics_helper register-root --run "$FORENSICS_RUN_DIR" \
        --name "$1" --parent "$parent") || { _forensics_block; return 1; }
    printf '%s' "$metadata" | _forensics_field path
}

# Observation has no copy/content digest. Physical mode only; metadata ioctl
# may supply size, otherwise it stays explicitly unknown. No payload is read.
forensics_observe_device() {
    local metadata
    metadata=$(_forensics_helper observe-device --run "$FORENSICS_RUN_DIR" --source "$1") || {
        _forensics_block; return 1;
    }
    FORENSICS_DEVICE_SIZE=$(printf '%s' "$metadata" | _forensics_field size) || return 1
}

# trap -p is shell-quoted; shlex decodes it without eval or executing its text.
_forensics_trap_body() {
    python3 -B -c 'import shlex,sys; s=shlex.split(sys.stdin.read()); print(s[2] if s else "")'
}

_forensics_restore_traps() {
    if [[ $_FORENSICS_HAS_INT = 1 ]]; then trap -- "$_FORENSICS_OLD_INT" INT; else trap - INT; fi
    if [[ $_FORENSICS_HAS_TERM = 1 ]]; then trap -- "$_FORENSICS_OLD_TERM" TERM; else trap - TERM; fi
    if [[ $_FORENSICS_HAS_PIPE = 1 ]]; then trap -- "$_FORENSICS_OLD_PIPE" PIPE; else trap - PIPE; fi
}

_forensics_signal() {
    if [[ ${_FORENSICS_WAITING:-0} = 1 ]]; then _FORENSICS_WAIT_INTERRUPTED=1; fi
    if (( _FORENSICS_CANCELLED == 0 )); then _FORENSICS_CANCELLED=$1; fi
    # Channel identity, never a recyclable PID. Before registration the sticky
    # cancellation flag prevents GO; after registration CANCEL precedes any GO.
    if [[ -n $_FORENSICS_CONTROL_FD ]]; then
        _forensics_send "CANCEL $_FORENSICS_CANCELLED" || _FORENSICS_FAILED=1
    fi
}

_forensics_send() {
    # One synchronous builtin writer: GO must not race a forked writer with a
    # CANCEL trap in the owner. PIPE is temporarily ignored/restored by capture;
    # a failed write remains visible and becomes runtime failure.
    printf '%s\n' "$1" >&"$_FORENSICS_CONTROL_FD"
}

_forensics_start_supervisor() {
    local name=$1 tool=$2
    shift 2
    coproc FORENSICS_WORKER {
        _forensics_helper supervise --run "$FORENSICS_RUN_DIR" --name "$name" --tool "$tool" -- "$@"
    }
}

_forensics_read_protocol() {
    local status
    while :; do
        IFS= read -r -u "$result_fd" protocol_line
        status=$?
        (( status != 0 )) || return 0
        # Bash read, like wait, is interrupted by a handled signal. The channel
        # remains owned; repeated signals must not discard the eventual result.
        (( status > 128 )) || return 1
    done
}

forensics_capture() {
    local name=$1 tool=$2 metadata status function_name result_fd protocol_line worker_status
    shift 2
    [[ ${_FORENSICS_FAILED:-1} = 0 && ${_FORENSICS_CANCELLED:-0} = 0 &&
       ${_FORENSICS_CLEANUP_ACTIVE:-0} = 0 ]] || return 1
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
    _FORENSICS_OLD_PIPE=$(trap -p PIPE)
    _FORENSICS_HAS_INT=0
    _FORENSICS_HAS_TERM=0
    _FORENSICS_HAS_PIPE=0
    [[ -z $_FORENSICS_OLD_INT ]] || _FORENSICS_HAS_INT=1
    [[ -z $_FORENSICS_OLD_TERM ]] || _FORENSICS_HAS_TERM=1
    [[ -z $_FORENSICS_OLD_PIPE ]] || _FORENSICS_HAS_PIPE=1
    _FORENSICS_OLD_INT=$(printf '%s' "$_FORENSICS_OLD_INT" | _forensics_trap_body) || return 1
    _FORENSICS_OLD_TERM=$(printf '%s' "$_FORENSICS_OLD_TERM" | _forensics_trap_body) || return 1
    _FORENSICS_OLD_PIPE=$(printf '%s' "$_FORENSICS_OLD_PIPE" | _forensics_trap_body) || return 1
    trap '_forensics_signal 2' INT
    trap '_forensics_signal 15' TERM
    trap '' PIPE
    # Export defined functions (including their pipeline dependencies), not an
    # interpolated command string. Arguments remain separate positional values.
    while read -r _ _ function_name; do export -f "$function_name"; done < <(declare -F)
    _forensics_start_supervisor "$name" "$tool" "$@"
    _FORENSICS_ACTIVE_PID=$!
    exec {_FORENSICS_CONTROL_FD}>&"${FORENSICS_WORKER[1]}"
    exec {result_fd}<&"${FORENSICS_WORKER[0]}"
    status=0
    if ! _forensics_read_protocol || [[ $protocol_line != READY ]]; then
        status=1
    elif (( _FORENSICS_CANCELLED != 0 )); then
        _forensics_send "CANCEL $_FORENSICS_CANCELLED" || status=1
    else
        # This authorization is the launch linearization point. A trap between
        # this check and the write sends CANCEL first on the same ordered pipe.
        _forensics_send GO || status=1
    fi
    if (( status == 0 )); then
        if ! _forensics_read_protocol || [[ $protocol_line != 'RESULT '* ]]; then
            status=1
        else
            metadata=${protocol_line#RESULT }
            FORENSICS_STEP_RC=$(printf '%s' "$metadata" | _forensics_field rc) || status=1
        fi
    fi
    # RELEASE closes only the private protocol, never signals a numeric PID.
    _forensics_send RELEASE || status=1
    exec {_FORENSICS_CONTROL_FD}>&-
    _FORENSICS_CONTROL_FD=
    exec {result_fd}<&-
    while :; do
        _FORENSICS_WAIT_INTERRUPTED=0
        _FORENSICS_WAITING=1
        wait "$_FORENSICS_ACTIVE_PID"
        worker_status=$?
        _FORENSICS_WAITING=0
        # A terminal rc>=128 is not evidence of interruption. Only our trap can
        # request another wait; a dead worker's cached status cannot loop here.
        (( _FORENSICS_WAIT_INTERRUPTED != 0 )) || break
    done
    (( worker_status == 0 )) || status=1
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
    if (( status == 0 )); then
        _forensics_helper capture-result --run "$FORENSICS_RUN_DIR" --name "$name" \
            --rc "$FORENSICS_STEP_RC" "${signal_flag[@]}" >/dev/null
        status=$?
    fi
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
    local status cleanup_rc metadata event_status event_state initial_cancel=${_FORENSICS_CANCELLED:-0} did_cleanup=0
    local old_int old_term has_int=0 has_term=0
    local captured_rc=${FORENSICS_STEP_RC:-} captured_out=${FORENSICS_STEP_OUT:-} captured_err=${FORENSICS_STEP_ERR:-}
    [[ ${_FORENSICS_CLEANUP_ACTIVE:-0} = 0 ]] || return 1
    if [[ -n ${_FORENSICS_CLEANUP_CALLBACK:-} && ${_FORENSICS_CLEANUP_DONE:-0} = 0 ]]; then
        # capture reaches here only after stream sealing, group teardown and
        # wait. Ordinary finish cannot close while an active writer is owned.
        [[ -z ${_FORENSICS_ACTIVE_PID:-} && -z ${_FORENSICS_CONTROL_FD:-} ]] || return 1
        # Protect the validation/trap-snapshot boundary too, not just the body
        # of the callback: a prior handler can itself request finish here.
        _FORENSICS_CLEANUP_ACTIVE=1
        metadata=$(_forensics_helper validate --run "$FORENSICS_RUN_DIR") || {
            _FORENSICS_FAILED=1; _FORENSICS_CLEANUP_ACTIVE=0; return 1;
        }
        [[ $(printf '%s' "$metadata" | _forensics_field finished) = None ]] || {
            _FORENSICS_FAILED=1; _FORENSICS_CLEANUP_ACTIVE=0; return 1;
        }
        old_int=$(trap -p INT); old_term=$(trap -p TERM)
        [[ -z $old_int ]] || has_int=1
        [[ -z $old_term ]] || has_term=1
        old_int=$(printf '%s' "$old_int" | _forensics_trap_body) || { _FORENSICS_CLEANUP_ACTIVE=0; return 1; }
        old_term=$(printf '%s' "$old_term" | _forensics_trap_body) || { _FORENSICS_CLEANUP_ACTIVE=0; return 1; }
        _FORENSICS_CLEANUP_DONE=1
        did_cleanup=1
        # Sticky signals defer prior handlers until receipts are published and
        # the run closes. In particular, no recursive handler can close early.
        trap '_forensics_cleanup_signal 2' INT
        trap '_forensics_cleanup_signal 15' TERM
        "$_FORENSICS_CLEANUP_CALLBACK"
        cleanup_rc=$?
        FORENSICS_STEP_RC=$captured_rc
        FORENSICS_STEP_OUT=$captured_out
        FORENSICS_STEP_ERR=$captured_err
        if (( _FORENSICS_CANCELLED != 0 )) && [[ ${_FORENSICS_FAILED:-1} = 0 ]]; then
            metadata=$(_forensics_helper step --run "$FORENSICS_RUN_DIR" --name runtime_cleanup_cancelled \
                --tool internal --rc 0 --state CANCELADO --coverage-code cancellation_wrapper)
            event_status=$?
            # A requested cancellation has semantic rc1, not a backend failure.
            event_state=$(printf '%s' "$metadata" | python3 -B -c '
import json,sys
try: print(json.load(sys.stdin)["state"])
except (ValueError,KeyError,TypeError): sys.exit(1)
') || cleanup_rc=1
            [[ $event_status = 1 && $event_state = CANCELADO ]] || cleanup_rc=1
        fi
        (( cleanup_rc == 0 )) || _forensics_block
        _FORENSICS_CLEANUP_ACTIVE=0
        if (( has_int )); then trap -- "$old_int" INT; else trap - INT; fi
        if (( has_term )); then trap -- "$old_term" TERM; else trap - TERM; fi
    fi
    _forensics_helper finish --run "$FORENSICS_RUN_DIR" >/dev/null
    status=$?
    # capture itself notifies its prior handler for an earlier cancellation.
    # A signal newly observed during ordinary finish is notified exactly once,
    # after cleanup publication and closure, with the original traps restored.
    if (( did_cleanup && initial_cancel == 0 && _FORENSICS_CANCELLED != 0 )); then
        if { (( _FORENSICS_CANCELLED == 2 )) && (( has_int )) && [[ -n $old_int ]]; } || \
           { (( _FORENSICS_CANCELLED == 15 )) && (( has_term )) && [[ -n $old_term ]]; }; then
            kill -s "$_FORENSICS_CANCELLED" "$$"
        fi
    fi
    (( status == 0 && ${_FORENSICS_FAILED:-1} == 0 )) || return 1
}
