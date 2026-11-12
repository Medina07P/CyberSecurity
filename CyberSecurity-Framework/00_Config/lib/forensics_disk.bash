# Module08 disk helpers. Only explicit files/devices; never auto-escalate.
_FORENSICS_DISK_SOURCE="${BASH_SOURCE[0]:-$0}"
source "${_FORENSICS_DISK_SOURCE%/*}/forensics_runtime.bash"

_forensics_disk_python() {
    python3 -B - "$@" <<'PY'
import json, os, re, stat, sys
from pathlib import Path
action, *args = sys.argv[1:]
def require(ok):
    if not ok: raise ValueError('invalid')
def path(value):
    p=Path(os.path.abspath(value))
    require(not any(ord(c)<32 or ord(c)==127 for c in str(p)))
    require(not any(q.is_symlink() for q in (*p.parents,p)))
    return p
try:
    if action=='file':
        p=path(args[0]); s=p.stat()
        require(stat.S_ISREG(s.st_mode) and s.st_mode & 0o444)
        print(str(p))
    elif action=='range':
        size=path(args[0]).stat().st_size
        offset,length=args[1:]
        require(offset.isdecimal() and length.isdecimal())
        require(0<=int(offset)<size and 0<int(length)<=size-int(offset))
    elif action=='mkdir':
        p=path(args[0]); p.mkdir(mode=0o700)
        print(str(p))
    elif action=='loop-name':
        value=path(args[0]).read_text().strip()
        require(re.fullmatch(r'/dev/loop[0-9]+',value) is not None)
        print(value)
    elif action=='loop-check':
        metadata,copy,offset,length=args
        records=json.loads(path(metadata).read_text())['loopdevices']
        require(len(records)==1)
        d=records[0]
        require(d['back-file']==str(path(copy)) and d['ro'] in (True,1))
        require(type(d['offset']) is int and d['offset']==int(offset))
        require(type(d['sizelimit']) is int and d['sizelimit']==int(length))
        require(re.fullmatch(r'/dev/loop[0-9]+',d['name']) is not None)
        print(d['name'])
    elif action=='mount-check':
        metadata,loop,point,fs,options=args
        records=json.loads(path(metadata).read_text())['filesystems']
        require(len(records)==1)
        d=records[0]
        require(d['source']==loop and d['target']==str(path(point)) and d['fstype']==fs)
        required=set(options.split(',')); actual=set(d['options'].split(','))
        require(required<=actual and 'rw' not in actual)
    elif action=='mount-absent':
        records=json.loads(path(args[0]).read_text())['filesystems']
        require(type(records) is list)
        require(not any(d['target']==args[1] for d in records))
    elif action=='loop-absent':
        records=json.loads(path(args[0]).read_text())['loopdevices']
        require(type(records) is list and not records)
    elif action=='list':
        root=path(args[0])
        entries=[]; sensitive=[]
        def visit(p):
            for child in sorted(p.iterdir()):
                s=child.lstat(); relative=child.relative_to(root).as_posix()
                entries.append({'path':relative,'mode':stat.S_IMODE(s.st_mode),'size':s.st_size})
                if child.suffix in ('.key','.pem','.crt','.pfx'): sensitive.append(relative)
                if stat.S_ISDIR(s.st_mode): visit(child)
        visit(root)
        print(json.dumps({'entries':entries,'sensitive':sensitive},ensure_ascii=True))
    elif action=='products':
        root=path(args[0]); products=[]
        def visit(p):
            require(stat.S_IMODE(p.stat().st_mode)==0o700)
            for child in p.iterdir():
                child=path(child); s=child.lstat()
                if stat.S_ISDIR(s.st_mode): visit(child)
                else:
                    require(stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o600)
                    products.append(str(child))
        visit(root)
        for product in sorted(products): print(product)
    elif action=='map':
        mapfile,image,expected=args
        lines=[line.split('#',1)[0].strip() for line in path(mapfile).read_text().splitlines()]
        lines=[line.split() for line in lines if line]
        require(len(lines)>=2 and len(lines[0]) in (2,3))
        require(lines[0][1] in ('?','*','/','-','+'))
        int(lines[0][0],0)
        if len(lines[0])==3: require(int(lines[0][2],0)>=1)
        end=0; pending=False
        for fields in lines[1:]:
            require(len(fields)==3)
            start,size=int(fields[0],0),int(fields[1],0)
            require(start==end and size>0 and fields[2] in ('?','*','/','-','+'))
            pending=pending or fields[2]!='+'
            end+=size
        image_size=path(image).stat().st_size
        require(image_size>0 and image_size<=end)
        if not pending: require(image_size==end)
        if expected!='None': require(end==int(expected))
        # Unknown device size cannot certify a whole-support recovery.
        print('PARCIAL' if pending else ('NO_EVALUABLE' if expected=='None' else 'COMPLETADO'))
    elif action=='same-point':
        p=path(args[0]); s=p.stat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid() and
                stat.S_IMODE(s.st_mode)==0o700 and f'{s.st_dev}:{s.st_ino}'==args[1])
    elif action=='point-id':
        s=path(args[0]).stat(); print(f'{s.st_dev}:{s.st_ino}')
    elif action=='rmdir':
        path(args[0]).rmdir()  # never recursive, never follows a link
    else: raise ValueError('action')
except (OSError,ValueError,TypeError,KeyError,OverflowError):
    sys.exit(2)
PY
}

_forensics_disk_confirm() {
    local answer
    printf 'Acción sensible explícita; escriba %s para continuar: ' "$1" >&2
    IFS= read -r answer || return 2
    [[ $answer = "$1" ]] || return 2
}

_forensics_disk_privilege() {
    # No sudo, policy agent or implicit privilege escalation.
    (( EUID == 0 )) || { printf 'Se requieren privilegios ya disponibles; sin escalada automática.\n' >&2; return 2; }
}

_forensics_disk_complete() {
    local state=COMPLETADO
    (( FORENSICS_STEP_RC == 0 )) || state=FALLIDO
    [[ ${_FORENSICS_CANCELLED:-0} = 0 ]] || return 1
    forensics_complete_step "$1" "$state" "$2"
}

_forensics_disk_record_products() {
    local name=$1 state=$2 directory=$3 product products
    local -a artifacts=() complete=()
    products=$(_forensics_disk_python products "$directory") || { _forensics_block; return 1; }
    while IFS= read -r product; do
        [[ -z $product ]] || artifacts+=(--artifact "$product")
    done <<<"$products"
    [[ $state != COMPLETADO ]] || complete=(--complete)
    _forensics_disk_publish_step "$state" --run "$FORENSICS_RUN_DIR" --name "${name}_products" \
        --tool internal --rc 0 --state "$state" --coverage-code products_validated \
        "${complete[@]}" "${artifacts[@]}"
}

_forensics_disk_loop_probe() {
    # These diagnostics are deliberately mutable, UNSEALED resource-control
    # receipts under analysis/disk-control/. Never alter sealed stdout/stderr.
    losetup --json --list --associated "$_FORENSICS_DISK_COPY" \
        --output NAME,BACK-FILE,RO,OFFSET,SIZELIMIT >"$_FORENSICS_DISK_CONTROL/loop.json" \
        2>>"$_FORENSICS_DISK_CONTROL/cleanup.log" || return 1
    _forensics_disk_python loop-check "$_FORENSICS_DISK_CONTROL/loop.json" \
        "$_FORENSICS_DISK_COPY" "$_FORENSICS_DISK_OFFSET" "$_FORENSICS_DISK_LENGTH"
}

_forensics_disk_mount_probe() {
    findmnt --json --mountpoint "$_FORENSICS_DISK_POINT" --output SOURCE,TARGET,FSTYPE,OPTIONS \
        >"$_FORENSICS_DISK_CONTROL/mount.json" 2>>"$_FORENSICS_DISK_CONTROL/cleanup.log" || return 1
    _forensics_disk_python same-point "$_FORENSICS_DISK_POINT" "$_FORENSICS_DISK_POINT_ID" || return 1
    _forensics_disk_python mount-check "$_FORENSICS_DISK_CONTROL/mount.json" \
        "$_FORENSICS_DISK_LOOP" "$_FORENSICS_DISK_POINT" "$_FORENSICS_DISK_FS" "$_FORENSICS_DISK_OPTIONS"
}

_forensics_disk_publish_step() {
    local expected=$1 metadata status state expected_status=1
    shift
    metadata=$(_forensics_helper step "$@")
    status=$?
    state=$(printf '%s' "$metadata" | python3 -B -c '
import json,sys
try: print(json.load(sys.stdin)["state"])
except (ValueError,KeyError,TypeError): sys.exit(1)
') || { _forensics_block; return 1; }
    [[ $expected != COMPLETADO ]] || expected_status=0
    if [[ $state != "$expected" || $status != "$expected_status" ]]; then
        _forensics_block; return 1
    fi
}

_forensics_disk_manual() {
    printf 'Recuperación manual requerida; recursos conservados, diagnóstico privado en el run.\n' >&2
    printf 'cleanup_incomplete loop=%s point=%s\n' "${_FORENSICS_DISK_LOOP:-unknown}" \
        "${_FORENSICS_DISK_POINT:-unknown}" >>"$_FORENSICS_DISK_CONTROL/cleanup.log"
    _FORENSICS_DISK_CLEANUP_FAILED=1
    return 1
}

_forensics_disk_publish_resources() {
    local state=$1 name rc
    local -a artifacts=() complete=()
    [[ $state != COMPLETADO ]] || complete=(--complete)
    if [[ -n ${_FORENSICS_DISK_CONTROL:-} && -f $_FORENSICS_DISK_CONTROL/cleanup.log ]]; then
        artifacts=(--artifact "$_FORENSICS_DISK_CONTROL/cleanup.log")
    fi
    # Preserve real wait statuses of cleanup commands separately from the
    # internal ownership decision; metadata errors are never tool statuses.
    for name in umount detach; do
        if [[ $name = umount ]]; then rc=${_FORENSICS_DISK_UMOUNT_RC:-}; else rc=${_FORENSICS_DISK_DETACH_RC:-}; fi
        [[ -n $rc ]] || continue
        local command_state=COMPLETADO command_tool=umount
        local -a command_complete=(--complete)
        [[ $name != detach ]] || command_tool=losetup
        if (( rc != 0 )); then command_state=FALLIDO; command_complete=(); fi
        _forensics_disk_publish_step "$command_state" --run "$FORENSICS_RUN_DIR" --name "cleanup_$name" --tool "$command_tool" \
            --rc "$rc" --state "$command_state" --coverage-code cleanup_command "${command_complete[@]}" \
            "${artifacts[@]}" || return 1
    done
    _forensics_disk_publish_step "$state" --run "$FORENSICS_RUN_DIR" --name disk_resources --tool internal \
        --rc 0 --state "$state" --coverage-code resource_ownership "${complete[@]}" "${artifacts[@]}" >/dev/null
}

forensics_disk_release() {
    [[ -n ${_FORENSICS_DISK_CONTROL:-} ]] || return 0
    [[ ${_FORENSICS_DISK_RELEASED:-0} = 0 ]] || return 0
    [[ ${_FORENSICS_DISK_CLEANUP_FAILED:-0} = 0 ]] || return 1
    _forensics_disk_python same-point "$_FORENSICS_DISK_POINT" "$_FORENSICS_DISK_POINT_ID" || {
        _forensics_disk_manual; return 1;
    }
    if [[ ${_FORENSICS_DISK_LOOP_ATTEMPTED:-0} = 1 ]]; then
        # Recover even if cancellation interrupted allocation before its stdout
        # could be consumed. The independent private backing copy identifies it.
        _FORENSICS_DISK_LOOP=$(_forensics_disk_loop_probe) || { _forensics_disk_manual; return 1; }
        if [[ ${_FORENSICS_DISK_MOUNT_ATTEMPTED:-0} = 1 ]]; then
            _forensics_disk_mount_probe || { _forensics_disk_manual; return 1; }
            umount -- "$_FORENSICS_DISK_POINT" >>"$_FORENSICS_DISK_CONTROL/cleanup.log" 2>&1
            local status=$?
            _FORENSICS_DISK_UMOUNT_RC=$status
            printf 'umount_rc=%s\n' "$status" >>"$_FORENSICS_DISK_CONTROL/cleanup.log"
            (( status == 0 )) || { _forensics_disk_manual; return 1; }
            # Verify absence, not merely the backend's exit status.
            findmnt --json --list --output SOURCE,TARGET >"$_FORENSICS_DISK_CONTROL/mount-after.json" \
                2>>"$_FORENSICS_DISK_CONTROL/cleanup.log" && \
                _forensics_disk_python mount-absent "$_FORENSICS_DISK_CONTROL/mount-after.json" "$_FORENSICS_DISK_POINT" || {
                    _forensics_disk_manual; return 1;
                }
        fi
        # Check backing identity/ro again immediately before detach.
        _forensics_disk_loop_probe >/dev/null || { _forensics_disk_manual; return 1; }
        losetup --detach -- "$_FORENSICS_DISK_LOOP" >>"$_FORENSICS_DISK_CONTROL/cleanup.log" 2>&1
        local status=$?
        _FORENSICS_DISK_DETACH_RC=$status
        printf 'detach_rc=%s\n' "$status" >>"$_FORENSICS_DISK_CONTROL/cleanup.log"
        (( status == 0 )) || { _forensics_disk_manual; return 1; }
        losetup --json --list --associated "$_FORENSICS_DISK_COPY" --output NAME,BACK-FILE,RO,OFFSET,SIZELIMIT \
            >"$_FORENSICS_DISK_CONTROL/loop-after.json" 2>>"$_FORENSICS_DISK_CONTROL/cleanup.log" && \
            _forensics_disk_python loop-absent "$_FORENSICS_DISK_CONTROL/loop-after.json" || {
                _forensics_disk_manual; return 1;
            }
    fi
    _forensics_disk_python same-point "$_FORENSICS_DISK_POINT" "$_FORENSICS_DISK_POINT_ID" && \
        _forensics_disk_python rmdir "$_FORENSICS_DISK_POINT" || { _forensics_disk_manual; return 1; }
    _FORENSICS_DISK_RELEASED=1
    printf 'cleanup_complete\n' >>"$_FORENSICS_DISK_CONTROL/cleanup.log"
}

_forensics_disk_cancel() {
    trap '' INT TERM
    forensics_disk_release || :
    local metadata finished
    metadata=$(_forensics_helper validate --run "$FORENSICS_RUN_DIR") || metadata=
    if [[ -n $metadata ]]; then
        finished=$(printf '%s' "$metadata" | _forensics_field finished) || finished=invalid
        if [[ $finished = None ]]; then
            _forensics_helper step --run "$FORENSICS_RUN_DIR" --name disk_cancel --tool internal \
                --rc 0 --state CANCELADO --coverage-code cancellation_wrapper >/dev/null || :
        fi
    fi
    forensics_finish || :
    exit 1
}

forensics_disk_listing() {
    _forensics_disk_python list "$1"
}

forensics_disk_mount() {
    local copy=$1 offset=${2:-0} length=${3:-0} fs status metadata
    [[ $# = 1 || $# = 3 ]] || return 2
    # The public helper cannot be used to bypass the leaf's copy policy.
    metadata=$(_forensics_helper validate --run "$FORENSICS_RUN_DIR") || return 1
    printf '%s' "$metadata" | python3 -B -c '
import json,sys
data=json.load(sys.stdin)
sys.exit(0 if data["mode"]=="offline" and data["finished"] is None and
         not data["dependents_blocked"] and any(i["kind"]=="file" and
         i["work_path"]==sys.argv[1] for i in data["inputs"]) else 2)
' "$copy" || return 2
    [[ $# = 1 ]] || _forensics_disk_python range "$copy" "$offset" "$length" || return 2
    local -a probe_range=(--offset "$offset")
    [[ $# = 1 ]] || probe_range+=(--size "$length")
    forensics_capture mount_filesystem blkid -p -o value -s TYPE "${probe_range[@]}" -- "$copy"
    status=$?
    (( status == 0 )) || { _forensics_disk_complete mount_filesystem filesystem_probe; return 1; }
    fs=$(python3 -B -c 'import sys; print(open(sys.argv[1]).read().strip())' "$FORENSICS_STEP_OUT") || return 1
    case "$fs" in
        ext2) _FORENSICS_DISK_OPTIONS=ro ;;
        ext3|ext4) _FORENSICS_DISK_OPTIONS=ro,noload ;;
        xfs) _FORENSICS_DISK_OPTIONS=ro,norecovery ;;
        *) forensics_complete_step mount_filesystem NO_EVALUABLE unsupported_filesystem; return 1 ;;
    esac
    forensics_complete_step mount_filesystem COMPLETADO filesystem_identified || return 1
    _FORENSICS_DISK_FS=$fs
    _FORENSICS_DISK_COPY=$copy
    _FORENSICS_DISK_OFFSET=$offset
    _FORENSICS_DISK_LENGTH=$length
    _FORENSICS_DISK_CONTROL=$(_forensics_disk_python mkdir "$FORENSICS_RUN_DIR/analysis/disk-control") || return 1
    _FORENSICS_DISK_POINT=$(_forensics_disk_python mkdir "$FORENSICS_RUN_DIR/work/mountpoint") || return 1
    _FORENSICS_DISK_POINT_ID=$(_forensics_disk_python point-id "$_FORENSICS_DISK_POINT") || return 1
    _FORENSICS_DISK_RELEASED=0
    _FORENSICS_DISK_CLEANUP_FAILED=0
    _FORENSICS_DISK_MOUNT_ATTEMPTED=0
    _FORENSICS_DISK_LOOP_ATTEMPTED=1
    local -a range=()
    [[ $# = 1 ]] || range=(--offset "$offset" --sizelimit "$length")
    forensics_capture loop_attach losetup --find --show --read-only "${range[@]}" -- "$copy"
    status=$?
    _forensics_disk_complete loop_attach loop_allocation || return 1
    (( status == 0 )) || return 1
    _FORENSICS_DISK_LOOP=$(_forensics_disk_python loop-name "$FORENSICS_STEP_OUT") || return 1
    local observed
    observed=$(_forensics_disk_loop_probe) || return 1
    [[ $observed = "$_FORENSICS_DISK_LOOP" ]] || return 1
    _FORENSICS_DISK_MOUNT_ATTEMPTED=1
    forensics_capture mount_copy mount -t "$fs" -o "$_FORENSICS_DISK_OPTIONS" -- "$_FORENSICS_DISK_LOOP" "$_FORENSICS_DISK_POINT"
    status=$?
    _forensics_disk_complete mount_copy mount_command || return 1
    (( status == 0 )) || return 1
    _forensics_disk_mount_probe || return 1
    forensics_capture filelist forensics_disk_listing "$_FORENSICS_DISK_POINT"
    status=$?
    _forensics_disk_complete filelist copy_listing || return 1
    return "$status"
}
