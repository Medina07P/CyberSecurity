#!/bin/bash
# ============================================================
#  PHASE STATUS - Estado de las fases deducido de la evidencia
#  Uso: source 00_Config/lib/phase_status.bash
#  No guarda estado propio: mira lo que hay en disco.
# ============================================================

PHASE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
PHASE_FW_DIR="${PHASE_FW_DIR:-$(cd "$PHASE_LIB_DIR/../.." && pwd)}"
PHASE_REPO_DIR="${PHASE_REPO_DIR:-$(cd "$PHASE_FW_DIR/.." && pwd)}"
PHASE_SCANS_DIR="${PHASE_SCANS_DIR:-$PHASE_REPO_DIR/scans}"

# _has_files <dir> → 0 si hay algún fichero que no sea .gitkeep
_has_files() {
    [[ -d "$1" ]] || return 1
    [[ -n "$(find "$1" -type f ! -name '.gitkeep' 2>/dev/null | head -1)" ]]
}

# Presence only. No JSON/schema validation, hashing or payload reads.
_evidence_record_tree() {
    local dir=$1 excluded=${2:-} item name line file
    [[ $dir != "$excluded" ]] || return 1
    [[ -d $dir && ! -L $dir ]] || return 1
    name=${dir##*/}
    if [[ $name =~ ^[0-9a-f]{32}$ && -f $dir/evidence.json && ! -L $dir/evidence.json &&
          -f $dir/artifact && ! -L $dir/artifact ]]; then return 0; fi
    for item in "$dir"/* "$dir"/.[!.]* "$dir"/..?*; do
        [[ ! -L $item ]] || continue
        if [[ -d $item ]]; then
            _evidence_record_tree "$item" "$excluded" && return 0
        elif [[ -f $item && $item = *.meta && ! -e $item.meta && ! -L $item.meta ]]; then
            # Only sidecar metadata; FILE must be the exact paired basename.
            file=
            while IFS= read -r line || [[ -n $line ]]; do
                case $line in
                    FILE:*)
                        file=${line#FILE:}
                        # Remove only the single optional legacy formatting space.
                        file=${file# }
                        break ;;
                esac
            done < "$item"
            [[ -n $file && $file != . && $file != .. && $file != .gitkeep &&
               $file != */* && $file != *\\* &&
               $file != *[$'\001'-$'\037'$'\177']* ]] || continue
            [[ $item = "$dir/$file.meta" && -f $dir/$file && ! -L $dir/$file ]] && return 0
        fi
    done
    return 1
}

_evidence_has_records() {
    local root=$1 category parent
    [[ $root = /* ]] || root=$PWD/$root
    # Reject symlink ancestors, not just the leaf/pair.
    parent=$root
    while [[ $parent != / && -n $parent ]]; do
        [[ -d $parent && ! -L $parent ]] || return 1
        parent=${parent%/*}
    done
    for category in screenshots pcaps credentials findings proofs; do
        _evidence_record_tree "$root/$category" && return 0
    done
    [[ -d $root/logs && ! -L $root/logs ]] || return 1
    _evidence_record_tree "$root/logs" "$root/logs/runs" && return 0
    return 1
}

# phase_state <fase> → done | pending | na
phase_state() {
    case "$1" in
        00_Config)
            if [[ -f "$PHASE_FW_DIR/00_Config/scope.yaml" ]] &&
               grep -q '|' "$PHASE_FW_DIR/00_Config/targets.txt" 2>/dev/null; then
                printf 'done\n'
            else
                printf 'pending\n'
            fi
            ;;
        02_Recon)
            if compgen -G "$PHASE_FW_DIR/02_Recon/recon_*" >/dev/null 2>&1; then
                printf 'done\n'
            else
                printf 'pending\n'
            fi
            ;;
        03_Scanners)
            if _has_files "$PHASE_SCANS_DIR/nmap" || _has_files "$PHASE_SCANS_DIR/nuclei" ||
               _has_files "$PHASE_SCANS_DIR/nikto" || _has_files "$PHASE_SCANS_DIR/masscan"; then
                printf 'done\n'
            else
                printf 'pending\n'
            fi
            ;;
        04_Enumeration)
            if _has_files "$PHASE_SCANS_DIR/ssh" || _has_files "$PHASE_SCANS_DIR/web" ||
               _has_files "$PHASE_SCANS_DIR/database" || _has_files "$PHASE_SCANS_DIR/smb" ||
               _has_files "$PHASE_SCANS_DIR/ldap" || _has_files "$PHASE_SCANS_DIR/ftp"; then
                printf 'done\n'
            else
                printf 'pending\n'
            fi
            ;;
        10_Evidence)
            if _evidence_has_records "$PHASE_FW_DIR/10_Evidence"; then
                printf 'done\n'
            else
                printf 'pending\n'
            fi
            ;;
        11_Reports)
            if compgen -G "$PHASE_FW_DIR/11_Reports/generated/*/findings.json" >/dev/null 2>&1; then
                printf 'done\n'
            elif _has_files "$PHASE_FW_DIR/11_Reports/final_report" ||
                 _has_files "$PHASE_FW_DIR/11_Reports/technical"; then
                printf 'done\n'
            else
                printf 'pending\n'
            fi
            ;;
        *)
            printf 'na\n'
            ;;
    esac
}

# phase_badge <fase> → marca corta para la cabecera
phase_badge() {
    case "$1" in
        03_Scanners)      key="03" ;;
        04_Enumeration)   key="04" ;;
        00_Config)        key="00" ;;
        02_Recon)         key="02" ;;
        10_Evidence)      key="10" ;;
        11_Reports)       key="11" ;;
        *)                key="??" ;;
    esac
    case "$(phase_state "$1")" in
        done)    printf '%s:hecha\n' "$key" ;;
        pending) printf '%s:pendiente\n' "$key" ;;
        *)       printf '%s:-\n' "$key" ;;
    esac
}

# next_suggested_phase → la primera fase pendiente en orden, o vacío
next_suggested_phase() {
    local p
    for p in 00_Config 02_Recon 03_Scanners 04_Enumeration 10_Evidence 11_Reports; do
        if [[ "$(phase_state "$p")" == "pending" ]]; then
            printf '%s\n' "$p"
            return 0
        fi
    done
    printf '\n'
}
