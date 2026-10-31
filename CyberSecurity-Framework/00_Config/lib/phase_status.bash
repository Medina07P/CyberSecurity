#!/bin/bash
# ============================================================
#  PHASE STATUS - Estado de las fases deducido de la evidencia
#  Uso: source 00_Config/lib/phase_status.bash
#  No guarda estado propio: mira lo que hay en disco.
# ============================================================

PHASE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHASE_FW_DIR="${PHASE_FW_DIR:-$(cd "$PHASE_LIB_DIR/../.." && pwd)}"
PHASE_REPO_DIR="${PHASE_REPO_DIR:-$(cd "$PHASE_FW_DIR/.." && pwd)}"
PHASE_SCANS_DIR="${PHASE_SCANS_DIR:-$PHASE_REPO_DIR/scans}"

# _has_files <dir> → 0 si hay algún fichero que no sea .gitkeep
_has_files() {
    [[ -d "$1" ]] || return 1
    [[ -n "$(find "$1" -type f ! -name '.gitkeep' 2>/dev/null | head -1)" ]]
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
            if _has_files "$PHASE_FW_DIR/10_Evidence/proofs" ||
               _has_files "$PHASE_FW_DIR/10_Evidence/screenshots"; then
                printf 'done\n'
            else
                printf 'pending\n'
            fi
            ;;
        11_Reports)
            if _has_files "$PHASE_FW_DIR/11_Reports/final_report" ||
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
