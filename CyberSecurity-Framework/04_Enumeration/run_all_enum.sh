#!/bin/bash
# Flujo completo original: SSH, FTP, SMB, LDAP, web y bases de datos.
# Uso: ./run_all_enum.sh <TARGET>
# Ejemplo: ./run_all_enum.sh 192.0.2.1
# ENUM_TIMEOUT: segundos por servicio, 60 por defecto.
MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$MODULE_DIR/../00_Config/lib/enumeration_runtime.bash"
TARGET="${1:-}"
[[ -n "$TARGET" ]] || { echo 'Uso: ./run_all_enum.sh <TARGET>'; exit 1; }
SECONDS_LIMIT="${ENUM_TIMEOUT:-60}"
[[ "$SECONDS_LIMIT" =~ ^[1-9][0-9]{0,3}$ ]] || { echo 'ENUM_TIMEOUT debe ser entero positivo.' >&2; exit 1; }
enum_init enumeration "$TARGET" 1 || exit 1
cd "$MODULE_DIR" || exit 1
echo "Flujo completo sobre $TARGET: incluye accesos anónimos, usuarios, NSE/fuzzing y credenciales por defecto."
PORTS=21,22,80,443,445,389,3306,5432,6379,8080,8443
# Un archivo exclusivamente nuevo: no hay fallback a resultados anteriores.
if ! enum_capture discovery nmap -Pn -sV -p "$PORTS" -oG "$ENUM_WORK/ports.data" "$TARGET"; then
    echo 'Descubrimiento fallido: NO_DETERMINADO. No se lanzan hijos.'
    exit 1
fi
[[ -s "$ENUM_WORK/ports.data" ]] || { echo 'Sin evidencia nueva de puertos: NO_DETERMINADO.'; exit 1; }
EJECUTADAS=0; FALLIDAS=0; OMITIDAS=0
port_state() {
    python3 - "$ENUM_WORK/ports.data" "$1" <<'PY'
import re,sys
text=open(sys.argv[1]).read()
match=re.search(r'(?:Ports: |, )'+re.escape(sys.argv[2])+r'/(open|closed|filtered|open\|filtered)/tcp/',text)
print(match.group(1) if match else 'NO_DETERMINADO')
PY
}
run_enum() {
    local label="$1" port="$2" script="$3" state rc
    shift 3
    state=$(port_state "$port")
    echo "$label ($port): $state"
    if [[ "$state" == NO_DETERMINADO ]]; then FALLIDAS=$((FALLIDAS+1)); return; fi
    if [[ "$state" != open ]]; then OMITIDAS=$((OMITIDAS+1)); return; fi
    if [[ ! -f "$script" || ! -x "$script" ]]; then
        echo "Script ausente o sin permiso: $script"
        FALLIDAS=$((FALLIDAS+1)); return
    fi
    EJECUTADAS=$((EJECUTADAS+1))
    timeout "$SECONDS_LIMIT" bash "$script" "$TARGET" "$@"
    rc=$?
    if (( rc )); then
        [[ "$rc" != 124 ]] || echo "$label: timeout tras ${SECONDS_LIMIT}s"
        echo "$label: NO_DETERMINADO (código $rc)"
        FALLIDAS=$((FALLIDAS+1))
    fi
}
run_enum SSH 22 ./ssh/enum_ssh.sh 22
run_enum FTP 21 ./ftp/enum_ftp.sh 21
run_enum SMB 445 ./smb/enum_smb_advanced.sh
run_enum LDAP 389 ./ldap/enum_ldap.sh 389
for port in 80 443 8080 8443; do run_enum Web "$port" ./web/enum_web.sh "$port"; done
run_enum MySQL 3306 ./database/enum_mysql.sh 3306
run_enum PostgreSQL 5432 ./database/enum_postgres.sh 5432
run_enum Redis 6379 ./database/enum_redis.sh 6379
printf '\nEjecutadas: %s | Fallidas: %s | Omitidas: %s\n' "$EJECUTADAS" "$FALLIDAS" "$OMITIDAS"
(( FALLIDAS == 0 )) || exit 1
echo 'Flujo terminado; los servicios omitidos no se han evaluado.'
