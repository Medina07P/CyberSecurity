#!/bin/bash
# Capacidades originales de 04; todas se mantienen accesibles desde sus hojas.
ENUM_SERVICE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
source "$ENUM_SERVICE_DIR/enumeration_runtime.bash"

enum_service() {
    local service="$1" host="${2:-}" port="${3:-}" domain
    [[ -n "$host" ]] || { echo 'Uso: indica un host y, si corresponde, un puerto.' >&2; return 1; }
    case "$service" in
        ftp_anon|ldap_anon)
            local ports failed=0 protocol
            if [[ "$service" == ftp_anon ]]; then ports='21 2121 2221'; else ports='389 636 3268 3269'; fi
            for port in $ports; do
                (
                    if [[ "$service" == ftp_anon ]]; then
                        enum_init ftp "$host" "$port" || exit 1
                        enum_step anonymous_ftp ftp ftp -n -v "$host" "$port" <<'FTP'
quote USER anonymous
quote PASS anonymous@
quit
FTP
                    else
                        enum_init ldap "$host" "$port" || exit 1
                        protocol=ldap; [[ "$port" != 636 && "$port" != 3269 ]] || protocol=ldaps
                        enum_step anonymous_access ldap ldapsearch -x -H "$protocol://$host:$port" -b '' -s base
                    fi
                ) || failed=$((failed + 1))
            done
            (( failed == 0 )); return
            ;;
        ssh) port="${port:-22}" ;;
        ftp) port="${port:-21}" ;;
        smb) port=445 ;;
        ldap) port="${port:-389}" ;;
        mysql) port="${port:-3306}" ;;
        postgres) port="${port:-5432}" ;;
        redis) port="${port:-6379}" ;;
        *) return 1 ;;
    esac
    local directory="$service"
    case "$service" in mysql|postgres|redis) directory=database ;; esac
    enum_init "$directory" "$host" "$port" || return 1
    echo "Enumeración $service en $host:$port — incluye las pruebas de acceso declaradas por esta herramienta."
    case "$service" in
        ssh)
            enum_step version nmap nmap -Pn -sV -p "$port" "$host" || :
            enum_nse auth_methods ssh-auth-methods || :
            if [[ "$host" != 127.0.0.1 && "$host" != localhost ]]; then
                enum_nse users ssh-enum-users || :
            fi
            enum_nse key_exchange ssh2-enum-algos || :
            ;;
        ftp)
            enum_step banner banner nc -w 3 "$host" "$port" </dev/null || :
            enum_step anonymous ftp ftp -n -v "$host" "$port" <<'FTP' || :
quote USER anonymous
quote PASS anonymous@
ls -la
quit
FTP
            enum_nse nmap_ftp 'ftp-*' || :
            ;;
        smb)
            enum_step null_users smb rpcclient -U '' -N "$host" -c enumdomusers || :
            if command -v enum4linux >/dev/null 2>&1; then
                enum_step enum4linux smb enum4linux -a "$host" || :
            else
                echo 'enum4linux no instalado: OMITIDO (capacidad conservada si se instala).'
            fi
            enum_step shares smb smbclient -L "//$host" -N || :
            enum_nse nmap_smb 'smb-enum*,smb-os-discovery,smb-security-mode' || :
            ;;
        ldap)
            local scheme=ldap
            [[ "$port" != 636 && "$port" != 3269 ]] || scheme=ldaps
            enum_step base ldap ldapsearch -x -H "$scheme://$host:$port" -b '' -s base || :
            enum_step domains ldap ldapsearch -x -H "$scheme://$host:$port" -b '' -s base namingContexts || :
            if [[ -f "$ENUM_WORK/domains.data" ]]; then
                local index=0
                while IFS= read -r domain; do
                    [[ -n "$domain" ]] || continue
                    index=$((index + 1))
                    enum_step "users_$index" ldap ldapsearch -x -H "$scheme://$host:$port" -b "$domain" -z 500 -l 15 '(objectClass=user)' || :
                done < <(sed -n 's/^namingContexts: //p' "$ENUM_WORK/domains.data")
            else
                # domains.data fue publicado: leer solo la salida de ESTA ejecución.
                local domains_path
                domains_path=$(enum_path domains)
                if [[ "$ENUM_RC" == 0 && -f "$domains_path" ]]; then
                    local index=0
                    while IFS= read -r domain; do
                        [[ -n "$domain" ]] || continue
                        index=$((index + 1))
                        enum_step "users_$index" ldap ldapsearch -x -H "$scheme://$host:$port" -b "$domain" -z 500 -l 15 '(objectClass=user)' || :
                    done < <(sed -n 's/^namingContexts: //p' "$domains_path")
                fi
            fi
            ;;
        mysql)
            enum_nse mysql_banner mysql-info || :
            enum_step anon mysql env -u MYSQL_PWD -u MYSQL_HOME HOME="$ENUM_WORK" MYSQL_TEST_LOGIN_FILE=/dev/null \
                mysql --no-defaults --skip-password --protocol=TCP -h "$host" -P "$port" -u root -e 'SELECT version();' || :
            ;;
        postgres)
            # pg-banner no existe en Nmap estándar; detección completa conserva la función de banner.
            enum_step postgres_banner nmap nmap -Pn -sV --version-all -p "$port" "$host" || :
            enum_step postgres_info postgres env -u PGHOSTADDR -u PGSERVICE -u PGSERVICEFILE -u PGOPTIONS HOME="$ENUM_WORK" \
                PGPASSFILE=/dev/null PGPASSWORD=postgres PGCONNECT_TIMEOUT=5 psql -X -w -h "$host" -p "$port" -U postgres -d postgres -c 'SELECT version();' || :
            local info_path
            info_path=$(enum_path postgres_info)
            if [[ -f "$info_path.meta.json" ]] && grep -q '"estado": "CONFIRMADO"' "$info_path.attempt.json"; then
                enum_step postgres_databases postgres env -u PGHOSTADDR -u PGSERVICE -u PGSERVICEFILE -u PGOPTIONS HOME="$ENUM_WORK" \
                    PGPASSFILE=/dev/null PGPASSWORD=postgres PGCONNECT_TIMEOUT=5 psql -X -w -h "$host" -p "$port" -U postgres -d postgres -c '\l' || :
            fi
            ;;
        redis)
            enum_step redis_info redis_info nc -w 3 "$host" "$port" <<< 'INFO' || :
            echo 'Aviso: KEYS * puede bloquear temporalmente Redis en bases grandes.'
            enum_step redis_keys redis_keys nc -w 3 "$host" "$port" <<< 'KEYS *' || :
            ;;
    esac
    enum_finish
}

enum_common_shares() {
    local prefix="$1" share index=0
    [[ "$prefix" =~ ^[A-Za-z0-9_-]+$ ]] || { echo 'Prefijo no válido.' >&2; ENUM_FAILED=$((ENUM_FAILED+1)); return 1; }
    for share in 'ADMIN$' 'IPC$' 'C$' public share documents backup; do
        index=$((index+1))
        echo "Probando share $share (sin credenciales)"
        enum_step "${prefix}_share_$index" smb smbclient "//$ENUM_HOST/$share" -N -c ls || :
    done
    enum_finish
}
