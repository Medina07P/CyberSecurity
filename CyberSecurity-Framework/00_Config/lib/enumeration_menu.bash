#!/bin/bash
# Navegación 04; conserva lista completa y todas las operaciones originales.
ENUM_MENU_LIB="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
source "$ENUM_MENU_LIB/scanner_runtime.bash"

enumeration_check_tools() {
    local tool
    echo 'COMPROBACIÓN LOCAL — sin tráfico ni ejecución de herramientas'
    for tool in python3 nmap nc ftp ldapsearch rpcclient smbclient enum4linux mysql psql curl whatweb ffuf timeout; do
        if command -v "$tool" >/dev/null 2>&1; then printf '  ✓ %s disponible\n' "$tool"; else printf '  — %s no instalado\n' "$tool"; fi
    done
    echo 'No se instala nada ni se cambian privilegios. Los NSE adicionales se comprueban al ejecutar.'
}

_enumeration_read() {
    local kind="$1" default="${2:-}" value
    printf '%s' "$3" >&2
    [[ -z "$default" ]] || printf ' [%s]' "$default" >&2
    printf ' (0 o ! cancela): ' >&2
    IFS= read -r value || return 2
    [[ "$value" != 0 && "$value" != '!' ]] || return 1
    value="${value:-$default}"
    [[ -n "$value" ]] || return 1
    case "$kind" in
        host) scanner_host "$value" || return 1 ;;
        url) scanner_url "$value" || return 1 ;;
        port) [[ "$value" =~ ^[0-9]+$ ]] && scanner_ports "$value" || return 1 ;;
    esac
    printf '%s\n' "$value"
}

enumeration_menu() {
    local choice target port sub script description default
    while :; do
        clear_screen
        target=$(session_target)
        printf '━━━ 04 · ENUMERACIÓN GUIADA ━━━\nObjetivo: %s\n\n' "${target:-sin definir}"
        echo '  1. Comprobar herramientas (local, sin red)'
        echo '  2. SSH — versión, autenticación, usuarios y algoritmos'
        echo '  3. FTP — banner, anónimo/listado y NSE ftp-*'
        echo '  4. SMB — null session, usuarios, shares y enum4linux'
        echo '  5. LDAP — RootDSE, dominios y usuarios'
        echo '  6. Bases de datos — MySQL, PostgreSQL o Redis'
        echo '  7. Web — completa con fuzzing o avanzada'
        echo '  8. API — endpoints, GET/POST/PUT/DELETE/PATCH/OPTIONS/HEAD y Swagger'
        echo '  9. Flujo completo original (accesos, NSE, fuzzing y credenciales)'
        echo ' 10. Ver resultados del objetivo (sin red)'
        echo ' 11. Lista completa: las 16 entradas, auxiliares y generadores'
        echo '  0. Volver al menú principal'
        printf 'Selecciona [0–11]: '
        IFS= read -r choice || return 0
        case "$choice" in
            0) return 0 ;;
            1) enumeration_check_tools; pause; continue ;;
            10) execute_script '04_Enumeration/show_results.sh' '04_Enumeration' --prepared "$target"; continue ;;
            11) run_module_scripts '04_Enumeration' '04_Enumeration · TODAS LAS CAPACIDADES'; continue ;;
            2) script=ssh/enum_ssh.sh; default=22; description='Versión, métodos de autenticación, usuarios (si no es localhost) y algoritmos SSH.' ;;
            3) script=ftp/enum_ftp.sh; default=21; description='Banner, login anónimo/listado y TODOS los NSE ftp-*; pueden incluir pruebas intrusivas.' ;;
            4) script=smb/enum_smb_advanced.sh; default=''; description='Null session, usuarios RPC, enum4linux, shares y NSE SMB en 445.' ;;
            5) script=ldap/enum_ldap.sh; default=389; description='Consulta anónima RootDSE, namingContexts y usuarios; LDAP/LDAPS según puerto.' ;;
            6)
                echo '1. MySQL: banner y root sin contraseña'
                echo '2. PostgreSQL: banner, postgres/postgres, versión y listado de bases'
                echo '3. Redis: INFO y KEYS * (puede bloquear bases grandes)'
                echo '0. Cancelar'
                IFS= read -r sub || return 0
                case "$sub" in
                    1) script=database/enum_mysql.sh; default=3306; description='MySQL: consulta de versión con root SIN contraseña.' ;;
                    2) script=database/enum_postgres.sh; default=5432; description='PostgreSQL: postgres/postgres y listado de bases si accede.' ;;
                    3) script=database/enum_redis.sh; default=6379; description='Redis: INFO y KEYS *; KEYS puede bloquear el servidor durante su recorrido.' ;;
                    0) continue ;;
                    *) echo 'Opción no válida.'; continue ;;
                esac
                ;;
            7|8)
                if [[ "$choice" == 7 ]]; then
                    echo '1. Web completa: cabeceras, tecnologías, robots, sitemap y ffuf'
                    echo '2. Web avanzada: siete puertos y búsqueda de archivos sensibles'
                    echo '0. Cancelar'
                    IFS= read -r sub || return 0
                    case "$sub" in
                        0) continue ;;
                        2)
                            target=$(_enumeration_read host "$target" 'Host/IPv4') || continue
                            echo "Resumen: web avanzada sobre $target; puertos 80/443/8080/8443/8000/8888/9000 y archivos sensibles."
                            execute_script '04_Enumeration/web/enum_web_advanced.sh' '04_Enumeration' --prepared "$target"
                            continue ;;
                        1) script=web/enum_web.sh; description='Web completa, incluyendo fuzzing con el diccionario original.' ;;
                        *) echo 'Opción no válida.'; continue ;;
                    esac
                else
                    script=api/enum_api.sh
                    description='API completa: incluye POST/PUT/DELETE/PATCH que pueden modificar o borrar datos; además endpoints y Swagger/OpenAPI.'
                fi
                target=$(_enumeration_read url '' 'URL HTTP(S) completa, con puerto/ruta/query') || continue
                printf 'Resumen\n  Objetivo: %s\n  Operaciones: %s\n' "$target" "$description"
                execute_script "04_Enumeration/$script" '04_Enumeration' --prepared --url "$target"
                continue
                ;;
            9) script=run_all_enum.sh; default=''; description='Flujo original completo: SSH/FTP/SMB/LDAP/web/DB; incluye accesos anónimos, usuarios, NSE, ffuf, credenciales por defecto e INFO/KEYS *.' ;;
            *) echo 'Opción no válida.'; continue ;;
        esac
        target=$(_enumeration_read host "$target" 'Host/IPv4') || continue
        port=''
        [[ -z "$default" ]] || { port=$(_enumeration_read port "$default" 'Puerto') || continue; }
        printf 'Resumen\n  Objetivo: %s%s\n  Operaciones: %s\n' "$target" "${port:+:$port}" "$description"
        echo 'La confirmación siguiente autoriza esta ejecución del menú, no sustituye el documento de alcance.'
        if [[ -n "$port" ]]; then
            execute_script "04_Enumeration/$script" '04_Enumeration' --prepared "$target" "$port"
        else
            execute_script "04_Enumeration/$script" '04_Enumeration' --prepared "$target"
        fi
    done
}
