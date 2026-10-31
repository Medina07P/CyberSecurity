#!/bin/bash
# ============================================================
#  RUN ALL ENUM - Ejecuta todas las enumeraciones
#  Uso: ./run_all_enum.sh <TARGET>
#  Ejemplo: ./run_all_enum.sh 192.168.1.10
#  Nota: se puede lanzar desde cualquier directorio (se autolocaliza);
#        los resultados van a <repo>/scans/
#  ENUM_TIMEOUT: segundos por servicio (por defecto 60)
# ============================================================

TARGET="$1"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./run_all_enum.sh <TARGET>"
    echo "Ejemplo: ./run_all_enum.sh 192.168.1.10"
    exit 1
fi

TIMEOUT_SECONDS="${ENUM_TIMEOUT:-60}"

# Los hijos se invocan con rutas relativas: ejecutar desde este directorio.
# Los resultados van siempre a <repo>/scans/, se lance desde donde se lance.
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scans"
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

GNMAP="$SCANS_DIR/enum_services_${TARGET}.gnmap"

mkdir -p "$SCANS_DIR"

echo "════════════════════════════════════════════════════════"
echo "  EJECUTANDO ENUMERACIONES PARA: $TARGET"
echo "════════════════════════════════════════════════════════"

# ─── Detección de servicios (una sola pasada) ────────────────
echo ""
echo "📋 Verificando servicios..."
nmap -sV -p 21,22,80,443,445,389,3306,5432,6379,8080 "$TARGET" \
    -oG "$GNMAP" -oN "${GNMAP%.gnmap}.txt" >/dev/null 2>/dev/null

# Usa el resultado del escaneo; si no hay fichero, pregunta a nmap
port_open() {
    local port="$1"
    if [[ -s "$GNMAP" ]]; then
        grep -qE "(Ports: |, )${port}/open" "$GNMAP"
    else
        nmap -p "$port" "$TARGET" 2>/dev/null | grep -q "open"
    fi
}

# run_enum <etiqueta> <puerto> <script> [args...]
run_enum() {
    local label="$1"
    local port="$2"
    local script="$3"
    local rc=0
    shift 3

    echo ""
    echo "📁 $label ($port)"
    echo "────────────────────────────────────────"

    if [[ ! -f "$script" ]]; then
        echo "  ⚠️  Script no encontrado: $script"
        return
    fi
    if [[ ! -x "$script" ]]; then
        echo "  ⚠️  Sin permiso de ejecución: $script (chmod +x)"
        return
    fi
    if ! port_open "$port"; then
        echo "  ⚠️  Puerto $port cerrado"
        return
    fi

    timeout "$TIMEOUT_SECONDS" "$script" "$TARGET" "$@"
    rc=$?
    if [[ $rc -eq 124 ]]; then
        echo "  ⚠️  $label: timeout tras ${TIMEOUT_SECONDS}s"
    elif [[ $rc -ne 0 ]]; then
        echo "  ⚠️  $label: terminó con código $rc"
    fi
}

# ─── Servicios de red ────────────────────────────────────────
run_enum "SSH" 22 ./ssh/enum_ssh.sh 22
run_enum "FTP" 21 ./ftp/enum_ftp.sh 21
# enum_smb.sh es un generador, no un enumerador: usar el _advanced
run_enum "SMB" 445 ./smb/enum_smb_advanced.sh
run_enum "LDAP" 389 ./ldap/enum_ldap.sh 389

# ─── Web ─────────────────────────────────────────────────────
for port in 80 443 8080 8443; do
    run_enum "Web" "$port" ./web/enum_web.sh "$port"
done

# ─── Bases de datos ─────────────────────────────────────────
run_enum "MySQL" 3306 ./database/enum_mysql.sh 3306
run_enum "PostgreSQL" 5432 ./database/enum_postgres.sh 5432
run_enum "Redis" 6379 ./database/enum_redis.sh 6379

echo ""
echo "════════════════════════════════════════════════════════"
echo "  ✅ ENUMERACIONES COMPLETADAS"
echo "  Resultados en: $SCANS_DIR/"
echo "════════════════════════════════════════════════════════"
