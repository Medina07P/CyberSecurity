#!/bin/bash
# ============================================================
#  SHOW RESULTS - Muestra los resultados de las enumeraciones
#  Uso: ./show_results.sh
#  Nota: se puede lanzar desde cualquier directorio (se autolocaliza);
#        los scripts hoja escriben en <repo>/scans/
# ============================================================

SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scans"

echo "════════════════════════════════════════════════════════"
echo "  RESUMEN DE ENUMERACIONES"
echo "════════════════════════════════════════════════════════"

if [[ ! -d "$SCANS_DIR" ]]; then
    echo ""
    echo "  ⚠️  No hay resultados todavía en $SCANS_DIR/"
    echo "     Ejecuta primero: ./run_all_enum.sh <TARGET>"
    echo ""
    echo "════════════════════════════════════════════════════════"
    exit 0
fi

# SSH
if [[ -f "$SCANS_DIR/ssh/version.txt" ]]; then
    echo ""
    echo "📁 SSH (22)"
    echo "────────────────────────────────────────"
    grep -E "open.*ssh" "$SCANS_DIR/ssh/version.txt" 2>/dev/null || echo "  No disponible"
    echo ""
    echo "  Métodos de autenticación:"
    grep -E "publickey|password" "$SCANS_DIR/ssh/auth_methods.txt" 2>/dev/null | head -3 || echo "  No disponible"
fi

# PostgreSQL
if [[ -f "$SCANS_DIR/database/postgres_banner.txt" ]]; then
    echo ""
    echo "📁 PostgreSQL (5432)"
    echo "────────────────────────────────────────"
    grep -E "postgres|open" "$SCANS_DIR/database/postgres_banner.txt" 2>/dev/null | head -3 || echo "  No disponible"
    if [[ -f "$SCANS_DIR/database/postgres_info.txt" ]] && [[ -s "$SCANS_DIR/database/postgres_info.txt" ]]; then
        echo "  ✅ Credenciales por defecto funcionan"
    else
        echo "  ❌ Credenciales por defecto no funcionan"
    fi
fi

# MySQL
if [[ -f "$SCANS_DIR/database/mysql_banner.txt" ]]; then
    echo ""
    echo "📁 MySQL (3306)"
    echo "────────────────────────────────────────"
    grep -E "mysql|open" "$SCANS_DIR/database/mysql_banner.txt" 2>/dev/null || echo "  Puerto cerrado"
fi

# Redis
if [[ -f "$SCANS_DIR/database/redis_info.txt" ]]; then
    echo ""
    echo "📁 Redis (6379)"
    echo "────────────────────────────────────────"
    grep -E "redis_version|open" "$SCANS_DIR/database/redis_info.txt" 2>/dev/null | head -3 || echo "  No disponible"
fi

echo ""
echo "════════════════════════════════════════════════════════"
