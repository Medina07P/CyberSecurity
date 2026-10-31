#!/bin/bash
# ============================================================
#  ENUM MYSQL - Enumeración MySQL (RÁPIDA)
#  Uso: ./enum_mysql.sh <IP> [PUERTO]
#  Ejemplo: ./enum_mysql.sh 192.168.1.10 3306
# ============================================================

TARGET="$1"
PORT="${2:-3306}"
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/scans"
OUTPUT_DIR="$SCANS_DIR/database"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./enum_mysql.sh <IP> [PUERTO]"
    echo "Ejemplo: ./enum_mysql.sh 192.168.1.10 3306"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "🗄️ Enumerando MySQL en: $TARGET:$PORT"
echo "────────────────────────────────────────"

# 1. Banner
echo "  → Versión MySQL..."
nmap -sV -p "$PORT" --script=mysql-info "$TARGET" -oN "$OUTPUT_DIR/mysql_banner.txt" 2>/dev/null

if [[ -f "$OUTPUT_DIR/mysql_banner.txt" ]]; then
    echo "    ✅ Versión obtenida"
    grep -E "mysql|version" "$OUTPUT_DIR/mysql_banner.txt" | head -3
fi

# 2. Conexión anónima
echo "  → Probando conexión anónima..."
mysql -h "$TARGET" -P "$PORT" -u root -e "SELECT version();" 2>/dev/null > "$OUTPUT_DIR/anon.txt"

if [[ -s "$OUTPUT_DIR/anon.txt" ]]; then
    echo "    ✅ Conexión exitosa sin contraseña"
    cat "$OUTPUT_DIR/anon.txt"
else
    echo "    ❌ No se pudo conectar anónimamente"
fi

echo ""
echo "📁 Resultados guardados en: $OUTPUT_DIR"
