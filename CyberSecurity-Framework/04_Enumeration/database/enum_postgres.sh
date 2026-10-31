#!/bin/bash
# ============================================================
#  ENUM POSTGRES - Enumeración PostgreSQL (CORREGIDO)
#  Uso: ./enum_postgres.sh <IP> [PUERTO]
#  Ejemplo: ./enum_postgres.sh 192.168.1.10 5432
# ============================================================

TARGET="$1"
PORT="${2:-5432}"
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/scans"
OUTPUT_DIR="$SCANS_DIR/database"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./enum_postgres.sh <IP> [PUERTO]"
    echo "Ejemplo: ./enum_postgres.sh 192.168.1.10 5432"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "🗄️ Enumerando PostgreSQL en: $TARGET:$PORT"
echo "────────────────────────────────────────"

# 1. Banner con nmap (script correcto)
echo "  → Versión PostgreSQL..."
nmap -sV -p "$PORT" --script=pg-banner "$TARGET" -oN "$OUTPUT_DIR/postgres_banner.txt" 2>/dev/null

if [[ -f "$OUTPUT_DIR/postgres_banner.txt" ]]; then
    echo "    ✅ Versión obtenida"
    grep -E "postgres|version|5432" "$OUTPUT_DIR/postgres_banner.txt" | head -3
fi

# 2. Probar conexión con credenciales por defecto
echo "  → Probando conexión con credenciales por defecto..."
PGPASSWORD=postgres psql -h "$TARGET" -p "$PORT" -U postgres -c "SELECT version();" 2>/dev/null > "$OUTPUT_DIR/postgres_info.txt"

if [[ -s "$OUTPUT_DIR/postgres_info.txt" ]]; then
    echo "    ✅ Conexión exitosa con credenciales por defecto"
    cat "$OUTPUT_DIR/postgres_info.txt"
else
    echo "    ❌ No se pudo conectar con credenciales por defecto"
fi

# 3. Enumeración de bases de datos (si hay conexión)
if [[ -s "$OUTPUT_DIR/postgres_info.txt" ]]; then
    echo "  → Enumerando bases de datos..."
    PGPASSWORD=postgres psql -h "$TARGET" -p "$PORT" -U postgres -c "\l" 2>/dev/null > "$OUTPUT_DIR/postgres_databases.txt"
fi

echo ""
echo "📁 Resultados guardados en: $OUTPUT_DIR"
