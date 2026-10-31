#!/bin/bash
# ============================================================
#  ENUM REDIS - Enumeración Redis (RÁPIDA)
#  Uso: ./enum_redis.sh <IP> [PUERTO]
#  Ejemplo: ./enum_redis.sh 192.168.1.10 6379
# ============================================================

TARGET="$1"
PORT="${2:-6379}"
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/scans"
OUTPUT_DIR="$SCANS_DIR/database"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./enum_redis.sh <IP> [PUERTO]"
    echo "Ejemplo: ./enum_redis.sh 192.168.1.10 6379"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "🗄️ Enumerando Redis en: $TARGET:$PORT"
echo "────────────────────────────────────────"

# 1. INFO
echo "  → INFO server..."
echo "INFO" | nc -w 3 "$TARGET" "$PORT" 2>/dev/null > "$OUTPUT_DIR/redis_info.txt"

if [[ -s "$OUTPUT_DIR/redis_info.txt" ]]; then
    echo "    ✅ Conexión exitosa"
    grep -E "redis_version|os|tcp_port" "$OUTPUT_DIR/redis_info.txt" | head -5
else
    echo "    ❌ No se pudo conectar a Redis"
fi

# 2. KEYS
echo "  → KEYS *..."
echo "KEYS *" | nc -w 3 "$TARGET" "$PORT" 2>/dev/null > "$OUTPUT_DIR/redis_keys.txt"

if [[ -s "$OUTPUT_DIR/redis_keys.txt" ]]; then
    echo "    ✅ Claves encontradas"
    cat "$OUTPUT_DIR/redis_keys.txt"
fi

echo ""
echo "📁 Resultados guardados en: $OUTPUT_DIR"
