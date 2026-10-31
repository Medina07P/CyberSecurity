#!/bin/bash

# ENUM API - Enumeración de APIs
# Uso: ./enum_api.sh <IP> [PUERTO]
# Ejemplo: ./enum_api.sh 192.168.1.10 8080

TARGET="$1"
PORT="${2:-8080}"
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/scans"
OUTPUT_DIR="$SCANS_DIR/api"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./enum_api.sh <IP> [PUERTO]"
    echo "Ejemplo: ./enum_api.sh 192.168.1.10 8080"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

URL="http://${TARGET}:${PORT}"

echo "🔌 Enumerando API en: $URL"
echo "────────────────────────────────────────"

# 1. Endpoints comunes
echo " → Endpoints comunes..."
ENDPOINTS=("/api" "/v1" "/v2" "/rest" "/graphql" "/swagger" "/docs" "/openapi" "/apidocs" "/api/v1" "/api/v2" "/api/rest")
for endpoint in "${ENDPOINTS[@]}"; do
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$URL$endpoint" 2>/dev/null)
    if [[ "$CODE" =~ (200|301|302|403) ]]; then
        echo " ✅ $endpoint ($CODE)"
        echo "$URL$endpoint|$CODE" >> "$OUTPUT_DIR/endpoints.txt"
    fi
done

# 2. Métodos permitidos
echo " → Métodos permitidos..."
for method in GET POST PUT DELETE PATCH OPTIONS HEAD; do
    CODE=$(curl -sk -X "$method" -o /dev/null -w "%{http_code}" "$URL/api" 2>/dev/null)
    if [[ "$CODE" != "405" ]]; then
        echo " ✅ $method ($CODE)"
    fi
done > "$OUTPUT_DIR/methods.txt"

# 3. Buscar Swagger/OpenAPI
echo " → Documentación API..."
for doc in swagger.json openapi.json api-docs; do
    if curl -sk "$URL/$doc" 2>/dev/null | grep -q "swagger\|openapi"; then
        echo " ✅ $doc encontrado"
        curl -sk "$URL/$doc" > "$OUTPUT_DIR/$doc"
    fi
done

echo ""
echo "📁 Resultados guardados en: $OUTPUT_DIR"
