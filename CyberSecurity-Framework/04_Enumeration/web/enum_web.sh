#!/bin/bash

# ENUM WEB - Enumeración Web completa
# Uso: ./enum_web.sh <IP> [PUERTO]
# Ejemplo: ./enum_web.sh 192.168.1.10 80

TARGET="$1"
PORT="${2:-80}"
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/scans"
OUTPUT_DIR="$SCANS_DIR/web"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./enum_web.sh <IP> [PUERTO]"
    echo "Ejemplo: ./enum_web.sh 192.168.1.10 80"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

PROTO="http"
[[ "$PORT" == "443" || "$PORT" == "8443" ]] && PROTO="https"
URL="${PROTO}://${TARGET}:${PORT}"

echo "🌐 Enumerando Web en: $URL"
echo "────────────────────────────────────────"

# 1. Cabeceras
echo " → Cabeceras HTTP..."
curl -skI "$URL" > "$OUTPUT_DIR/headers_${PORT}.txt"
if [[ -s "$OUTPUT_DIR/headers_${PORT}.txt" ]]; then
    echo " ✅ Cabeceras obtenidas"
    head -10 "$OUTPUT_DIR/headers_${PORT}.txt"
fi

# 2. Tecnologías
echo " → Tecnologías..."
if command -v whatweb &>/dev/null; then
    whatweb -a 3 "$URL" > "$OUTPUT_DIR/technologies_${PORT}.txt"
    echo " ✅ Tecnologías detectadas"
fi

# 3. Robots.txt
echo " → Robots.txt..."
curl -sk "$URL/robots.txt" > "$OUTPUT_DIR/robots_${PORT}.txt"
if [[ -s "$OUTPUT_DIR/robots_${PORT}.txt" ]]; then
    echo " ✅ Robots.txt encontrado"
    head -5 "$OUTPUT_DIR/robots_${PORT}.txt"
fi

# 4. Sitemap
echo " → Sitemap.xml..."
curl -sk "$URL/sitemap.xml" > "$OUTPUT_DIR/sitemap_${PORT}.xml" 2>/dev/null

# 5. Fuzzing rápido
echo " → Fuzzing rápido..."
if command -v ffuf &>/dev/null; then
    ffuf -w /usr/share/wordlists/dirb/common.txt -u "$URL/FUZZ" -mc 200,301,302,403 -fc 404 -t 20 -o "$OUTPUT_DIR/ffuf_${PORT}.json" -of json 2>/dev/null
    if [[ -f "$OUTPUT_DIR/ffuf_${PORT}.json" ]]; then
        FOUND=$(grep -c "url" "$OUTPUT_DIR/ffuf_${PORT}.json" 2>/dev/null)
        echo " ✅ $FOUND directorios encontrados"
    fi
fi

echo ""
echo "📁 Resultados guardados en: $OUTPUT_DIR"
