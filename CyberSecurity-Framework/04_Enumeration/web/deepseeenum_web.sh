#!/bin/bash
# ─── Generador: escribe 04_Enumeration/web/enum_web.sh ───
# Uso: ./deepseeenum_web.sh
# Ejemplo: ./deepseeenum_web.sh
# Mantener el heredoc en paralelo con enum_web.sh: regenerar no debe
# revertir los arreglos de nombres ni la línea base.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../.." && pwd)"
TARGET_FILE="$ROOT/04_Enumeration/web/enum_web.sh"
TMP_FILE="$(mktemp "${TARGET_FILE}.XXXXXX")"
cat > "$TMP_FILE" << 'EOF'
#!/bin/bash

# ENUM WEB - Enumeración Web completa
# Uso: ./enum_web.sh <IP> [PUERTO]
# Ejemplo: ./enum_web.sh 192.168.1.10 80

TARGET="$1"
PORT="${2:-80}"

SCANS_LIB="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../../00_Config/lib" && pwd)"
source "$SCANS_LIB/scans.bash"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./enum_web.sh <IP> [PUERTO]"
    echo "Ejemplo: ./enum_web.sh 192.168.1.10 80"
    exit 1
fi

OUTPUT_DIR=$(scans_dir web)
SLUG=$(scans_slug "$TARGET")

PROTO="http"
[[ "$PORT" == "443" || "$PORT" == "8443" ]] && PROTO="https"
URL="${PROTO}://${TARGET}:${PORT}"

echo "🌐 Enumerando Web en: $URL"
echo "────────────────────────────────────────"

# 1. Cabeceras
echo " → Cabeceras HTTP..."
curl -skI "$URL" > "$OUTPUT_DIR/headers_${SLUG}_${PORT}.txt"
if [[ -s "$OUTPUT_DIR/headers_${SLUG}_${PORT}.txt" ]]; then
    echo " ✅ Cabeceras obtenidas"
    head -10 "$OUTPUT_DIR/headers_${SLUG}_${PORT}.txt"
fi

# 2. Tecnologías
echo " → Tecnologías..."
if command -v whatweb &>/dev/null; then
    whatweb -a 3 "$URL" > "$OUTPUT_DIR/technologies_${SLUG}_${PORT}.txt"
    echo " ✅ Tecnologías detectadas"
fi

# 3. Robots.txt
echo " → Robots.txt..."
curl -sk "$URL/robots.txt" > "$OUTPUT_DIR/robots_${SLUG}_${PORT}.txt"
if [[ -s "$OUTPUT_DIR/robots_${SLUG}_${PORT}.txt" ]]; then
    echo " ✅ Robots.txt encontrado"
    head -5 "$OUTPUT_DIR/robots_${SLUG}_${PORT}.txt"
fi

# 4. Sitemap
echo " → Sitemap.xml..."
curl -sk "$URL/sitemap.xml" > "$OUTPUT_DIR/sitemap_${SLUG}_${PORT}.xml" 2>/dev/null

# 5. Fuzzing rápido
# Sin línea base, una SPA que responde 200 a todo marca cada ruta como hallazgo.
echo " → Fuzzing rápido..."
if command -v ffuf &>/dev/null; then
    BASE=$(scans_baseline_size "$URL")
    FFUF_ARGS=(-w /usr/share/wordlists/dirb/common.txt -u "$URL/FUZZ"
               -mc 200,301,302,403 -fc 404 -t 20
               -o "$OUTPUT_DIR/ffuf_${SLUG}_${PORT}.json" -of json)
    if [[ "$BASE" != "0" ]]; then
        echo "   (línea base detectada: ${BASE} bytes se filtran)"
        FFUF_ARGS+=(-fs "$BASE")
    fi
    ffuf "${FFUF_ARGS[@]}" 2>/dev/null
    if [[ -f "$OUTPUT_DIR/ffuf_${SLUG}_${PORT}.json" ]]; then
        FOUND=$(grep -c "\"url\"" "$OUTPUT_DIR/ffuf_${SLUG}_${PORT}.json" 2>/dev/null)
        echo " ✅ ${FOUND} directorios encontrados"
    fi
fi

echo ""
echo "📁 Resultados guardados en: $OUTPUT_DIR"
EOF

chmod +x "$TMP_FILE"
mv -f "$TMP_FILE" "$TARGET_FILE"
