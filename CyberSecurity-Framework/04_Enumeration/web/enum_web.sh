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

# Un servidor que no responde no es un servidor limpio: enumerar en silencio
# produce un run vacío que se lee como "sin hallazgos".
PROBE=$(curl -sk -o /dev/null -w '%{http_code}' "$URL" 2>>"$OUTPUT_DIR/errores.log")
PROBE_CODE=${PROBE%%:*}
if [[ -z "$PROBE_CODE" || "$PROBE_CODE" == "000" ]]; then
    echo "❌ No se pudo conectar con $URL"
    echo "   Sin respuesta no se enumera nada. El error de curl queda en:"
    echo "   $OUTPUT_DIR/errores.log"
    exit 1
fi

echo "🌐 Enumerando Web en: $URL"
echo "────────────────────────────────────────"

# Una sola línea base para todo el script: evita sondear el catch-all dos veces.
BASE=$(scans_baseline_size "$URL")

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
# "No vacío" no significa "existe": en un catch-all el robots.txt es el mismo
# relleno de la app y anunciarlo sería un hallazgo inventado.
echo " → Robots.txt..."
ROBOTS_SIG=$(scans_signature "$URL/robots.txt")
ROBOTS_SIZE=${ROBOTS_SIG#*:}
curl -sk "$URL/robots.txt" > "$OUTPUT_DIR/robots_${SLUG}_${PORT}.txt"
if [[ -s "$OUTPUT_DIR/robots_${SLUG}_${PORT}.txt" ]]; then
    if [[ -n "$BASE" && "$ROBOTS_SIZE" == "$BASE" ]]; then
        echo "   (la respuesta es el relleno de la app, ${ROBOTS_SIZE} B: no hay robots.txt real)"
    else
        echo " ✅ Robots.txt encontrado"
        head -5 "$OUTPUT_DIR/robots_${SLUG}_${PORT}.txt"
    fi
fi

# 4. Sitemap
echo " → Sitemap.xml..."
curl -sk "$URL/sitemap.xml" > "$OUTPUT_DIR/sitemap_${SLUG}_${PORT}.xml" 2>/dev/null

# 5. Fuzzing rápido
# Sin línea base, una SPA que responde 200 a todo marca cada ruta como hallazgo.
echo " → Fuzzing rápido..."
if command -v ffuf &>/dev/null; then
    FFUF_ARGS=(-w /usr/share/wordlists/dirb/common.txt -u "$URL/FUZZ"
               -mc 200,301,302,403 -fc 404 -t 20
               -o "$OUTPUT_DIR/ffuf_${SLUG}_${PORT}.json" -of json)
    if [[ -n "$BASE" ]]; then
        echo "   (línea base detectada: ${BASE} bytes se filtran)"
        FFUF_ARGS+=(-fs "$BASE")
    fi
    ffuf "${FFUF_ARGS[@]}" 2>>"$OUTPUT_DIR/errores.log"
    if [[ -f "$OUTPUT_DIR/ffuf_${SLUG}_${PORT}.json" ]]; then
        FOUND=$(scans_ffuf_count "$OUTPUT_DIR/ffuf_${SLUG}_${PORT}.json")
        echo " ✅ ${FOUND} directorios encontrados"
    fi
fi

echo ""
echo "📁 Resultados guardados en: $OUTPUT_DIR"
