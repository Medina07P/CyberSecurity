#!/bin/bash

# ENUM WEB ADVANCED - Enumeración Web avanzada
# Uso: ./enum_web_advanced.sh <IP>
# Ejemplo: ./enum_web_advanced.sh 192.168.1.10

TARGET="$1"

SCANS_LIB="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../../00_Config/lib" && pwd)"
source "$SCANS_LIB/scans.bash"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./enum_web_advanced.sh <IP>"
    echo "Ejemplo: ./enum_web_advanced.sh 192.168.1.10"
    exit 1
fi

OUTPUT_DIR=$(scans_dir web)
SLUG=$(scans_slug "$TARGET")

echo "🌐 Enumeración Web Avanzada en: $TARGET"
echo "────────────────────────────────────────"

# Escanear puertos web comunes
for port in 80 443 8080 8443 8000 8888 9000; do
    if nc -zv "$TARGET" "$port" 2>/dev/null; then
        echo " → Puerto $port abierto"
        PROTO="http"
        [[ "$port" == "443" || "$port" == "8443" ]] && PROTO="https"
        URL="${PROTO}://${TARGET}:${port}"

        # Cabeceras de seguridad
        echo " → Cabeceras de seguridad..."
        curl -skI "$URL" | grep -iE "X-Frame-Options|X-Content-Type-Options|Content-Security-Policy|Strict-Transport-Security" > "$OUTPUT_DIR/security_headers_${SLUG}_${port}.txt"

        # Archivos sensibles. Sin línea base, un catch-all marca los siete archivos.
        echo " → Buscando archivos sensibles..."
        BASE=$(scans_baseline_size "$URL")
        for file in .env .git/config backup.zip config.php wp-config.php .htaccess admin.php; do
            SIG=$(scans_signature "$URL/$file")
            CODE=${SIG%%:*}
            SIZE=${SIG#*:}
            [[ "$CODE" =~ ^(200|301|302|403)$ ]] || continue
            [[ "$BASE" != "0" && "$SIZE" == "$BASE" ]] && continue
            echo " 🔴 $file ($CODE)"
            echo "$URL/$file|$CODE" >> "$OUTPUT_DIR/sensitive_files_${SLUG}_${port}.txt"
        done
    fi
done

echo ""
echo "📁 Resultados guardados en: $OUTPUT_DIR"
