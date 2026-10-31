#!/bin/bash

# ENUM WEB ADVANCED - Enumeración Web avanzada
# Uso: ./enum_web_advanced.sh <IP>
# Ejemplo: ./enum_web_advanced.sh 192.168.1.10

TARGET="$1"
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/scans"
OUTPUT_DIR="$SCANS_DIR/web"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./enum_web_advanced.sh <IP>"
    echo "Ejemplo: ./enum_web_advanced.sh 192.168.1.10"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

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
        curl -skI "$URL" | grep -iE "X-Frame-Options|X-Content-Type-Options|Content-Security-Policy|Strict-Transport-Security" > "$OUTPUT_DIR/security_headers_${port}.txt"

        # Archivos sensibles
        echo " → Buscando archivos sensibles..."
        for file in .env .git/config backup.zip config.php wp-config.php .htaccess admin.php; do
            CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$URL/$file")
            if [[ "$CODE" =~ ^(200|301|302|403) ]]; then
                echo " 🔴 $file ($CODE)"
                echo "$URL/$file|$CODE" >> "$OUTPUT_DIR/sensitive_files_${port}.txt"
            fi
        done
    fi
done

echo ""
echo "📁 Resultados guardados en: $OUTPUT_DIR"
