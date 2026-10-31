# ─── 04_Enumeration/web/enum_web.sh ───
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGET_FILE="$ROOT/04_Enumeration/web/enum_web.sh"
TMP_FILE="$(mktemp "${TARGET_FILE}.XXXXXX")"
cat > "$TMP_FILE" << 'EOF'
#!/bin/bash
# ============================================================
#  ENUMERACIÓN WEB COMPLETA
# ============================================================

TARGET="$1"
PORT="${2:-80}"
OUTPUT="${3:-web_enum}"

URL="http://${TARGET}:${PORT}"
if [[ "$PORT" == "443" ]]; then
    URL="https://${TARGET}:${PORT}"
fi

echo "🌐 Enumerando web en: $URL"

# 1. Cabeceras
curl -skI "$URL" > "${OUTPUT}_headers.txt"
echo "  ✅ Cabeceras"

# 2. Robots.txt
curl -sk "$URL/robots.txt" > "${OUTPUT}_robots.txt"
echo "  ✅ Robots.txt"

# 3. Sitemap
curl -sk "$URL/sitemap.xml" > "${OUTPUT}_sitemap.xml"
echo "  ✅ Sitemap"

# 4. Fuzzing directorios (rápido)
ffuf -w /usr/share/wordlists/dirb/common.txt -u "$URL/FUZZ" -mc 200,301,302,403 -fc 404 -o "${OUTPUT}_dirs.json" -of json 2>/dev/null
echo "  ✅ Directorios"

# 5. Tecnologías
whatweb -a 3 "$URL" > "${OUTPUT}_technologies.txt"
echo "  ✅ Tecnologías"

echo "✅ Enumeración web completada"
EOF

chmod +x "$TMP_FILE"
mv -f "$TMP_FILE" "$TARGET_FILE"