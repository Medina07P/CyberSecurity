#!/bin/bash
# Generador: sobrescribe enum_web.sh, no enumera ni escanea.
# Uso: ./deepseeenum_web.sh
# Ejemplo: ./deepseeenum_web.sh
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../.." && pwd)"
TARGET_FILE="$ROOT/04_Enumeration/web/enum_web.sh"
TMP_FILE=$(mktemp "${TARGET_FILE}.XXXXXX") || exit 1
cat > "$TMP_FILE" <<'EOF'
#!/bin/bash
# Web completa: headers, tecnologías, robots, sitemap y fuzzing.
# Uso: ./enum_web.sh <IP> [PUERTO] [esquema]
# Ejemplo: ./enum_web.sh 192.0.2.1 80 http
# Alternativa CLI: ./enum_web.sh --url https://example.com:9443/ruta
LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../00_Config/lib" && pwd)"
source "$LIB/enumeration_web.bash"
enum_web_run web "$@"
EOF
chmod +x "$TMP_FILE" || exit 1
mv -f "$TMP_FILE" "$TARGET_FILE" || exit 1
echo "Generado: $TARGET_FILE (sin ejecutar enumeración)."
