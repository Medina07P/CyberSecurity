#!/bin/bash
# Generador: se reemplaza por el enumerador SMB; no escanea al generar.
# Uso: ./enum_smb.sh
# Ejemplo: ./enum_smb.sh
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../.." && pwd)"
TARGET_FILE="$ROOT/04_Enumeration/smb/enum_smb.sh"
TMP_FILE=$(mktemp "${TARGET_FILE}.XXXXXX") || exit 1
cat > "$TMP_FILE" <<'EOF'
#!/bin/bash
# SMB generado: shares, enum4linux, RPC y prueba de los siete shares comunes.
# Uso: ./enum_smb.sh <IP> [prefijo]
# Ejemplo: ./enum_smb.sh 192.0.2.1 smb_enum
LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../00_Config/lib" && pwd)"
source "$LIB/enumeration_services.bash"
enum_service smb "${1:-}"
RC=$?
[[ -n "${ENUM_WORK:-}" ]] || exit 1
enum_common_shares "${2:-smb_enum}"
(( RC == 0 && ENUM_FAILED == 0 ))
EOF
chmod +x "$TMP_FILE" || exit 1
mv -f "$TMP_FILE" "$TARGET_FILE" || exit 1
echo "Generado: $TARGET_FILE (sin ejecutar enumeración)."
