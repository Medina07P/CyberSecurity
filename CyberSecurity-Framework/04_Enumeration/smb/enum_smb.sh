# ─── 04_Enumeration/smb/enum_smb.sh ───
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGET_FILE="$ROOT/04_Enumeration/smb/enum_smb.sh"
TMP_FILE="$(mktemp "${TARGET_FILE}.XXXXXX")"
cat > "$TMP_FILE" << 'EOF'
#!/bin/bash
# ============================================================
#  ENUMERACIÓN SMB COMPLETA
# ============================================================

TARGET="$1"
OUTPUT="${2:-smb_enum}"

echo "📁 Enumerando SMB en: $TARGET"

# 1. Listar shares
echo "  → Shares disponibles"
smbclient -L "//$TARGET" -N > "${OUTPUT}_shares.txt" 2>/dev/null

# 2. Enumerar usuarios (enum4linux)
enum4linux -a "$TARGET" > "${OUTPUT}_enum4linux.txt" 2>/dev/null

# 3. Null session
rpcclient -U "" -N "$TARGET" -c "enumdomusers" > "${OUTPUT}_users.txt" 2>/dev/null

# 4. Probando shares comunes
for share in "ADMIN$" "IPC$" "C$" "public" "share" "documents" "backup"; do
    echo -n "  → Probando $share: "
    if smbclient "//$TARGET/$share" -N -c "ls" 2>/dev/null | grep -q "."; then
        echo "✅ Accesible"
        echo "$share: accesible" >> "${OUTPUT}_accesible.txt"
    else
        echo "❌ No accesible"
    fi
done

echo "✅ Enumeración SMB completada"
EOF

chmod +x "$TMP_FILE"
mv -f "$TMP_FILE" "$TARGET_FILE"