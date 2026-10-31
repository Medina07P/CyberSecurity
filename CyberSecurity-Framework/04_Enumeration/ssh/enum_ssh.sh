#!/bin/bash
# ============================================================
#  ENUM SSH - Enumeración SSH (OPTIMIZADO)
#  Solo enumera, NO hace fuerza bruta
#  Uso: ./enum_ssh.sh <IP> [PUERTO]
#  Ejemplo: ./enum_ssh.sh 192.168.1.10 22
# ============================================================

TARGET="$1"
PORT="${2:-22}"
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/scans"
OUTPUT_DIR="$SCANS_DIR/ssh"

if [[ -z "$TARGET" ]]; then
    echo "Uso: ./enum_ssh.sh <IP> [PUERTO]"
    echo "Ejemplo: ./enum_ssh.sh 192.168.1.10 22"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "🔑 Enumerando SSH en: $TARGET:$PORT"
echo "────────────────────────────────────────"

# 1. Versión
echo "  → Versión SSH..."
nmap -sV -p "$PORT" "$TARGET" -oN "$OUTPUT_DIR/version.txt" 2>/dev/null

if [[ -f "$OUTPUT_DIR/version.txt" ]]; then
    echo "    ✅ Versión obtenida"
    grep -E "open.*ssh" "$OUTPUT_DIR/version.txt" | head -1
fi

# 2. Métodos de autenticación
echo "  → Métodos de autenticación..."
nmap --script=ssh-auth-methods -p "$PORT" "$TARGET" -oN "$OUTPUT_DIR/auth_methods.txt" 2>/dev/null

if [[ -f "$OUTPUT_DIR/auth_methods.txt" ]]; then
    grep -E "publickey|password|gssapi" "$OUTPUT_DIR/auth_methods.txt" | head -3
fi

# 3. Enumeración de usuarios (solo si no es localhost)
if [[ "$TARGET" != "127.0.0.1" ]] && [[ "$TARGET" != "localhost" ]]; then
    echo "  → Enumerando usuarios (ssh-enum-users)..."
    nmap --script=ssh-enum-users -p "$PORT" "$TARGET" -oN "$OUTPUT_DIR/users.txt" 2>/dev/null
    if [[ -f "$OUTPUT_DIR/users.txt" ]]; then
        grep -E "Valid user" "$OUTPUT_DIR/users.txt"
    fi
fi

# 4. Key exchange (si hay)
echo "  → Key exchange algorithms..."
nmap --script=ssh2-enum-algos -p "$PORT" "$TARGET" -oN "$OUTPUT_DIR/key_exchange.txt" 2>/dev/null

echo ""
echo "📁 Resultados guardados en: $OUTPUT_DIR"
