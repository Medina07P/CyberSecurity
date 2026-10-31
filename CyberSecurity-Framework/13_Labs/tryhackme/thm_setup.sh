#!/bin/bash

# ============================================================
# THM SETUP - Configura sala de TryHackMe
# Uso:     ./thm_setup.sh <SALA>
# Ejemplo: ./thm_setup.sh VulnNet
# ============================================================

ROOM="$1"

if [[ -z "$ROOM" ]]; then
    echo "Uso: ./thm_setup.sh <SALA>"
    echo "Ejemplo: ./thm_setup.sh VulnNet"
    exit 1
fi

mkdir -p "rooms/${ROOM}"/{recon,exploits,loot,notes}
echo "📁 Sala ${ROOM} creada en: rooms/${ROOM}"

# Obtener IP de la VPN (si existe)
VPN_IP=$(ip a 2>/dev/null | grep tun0 | grep inet | awk '{print $2}' | cut -d/ -f1)
if [[ -z "$VPN_IP" ]]; then
    VPN_IP="No conectado a VPN"
fi

cat > "rooms/${ROOM}/notes/README.md" << NOTES
# THM - ${ROOM}

## IP
${ROOM}

## Puertos
\`\`\`
\`\`\`

## Hallazgos
\`\`\`
\`\`\`

## Explotación
\`\`\`
\`\`\`

## Flags
\`\`\`
\`\`\`
NOTES

echo "✅ Sala ${ROOM} configurada"
