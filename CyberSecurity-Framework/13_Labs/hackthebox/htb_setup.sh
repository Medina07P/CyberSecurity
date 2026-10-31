#!/bin/bash

# ============================================================
# HTB SETUP - Configura máquina de HackTheBox
# Uso:     ./htb_setup.sh <MÁQUINA>
# Ejemplo: ./htb_setup.sh Blue
# ============================================================

MACHINE="$1"

if [[ -z "$MACHINE" ]]; then
    echo "Uso: ./htb_setup.sh <MÁQUINA>"
    echo "Ejemplo: ./htb_setup.sh Blue"
    exit 1
fi

mkdir -p "machines/${MACHINE}"/{recon,exploits,loot,notes}
echo "📁 Máquina ${MACHINE} creada en: machines/${MACHINE}"

# Obtener IP de la VPN (si existe)
VPN_IP=$(ip a 2>/dev/null | grep tun0 | grep inet | awk '{print $2}' | cut -d/ -f1)
if [[ -z "$VPN_IP" ]]; then
    VPN_IP="No conectado a VPN"
fi

cat > "machines/${MACHINE}/notes/README.md" << NOTES
# HTB - ${MACHINE}

## IP
${VPN_IP}

## Puertos abiertos
\`\`\`
\`\`\`

## Servicios
\`\`\`
\`\`\`

## Hallazgos
\`\`\`
\`\`\`

## Explotación
\`\`\`
\`\`\`

## Post-explotación
\`\`\`
\`\`\`

## Flags
- user:
- root:
NOTES

echo "✅ Máquina ${MACHINE} configurada"
echo "📁 Directorio: $(pwd)/machines/${MACHINE}"
