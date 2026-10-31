#!/bin/bash

# ============================================================
# AD SETUP - Configura laboratorio Active Directory
# Uso:     ./ad_setup.sh <DOMINIO>
# Ejemplo: ./ad_setup.sh domain.local
# ============================================================

DOMAIN="$1"

if [[ -z "$DOMAIN" ]]; then
    echo "Uso: ./ad_setup.sh <DOMINIO>"
    echo "Ejemplo: ./ad_setup.sh domain.local"
    exit 1
fi

mkdir -p "machines/${DOMAIN}"/{recon,exploits,loot,notes}
echo "📁 Dominio ${DOMAIN} creado en: machines/${DOMAIN}"

cat > "machines/${DOMAIN}/notes/README.md" << NOTES
# AD - ${DOMAIN}

## Controladores de Dominio
\`\`\`
\`\`\`

## Usuarios
\`\`\`
\`\`\`

## Grupos
\`\`\`
\`\`\`

## Hallazgos
\`\`\`
\`\`\`

## Ataques
\`\`\`
\`\`\`

## Flags
\`\`\`
\`\`\`
NOTES

echo "✅ Dominio ${DOMAIN} configurado"
