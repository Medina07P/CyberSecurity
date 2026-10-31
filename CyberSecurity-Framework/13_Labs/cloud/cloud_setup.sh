#!/bin/bash

# ============================================================
# CLOUD SETUP - Configura laboratorio en la nube
# Uso:     ./cloud_setup.sh <NOMBRE>
# Ejemplo: ./cloud_setup.sh aws-lab
# ============================================================

LAB="$1"

if [[ -z "$LAB" ]]; then
    echo "Uso: ./cloud_setup.sh <NOMBRE>"
    echo "Ejemplo: ./cloud_setup.sh aws-lab"
    exit 1
fi

mkdir -p "machines/${LAB}"/{recon,exploits,loot,notes}
echo "📁 Laboratorio ${LAB} creado en: machines/${LAB}"

cat > "machines/${LAB}/notes/README.md" << NOTES
# Cloud - ${LAB}

## Proveedor
\`\`\`
\`\`\`

## Recursos
\`\`\`
\`\`\`

## Credenciales
\`\`\`
\`\`\`

## Hallazgos
\`\`\`
\`\`\`

## Explotación
\`\`\`
\`\`\`
NOTES

echo "✅ Laboratorio ${LAB} configurado"
