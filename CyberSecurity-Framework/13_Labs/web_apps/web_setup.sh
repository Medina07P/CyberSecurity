#!/bin/bash

# ============================================================
# WEB SETUP - Configura laboratorio web
# Uso:     ./web_setup.sh <NOMBRE>
# Ejemplo: ./web_setup.sh app.local
# ============================================================

APP="$1"

if [[ -z "$APP" ]]; then
    echo "Uso: ./web_setup.sh <NOMBRE>"
    echo "Ejemplo: ./web_setup.sh app.local"
    exit 1
fi

mkdir -p "machines/${APP}"/{recon,exploits,loot,notes}
echo "📁 Aplicación ${APP} creada en: machines/${APP}"

cat > "machines/${APP}/notes/README.md" << NOTES
# Web - ${APP}

## URL
http://${APP}

## Tecnologías
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

echo "✅ Aplicación ${APP} configurada"
