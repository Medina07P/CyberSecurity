#!/bin/bash
# ============================================================
#  RUN ALL OSINT - Ejecuta la recopilación OSINT de un dominio
#  Uso: ./run_all_osint.sh <dominio> [archivo]
#  Ejemplo: ./run_all_osint.sh example.com
#  Nota: se puede lanzar desde cualquier directorio (se autolocaliza);
#        los resultados van a los directorios del módulo (emails/,
#        domains/, subdomains/, social_media/, metadata/).
#  <archivo> es opcional y solo se usa con metadata_extractor.sh, que
#        extrae metadatos de un documento local, no de un dominio.
#  Un hijo que falla no se da por bueno: se cuenta, su stderr queda en
#  osint_errores.log y el script sale 1 sin anunciar que completó.
# ============================================================

DOMAIN="$1"
FILE="$2"

if [[ -z "$DOMAIN" ]]; then
    echo "Uso: ./run_all_osint.sh <dominio> [archivo]"
    echo "Ejemplo: ./run_all_osint.sh example.com"
    exit 1
fi

if [[ -n "$FILE" && ! -f "$FILE" ]]; then
    echo "❌ Archivo no encontrado: $FILE"
    echo "   <archivo> es opcional; si se indica, debe ser un archivo local."
    exit 1
fi

# Los hijos se invocan con rutas relativas: ejecutar desde este directorio.
MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$MODULE_DIR" || exit 1

ERROR_LOG="$MODULE_DIR/osint_errores.log"
# El log se añade, no se vacía: así quedan los fallos de ejecuciones previas.
{
    echo "── $(date '+%Y-%m-%d %H:%M:%S') — $DOMAIN${FILE:+ (archivo: $FILE)}"
} >> "$ERROR_LOG"

RAN=0
FAILED=0

# run_one <etiqueta> <script> [args...]
run_one() {
    local label="$1"
    local script="$2"
    local rc=0
    shift 2

    RAN=$((RAN + 1))
    echo ""
    echo "▶️  $label — $script $*"
    echo "────────────────────────────────────────────────"

    if [[ ! -f "$script" ]]; then
        echo "  ⚠️  Script no encontrado: $script"
        FAILED=$((FAILED + 1))
        return 1
    fi

    bash "$script" "$@" 2>>"$ERROR_LOG"
    rc=$?
    if [[ $rc -ne 0 ]]; then
        echo "  ⚠️  $label: terminó con código $rc"
        FAILED=$((FAILED + 1))
    fi
    return $rc
}

echo "════════════════════════════════════════════════════════"
echo "  EJECUTANDO OSINT PARA: $DOMAIN"
echo "════════════════════════════════════════════════════════"

run_one "Emails"        scripts/email_harvester.sh    "$DOMAIN"
run_one "WHOIS/DNS"     scripts/osint_harvester.sh    "$DOMAIN"
run_one "Subdominios"   scripts/subdomain_finder.sh   "$DOMAIN"

# social_media_search.sh pide un nombre de empresa, no un dominio. Se
# deriva quitando la última etiqueta (el TLD) y se anuncia el término
# usado, porque es una aproximación: si no cuadra, ejecútalo a mano.
echo ""
if printf '%s' "$DOMAIN" | grep -qE '^[0-9]+(\.[0-9]+)*$'; then
    echo "ℹ️  Redes sociales: se omite, $DOMAIN es una IP y no hay nombre de empresa que derivar."
    echo "    Si lo necesitas: ./scripts/social_media_search.sh 'Nombre Empresa'"
else
    COMPANY="${DOMAIN%%.*}"
    echo "ℹ️  Redes sociales: término derivado del dominio → '$COMPANY'"
    run_one "Redes sociales" scripts/social_media_search.sh "$COMPANY"
fi

if [[ -n "$FILE" ]]; then
    run_one "Metadatos" scripts/metadata_extractor.sh "$FILE"
else
    echo ""
    echo "ℹ️  Metadatos: se omite, metadata_extractor.sh necesita un <archivo> local."
    echo "    Para incluirlo: ./run_all_osint.sh <dominio> <archivo>"
fi

echo ""
echo "════════════════════════════════════════════════════════"
if [[ $FAILED -gt 0 ]]; then
    echo "  ⚠️  OSINT terminó con $FAILED de $RAN pasos fallidos"
    [[ -s "$ERROR_LOG" ]] && echo "  Errores en: $ERROR_LOG"
    echo "════════════════════════════════════════════════════════"
    exit 1
fi
echo "  ✅ OSINT completado ($RAN pasos)"
echo "  Resultados en: $MODULE_DIR/"
echo "════════════════════════════════════════════════════════"
