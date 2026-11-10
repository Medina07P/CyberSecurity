#!/bin/bash
# Orquestador AVANZADO: Nmap completo, Masscan opcional y análisis web activo.
# Uso: ./run_all_scanners.sh <TARGET>
# Ejemplo: ./run_all_scanners.sh 192.0.2.1
MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$MODULE_DIR/../00_Config/lib/scanner_runtime.bash"
TARGET="${1:-}"
[[ -n "$TARGET" ]] || { echo 'Uso: ./run_all_scanners.sh <TARGET>'; exit 1; }
scanner_host "$TARGET" && scanner_require nmap || exit 1
cd "$MODULE_DIR" || exit 1
OUTPUT_DIR=$(scans_dir nmap) || exit 1
EJECUTADAS=0
FALLIDAS=0
OMITIDAS=0
run_child() {
    local script="$1"
    shift
    if [[ ! -f "$script" ]]; then
        echo "❌ Script no encontrado: $script"
        FALLIDAS=$((FALLIDAS + 1))
        return
    fi
    EJECUTADAS=$((EJECUTADAS + 1))
    if ! bash "$script" "$@"; then
        FALLIDAS=$((FALLIDAS + 1))
    fi
}
echo "⚠️ Modo avanzado: todos los puertos y análisis activo sobre $TARGET"
run_child network_scanners/nmap/nmap_smart.sh "$TARGET"
if [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    if command -v masscan >/dev/null 2>&1 && [[ "$(id -u)" == 0 ]]; then
        run_child network_scanners/masscan/masscan_scan.sh "$TARGET" 1-65535
    else
        echo 'OMITIDO Masscan: requiere herramienta instalada y root; sin sudo automático.'
        OMITIDAS=$((OMITIDAS + 1))
    fi
else
    echo 'OMITIDO Masscan: solo se usa con una IPv4 explícita, sin resolver dominios.'
    OMITIDAS=$((OMITIDAS + 1))
fi

echo 'Descubriendo puertos web 80,443,8080,8443 (no cubre otros puertos).'
EJECUTADAS=$((EJECUTADAS + 1))
if WEB_DISCOVERY=$(scanner_run "$OUTPUT_DIR/errores.log" nmap -Pn -p 80,443,8080,8443 "$TARGET"); then
    WEB_PORTS=$(printf '%s\n' "$WEB_DISCOVERY" | awk '$1 ~ /^[0-9]+\/tcp$/ && $2 == "open" {split($1,p,"/"); print p[1]}')
    if [[ -z "$WEB_PORTS" ]]; then
        echo 'No se encontraron puertos web abiertos entre los cuatro comprobados.'
    else
        echo 'El esquema por puerto es una heurística (443/8443 → HTTPS), no detección de TLS.'
        URL_HOST="$TARGET"
        [[ "$TARGET" != *:* ]] || URL_HOST="[$TARGET]"
        for port in $WEB_PORTS; do
            scheme=http
            [[ "$port" != 443 && "$port" != 8443 ]] || scheme=https
            url="$scheme://$URL_HOST:$port"
            run_child web_scanners/nikto/nikto_scan.sh "$url"
            run_child web_scanners/nuclei/nuclei_scan.sh "$url"
        done
    fi
else
    echo '❌ Descubrimiento web fallido: NO DETERMINADO; no se ejecutan sondas web.'
    FALLIDAS=$((FALLIDAS + 1))
fi
printf '\nRESUMEN — Ejecutadas: %s | Fallidas: %s | Omitidas: %s\n' "$EJECUTADAS" "$FALLIDAS" "$OMITIDAS"
if (( FALLIDAS )); then
    echo '❌ Ejecución incompleta. Revisa los diagnósticos de esta ejecución.'
    exit 1
fi
echo '✅ Ejecución terminada; las omisiones no se han evaluado.'
exit 0
