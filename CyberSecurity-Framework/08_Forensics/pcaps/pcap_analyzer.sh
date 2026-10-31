#!/bin/bash

# PCAP ANALYZER - Analiza capturas de red
# Uso: ./pcap_analyzer.sh <PCAP_FILE>
# Ejemplo: ./pcap_analyzer.sh capture.pcap

PCAP_FILE="$1"
MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="$MODULE_DIR/analysis/pcaps"

if [[ -z "$PCAP_FILE" ]]; then
    echo "Uso: ./pcap_analyzer.sh <PCAP_FILE>"
    echo "Ejemplo: ./pcap_analyzer.sh capture.pcap"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "📡 Analizando captura: $PCAP_FILE"
echo "────────────────────────────────────────"

# 1. Información general
echo " → Información general:"
capinfos "$PCAP_FILE" > "$OUTPUT_DIR/capinfos.txt"
echo " ✅ Información guardada"

# 2. Estadísticas de protocolos
echo " → Protocolos:"
tshark -r "$PCAP_FILE" -z protocols -q > "$OUTPUT_DIR/protocols.txt"

# 3. Conversaciones
echo " → Conversaciones:"
tshark -r "$PCAP_FILE" -z conv,tcp -q > "$OUTPUT_DIR/conversations_tcp.txt"
tshark -r "$PCAP_FILE" -z conv,udp -q > "$OUTPUT_DIR/conversations_udp.txt"

# 4. DNS queries
echo " → DNS queries:"
tshark -r "$PCAP_FILE" -Y "dns.flags.response==0" -T fields -e dns.qry.name | sort -u > "$OUTPUT_DIR/dns_queries.txt"

# 5. HTTP requests
echo " → HTTP requests:"
tshark -r "$PCAP_FILE" -Y "http.request" -T fields -e http.request.uri -e http.host | sort -u > "$OUTPUT_DIR/http_requests.txt"

# 6. Credenciales en texto plano
echo " → Credenciales:"
tshark -r "$PCAP_FILE" -Y "http.request.method==POST" -T fields -e http.request.uri -e http.host -e http.request.uri.query | grep -E "pass|user|login" > "$OUTPUT_DIR/credentials.txt"

# 7. Archivos transferidos
echo " → Archivos transferidos:"
tshark -r "$PCAP_FILE" -Y "http.response" -T fields -e http.file_data -e http.content_type > "$OUTPUT_DIR/files.txt"

echo ""
echo "📁 Resultados guardados en: $OUTPUT_DIR"
