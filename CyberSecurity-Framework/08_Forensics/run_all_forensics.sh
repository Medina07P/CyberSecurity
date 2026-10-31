#!/bin/bash

# RUN ALL FORENSICS - Ejecuta análisis forense completo
# Uso: ./run_all_forensics.sh

echo "════════════════════════════════════════════════════════"
echo " ANÁLISIS FORENSE COMPLETO"
echo "════════════════════════════════════════════════════════"

# 1. Memoria
echo ""
echo "📁 MEMORY ANALYSIS"
echo "────────────────────────────────────────"
echo " → Dump de memoria..."
./memory/memory_dump.sh
echo " → Strings analysis..."
./memory/strings_analysis.sh ../captures/memory/*.raw 2>/dev/null

# 2. Logs
echo ""
echo "📁 LOGS ANALYSIS"
echo "────────────────────────────────────────"
if [[ -f "/var/log/syslog" ]]; then
    ./logs/log_analyzer.sh /var/log/syslog
fi

# 3. PCAP (si existe)
echo ""
echo "📁 PCAP ANALYSIS"
echo "────────────────────────────────────────"
if ls ../captures/pcap/*.pcap 2>/dev/null; then
    for pcap in ../captures/pcap/*.pcap; do
        ./pcaps/pcap_analyzer.sh "$pcap"
    done
else
    echo " ℹ️ No se encontraron archivos PCAP"
fi

# 4. Timeline
echo ""
echo "📁 TIMELINE"
echo "────────────────────────────────────────"
./timeline/timeline_creator.sh

echo ""
echo "════════════════════════════════════════════════════════"
echo " ✅ ANÁLISIS FORENSE COMPLETADO"
echo "════════════════════════════════════════════════════════"
