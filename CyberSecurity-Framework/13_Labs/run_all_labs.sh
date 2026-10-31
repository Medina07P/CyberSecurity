#!/bin/bash

# ============================================================
# RUN ALL LABS - Muestra todos los laboratorios
# Uso: ./run_all_labs.sh
# ============================================================

echo "════════════════════════════════════════════════════════"
echo " LABORATORIOS DISPONIBLES"
echo "════════════════════════════════════════════════════════"

echo ""
echo "📁 HACKTHEBOX"
echo "────────────────────────────────────────"
ls hackthebox/machines/ 2>/dev/null || echo "  Sin máquinas configuradas"

echo ""
echo "📁 TRYHACKME"
echo "────────────────────────────────────────"
ls tryhackme/rooms/ 2>/dev/null || echo "  Sin salas configuradas"

echo ""
echo "📁 ACTIVE DIRECTORY"
echo "────────────────────────────────────────"
ls active_directory/machines/ 2>/dev/null || echo "  Sin dominios configurados"

echo ""
echo "📁 WEB APPS"
echo "────────────────────────────────────────"
ls web_apps/machines/ 2>/dev/null || echo "  Sin aplicaciones configuradas"

echo ""
echo "📁 CLOUD"
echo "────────────────────────────────────────"
ls cloud/machines/ 2>/dev/null || echo "  Sin laboratorios configurados"

echo ""
echo "════════════════════════════════════════════════════════"
echo " ✅ LABORATORIOS LISTADOS"
echo "════════════════════════════════════════════════════════"
