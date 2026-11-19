#!/bin/bash

# ============================================================
# RUN ALL LABS - Muestra todos los laboratorios
# Uso: ./run_all_labs.sh
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

echo "════════════════════════════════════════════════════════"
echo " LABORATORIOS DISPONIBLES"
echo "════════════════════════════════════════════════════════"

echo ""
echo "▪ HACKTHEBOX"
echo "────────────────────────────────────────"
ls "$SCRIPT_DIR/hackthebox/machines/" 2>/dev/null || echo "  Sin máquinas configuradas"

echo ""
echo "▪ TRYHACKME"
echo "────────────────────────────────────────"
ls "$SCRIPT_DIR/tryhackme/rooms/" 2>/dev/null || echo "  Sin salas configuradas"

echo ""
echo "▪ ACTIVE DIRECTORY"
echo "────────────────────────────────────────"
ls "$SCRIPT_DIR/active_directory/machines/" 2>/dev/null || echo "  Sin dominios configurados"

echo ""
echo "▪ WEB APPS"
echo "────────────────────────────────────────"
ls "$SCRIPT_DIR/web_apps/machines/" 2>/dev/null || echo "  Sin aplicaciones configuradas"

echo ""
echo "▪ CLOUD"
echo "────────────────────────────────────────"
ls "$SCRIPT_DIR/cloud/machines/" 2>/dev/null || echo "  Sin laboratorios configurados"

echo ""
echo "════════════════════════════════════════════════════════"
echo " ✔ LABORATORIOS LISTADOS"
echo "════════════════════════════════════════════════════════"
