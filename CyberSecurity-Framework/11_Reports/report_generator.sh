#!/bin/bash

# ============================================================
# REPORT GENERATOR - Genera informes profesionales
# Uso: ./report_generator.sh [OPCIONES]
# Ejemplo: ./report_generator.sh --full
# ============================================================

REPORT_DIR="$(pwd)"
EVIDENCE_DIR="../10_Evidence"
DATE=$(date +%Y%m%d)
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

generate_executive() {
    echo "📊 Generando informe ejecutivo..."
    echo "────────────────────────────────────────"

    mkdir -p executive

    cat > executive/executive_summary.md << 'EOF'
# INFORME EJECUTIVO DE AUDITORÍA

## Resumen Ejecutivo
- **Fecha:** [FECHA]
- **Auditor:** [NOMBRE_AUDITOR]
- **Cliente:** [NOMBRE_CLIENTE]
- **Alcance:** [DESCRIPCIÓN_ALCANCE]

## Hallazgos Principales

### Resumen de Hallazgos
| Severidad | Cantidad |
|-----------|----------|
| Crítico   | X        |
| Alto      | X        |
| Medio     | X        |
| Bajo      | X        |

### Hallazgos Críticos
- **[Nombre del hallazgo]**
  - Descripción: [Descripción]
  - Impacto: [Impacto]
  - Recomendación: [Recomendación]

### Hallazgos de Alto Riesgo
- **[Nombre del hallazgo]**
  - Descripción: [Descripción]
  - Impacto: [Impacto]
  - Recomendación: [Recomendación]

## Recomendaciones Prioritarias
1. [Recomendación 1]
2. [Recomendación 2]
3. [Recomendación 3]

## Conclusión
[Conclusión general de la auditoría]

## Próximos Pasos
1. [Paso 1]
2. [Paso 2]
3. [Paso 3]

---
*Informe generado automáticamente por CTF Toolkit Pro*
EOF

    sed -i "s/\[FECHA\]/$TIMESTAMP/g"           executive/executive_summary.md
    sed -i "s/\[NOMBRE_AUDITOR\]/$(whoami)/g"   executive/executive_summary.md
    sed -i "s/\[NOMBRE_CLIENTE\]/Cliente/g"      executive/executive_summary.md
    sed -i "s/\[DESCRIPCIÓN_ALCANCE\]/Escaneo de red y aplicaciones web/g" executive/executive_summary.md

    echo "  ✅ Informe ejecutivo generado: executive/executive_summary.md"
}

generate_technical() {
    echo "🔬 Generando informe técnico..."
    echo "────────────────────────────────────────"

    mkdir -p technical

    cat > technical/technical_report.md << 'EOF'
# INFORME TÉCNICO DE AUDITORÍA

## Metodología
La auditoría se realizó siguiendo las siguientes fases:
1. Recopilación de Información (OSINT)
2. Reconocimiento Activo
3. Escaneo de Vulnerabilidades
4. Enumeración de Servicios
5. Explotación Controlada
6. Post-Explotación
7. Recopilación de Evidencias

## Hallazgos Detallados

### Vulnerabilidades Encontradas

#### [CVE-ID] - [Nombre]
- **Severidad:** [Crítico/Alto/Medio/Bajo]
- **Descripción:** [Descripción detallada]
- **Impacto:** [Impacto técnico]
- **CVSS Score:** [Puntuación]
- **Sistemas Afectados:** [Lista de sistemas]
- **Evidencia:** [Ruta a la evidencia]
- **Recomendación:** [Cómo corregir]

### Configuraciones Inseguras

#### [Nombre]
- **Descripción:** [Descripción]
- **Impacto:** [Impacto]
- **Recomendación:** [Cómo corregir]

## Pruebas Realizadas

### Pruebas de Autenticación
[Resultados]

### Pruebas de Autorización
[Resultados]

### Pruebas de Inyección
[Resultados]

## Recomendaciones Técnicas

### Parcheo de Sistemas
- [Lista de parches necesarios]

### Configuración de Seguridad
- [Lista de configuraciones]

### Controles Adicionales
- [Lista de controles]

## Apéndice

### Herramientas Utilizadas
- Nmap
- Metasploit
- Burp Suite
- [Otras herramientas]

### Tiempos de Ejecución
- [Tiempo por fase]

---
*Informe técnico generado automáticamente*
EOF

    echo "  ✅ Informe técnico generado: technical/technical_report.md"
}

generate_final() {
    echo "📄 Generando informe final..."
    echo "────────────────────────────────────────"

    mkdir -p final_report

    {
        echo "# INFORME FINAL DE AUDITORÍA"
        echo ""
        cat executive/executive_summary.md
        echo ""
        echo "---"
        echo ""
        cat technical/technical_report.md
    } > final_report/final_report.md

    echo "  ✅ Informe final generado: final_report/final_report.md"
}

generate_html() {
    echo "🌐 Convirtiendo a HTML..."
    echo "────────────────────────────────────────"

    if command -v pandoc &>/dev/null; then
        for file in final_report/final_report.md executive/executive_summary.md technical/technical_report.md; do
            if [[ -f "$file" ]]; then
                output="${file%.md}.html"
                pandoc "$file" -o "$output" \
                    --standalone \
                    --toc \
                    --css=https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css
                echo "  ✅ HTML generado: $output"
            fi
        done
    else
        echo "  ⚠️  Pandoc no instalado. Instalar con: sudo apt install pandoc"

        for file in final_report/final_report.md; do
            if [[ -f "$file" ]]; then
                output="${file%.md}.html"
                {
                    echo '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Informe de Auditoría</title></head><body><pre>'
                    cat "$file"
                    echo '</pre></body></html>'
                } > "$output"
                echo "  ✅ HTML básico generado: $output"
            fi
        done
    fi
}

generate_pdf() {
    echo "📄 Convirtiendo a PDF..."
    echo "────────────────────────────────────────"

    if command -v wkhtmltopdf &>/dev/null; then
        for file in final_report/final_report.html executive/executive_summary.html technical/technical_report.html; do
            if [[ -f "$file" ]]; then
                output="${file%.html}.pdf"
                wkhtmltopdf "$file" "$output" 2>/dev/null
                echo "  ✅ PDF generado: $output"
            fi
        done
    else
        echo "  ⚠️  wkhtmltopdf no instalado. Instalar con: sudo apt install wkhtmltopdf"

        if command -v pandoc &>/dev/null; then
            pandoc final_report/final_report.md -o final_report/final_report.pdf 2>/dev/null
            echo "  ✅ PDF generado con pandoc: final_report/final_report.pdf"
        else
            echo "  ⚠️  Pandoc tampoco disponible. No se puede generar PDF."
        fi
    fi
}

show_help() {
    echo "════════════════════════════════════════════════════════"
    echo "  REPORT GENERATOR"
    echo "════════════════════════════════════════════════════════"
    echo ""
    echo "  Uso: ./report_generator.sh [OPCIONES]"
    echo ""
    echo "  Opciones:"
    echo "    --executive   Generar informe ejecutivo"
    echo "    --technical   Generar informe técnico"
    echo "    --full        Generar informe completo"
    echo "    --html        Generar versión HTML"
    echo "    --pdf         Generar versión PDF"
    echo "    --all         Generar todo"
    echo "    --help        Mostrar esta ayuda"
    echo ""
    echo "  Ejemplos:"
    echo "    ./report_generator.sh --full"
    echo "    ./report_generator.sh --all"
}

case "$1" in
    --executive) generate_executive ;;
    --technical) generate_technical ;;
    --full)
        generate_executive
        generate_technical
        generate_final
        ;;
    --html) generate_html ;;
    --pdf)  generate_pdf ;;
    --all)
        generate_executive
        generate_technical
        generate_final
        generate_html
        generate_pdf
        ;;
    --help|-h) show_help ;;
    *)
        echo "❌ Opción no reconocida: $1"
        echo "Usa: ./report_generator.sh --help"
        exit 1
        ;;
esac
