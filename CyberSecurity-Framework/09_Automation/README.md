# 🤖 09_Automation - Automatización

Scripts y workflows para automatizar todas las fases del framework.

## 📁 Estructura

| Directorio | Descripción |
|-----------|-------------|
| `bash/` | Scripts Bash para automatización |
| `python/` | Scripts Python para tareas complejas |
| `powershell/` | Scripts PowerShell para Windows |
| `docker/` | Contenedores para entornos aislados |
| `workflows/` | Definiciones de flujos de trabajo |

## 🚀 Uso Rápido

```bash
# Auditoría completa con Bash
./bash/auto_recon.sh 192.168.1.10

# Orquestador Python
python3 python/orchestrator.py --target 192.168.1.10 --full

# Generar reporte
python3 python/report_generator.py --input scans/ --output report.html

# Docker
docker-compose up -d