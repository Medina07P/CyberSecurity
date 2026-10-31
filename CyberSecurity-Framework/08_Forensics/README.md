# 🔬 08_Forensics - Análisis Forense Digital

Herramientas para análisis forense de sistemas, memoria, discos y redes.

## 📁 Estructura

| Directorio | Descripción |
|-----------|-------------|
| `memory/` | Análisis de memoria RAM |
| `disk/` | Análisis de discos y archivos |
| `logs/` | Análisis de logs del sistema |
| `pcaps/` | Análisis de capturas de red |
| `timeline/` | Creación de líneas de tiempo |

## 🚀 Uso Rápido

```bash
# Análisis de memoria
./memory/memory_dump.sh

# Análisis de disco
./disk/disk_forensics.sh /dev/sda1

# Análisis de logs
./logs/log_analyzer.sh /var/log/syslog

# Análisis de PCAP
./pcaps/pcap_analyzer.sh capture.pcap

# Crear línea de tiempo
./timeline/timeline_creator.sh