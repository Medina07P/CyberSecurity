# 📡 02_Recon - Reconocimiento Activo

Este directorio contiene herramientas y datos para la fase de reconocimiento activo.

## 📁 Estructura

| Directorio | Descripción |
|-----------|-------------|
| `host_discovery/` | Descubrimiento de hosts en red |
| `dns/` | Enumeración DNS y registros |
| `whois/` | Información WHOIS |
| `screenshots/` | Capturas de pantalla web |
| `fingerprinting/` | Huella digital de servicios |
| `scripts/` | Scripts de automatización |

## 🚀 Uso Rápido

```bash
# Descubrir hosts
./scripts/ping_sweep.sh 192.168.1 1-254

# Enumerar DNS
./scripts/dns_enum.sh example.com

# Capturar screenshot
./scripts/screenshotter.sh 192.168.1.10 80

# Fingerprinting
./scripts/fingerprint.sh 192.168.1.10

# Auto-recon (completo)
./scripts/auto_recon.sh 192.168.1.10