# 📡 03_Scanners - Escáneres de Red y Vulnerabilidades

Este directorio contiene los escáneres de puertos, servicios y vulnerabilidades web.

## 📁 Estructura

| Directorio | Descripción |
|-----------|-------------|
| `network_scanners/nmap/` | Nmap: escaneo inteligente, agresivo y con scripts NSE |
| `network_scanners/masscan/` | Masscan: descubrimiento ultrarrápido de puertos |
| `network_scanners/rustscan/` | RustScan: descubrimiento rápido con derivación a Nmap |
| `web_scanners/nikto/` | Nikto: análisis de servidores web |
| `web_scanners/nuclei/` | Nuclei: plantillas de vulnerabilidades y CVEs |
| `web_scanners/burpsuite/` | Configuración de Burp Suite (no ejecutable) |

## 🚀 Uso Rápido

Ejecutar siempre desde `03_Scanners/`, nunca desde la raíz del repo:

```bash
# Encadena todos los escáneres disponibles
./run_all_scanners.sh 192.168.1.10

# Nmap inteligente (puertos → servicios → vulnerabilidades)
./network_scanners/nmap/nmap_smart.sh 192.168.1.10

# Nmap agresivo
./network_scanners/nmap/nmap_aggressive.sh 192.168.1.10

# Nmap con scripts NSE sobre puertos concretos
./network_scanners/nmap/nmap_scripts.sh 192.168.1.10 80,443

# Masscan sobre un rango
./network_scanners/masscan/masscan_scan.sh 192.168.1.0/24 80,443,8080

# RustScan
./network_scanners/rustscan/rustscan_scan.sh 192.168.1.10

# Nikto
./web_scanners/nikto/nikto_scan.sh https://example.com

# Nuclei (escaneo completo y solo CVEs críticas)
./web_scanners/nuclei/nuclei_scan.sh https://example.com
./web_scanners/nuclei/nuclei_cves.sh https://example.com critical
```

## 📤 Resultados

Cada script escribe en `scans/<herramienta>/` según su propia variable `OUTPUT_DIR`.
Masscan y RustScan requieren `sudo`.

## 🔗 Ver también

- `USE.md` — comprobación de permisos y primera ejecución.
- `00_Config/scope.yaml` — todo escaneo debe estar dentro del alcance autorizado.
