# 📡 01_OSINT - Recopilación de Información

Este directorio contiene herramientas y datos para la fase de OSINT (Open Source Intelligence).

## 📁 Estructura

| Directorio | Descripción |
|-----------|-------------|
| `domains/` | Información de dominios (whois, histórico) |
| `subdomains/` | Subdominios encontrados |
| `emails/` | Emails identificados + filtraciones |
| `social_media/` | Perfiles en redes sociales |
| `metadata/` | Metadatos de documentos e imágenes |
| `scripts/` | Scripts de automatización OSINT |

## 🚀 Uso Rápido

```bash
# Recopilar todo de un dominio
./scripts/osint_harvester.sh example.com

# Buscar emails
./scripts/email_harvester.sh example.com

# Encontrar subdominios
./scripts/subdomain_finder.sh example.com

# Buscar en redes sociales
./scripts/social_media_search.sh "Nombre Empresa"

# Extraer metadatos
./scripts/metadata_extractor.sh documento.pdf