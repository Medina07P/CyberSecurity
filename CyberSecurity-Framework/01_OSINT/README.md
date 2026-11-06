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
# Toda la fase OSINT sobre un dominio (lo que ofrece el gestor)
./run_all_osint.sh example.com

# Igual, y además metadatos de un documento local que ya tengas
./run_all_osint.sh example.com documento.pdf

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
```

`run_all_osint.sh` lanza emails, WHOIS/DNS y subdominios con el dominio y
redes sociales con el nombre de empresa derivado del dominio (te muestra el
término usado). `metadata_extractor.sh` no se ejecuta salvo que le pases un
archivo, porque trabaja sobre documentos locales y no sobre dominios. Si un
paso falla, no se declara completado: sale con código 1 y deja el stderr del
hijo en `osint_errores.log`.
