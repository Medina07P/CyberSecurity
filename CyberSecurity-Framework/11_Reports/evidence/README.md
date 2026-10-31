# Evidencias Empaquetadas

Este directorio contiene los paquetes de evidencias generados durante la auditoría.

## Archivos

- `evidence_YYYYMMDD.tar.gz` - Paquete de evidencias comprimido

## Crear paquete

```bash
cd ../10_Evidence
./evidence_manager.sh --package audit_$(date +%Y%m%d)