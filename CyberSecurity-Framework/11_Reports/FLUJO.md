# Flujo de generación de informes

1. **Recopilar evidencia** → `10_Evidence/` y resultados en `<repo>/scans/`
2. **Generar informes** → motor Python (`report_engine.py`) lee `scans/`
3. **Informe técnico** → `generated/<objetivo>/informe_tecnico.{md,html}`
4. **Informe de cliente** → `generated/<objetivo>/informe_cliente.{md,html}`
5. **Revisar y corregir** → editar los .md generados si es necesario
6. **Entregar al cliente** → `informe_cliente.html` (sin paths internos ni payloads)

## Acceso rápido desde el gestor

- Tecla **R** en el menú principal → submenu de informe rápido
- Perfil de cliente/auditor se guarda en `11_Reports/.report_profile`
- El objetivo de la sesión se pasa automáticamente como `--objetivo`

## Compatibilidad

El script `09_Automation/python/report_generator.py` es obsoleto y delega
en el motor. Mantener solo para automatizaciones antiguas que usen
`--input` / `--output`.
