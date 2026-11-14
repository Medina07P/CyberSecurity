# Flujo de generación de informes

1. **Seleccionar objetivo** → host explícito o sesión; nunca agregar otros objetivos sin `--todos`
2. **Generar desde lo existente** → motor Python lee fuentes soportadas de `scans/` y metadata/contexto de módulos anteriores, sin ejecutar hojas
3. **Reserva exclusiva** → `generated/<objetivo>/runs/<id>/`; informe técnico `informe_tecnico.{md,html}`
4. **Informe de cliente y cierre** → `informe_cliente.{md,html}` y `run.json` final del mismo run; stdout entrega rutas reales
5. **Revisar confianza y cobertura** → corregir el registro `findings.json` y re-renderizar con `--desde-json`; un registro editado no autentica evidencia
6. **Entregar al cliente** → revisar `informe_cliente.html` y sus límites; el paquete de evidencias es otra acción explícita de 10 y puede contener secretos

## Acceso rápido desde el gestor

- Tecla **R** en el menú principal → submenu de informe rápido
- Perfil de cliente/auditor se guarda en `11_Reports/.report_profile`
- El objetivo de la sesión se pasa automáticamente como `--objetivo`
- Solo se muestran/ofrecen los archivos del recibo de esta generación; se respetan las salidas personalizadas y el tipo elegido
- Sin fuentes evaluables, rc3 y documentos limitados; error rc1 no abre informes anteriores
- `--salida DIR` crea `DIR/runs/<id>/`; informes anteriores no se sobrescriben ni migran
- Rerender crea otro run; `--todos` usa raíz `_todos`; run ESCRIBIENDO no cuenta como publicado

La cobertura no transforma contexto OSINT, un archivo de reconocimiento o una
captura etiquetada como `finding` en vulnerabilidad confirmada. Véase [USE.md](USE.md).
Masscan/RustScan aportan observaciones de puertos: no prueban finalización ni
actualidad del escaneo; vacío o truncado no significa «sin puertos».

## Compatibilidad

El script `09_Automation/python/report_generator.py` es obsoleto y delega
en el motor. Mantener solo para automatizaciones antiguas que usen
`--input` / `--output`. Su salida también sigue el historial nuevo; automatizaciones
que esperaban documentos fijos deben adaptarse a `runs/<id>/`.
