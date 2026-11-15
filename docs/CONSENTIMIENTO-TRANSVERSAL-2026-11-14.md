# Consentimiento transversal — cierre acotado

Implementación y revisión independiente sobre `204e89e` del plan
`docs/superpowers/plans/2026-11-14-cross-module-consent.md`.

- Cleanup: preview/ayuda inertes; aplicación con consentimiento LOCAL explícito,
  credenciales actuales sin sudo automático, destinos fijados, rechazo de enlaces,
  resultados parciales veraces y snapshot privado exclusivo. No borra memoria del
  shell padre ni adopta el antiguo `/tmp/last_access.txt`.
- Burp: apertura GUI, consulta pasiva, GET explícitamente autorizado y parada de
  instancia propia acreditada separados. curl desactiva configuración automática;
  el gestor no muestra path/query, pero conserva la URL original al despachar.
- Menús, guías e inventario alineados; coordinadores no adquieren acciones nuevas.
  Rutas públicas y capacidades originales conservadas con gates explícitos.

## Evidencia fresca del controlador

Comandos separados, autorizados después de revisión estática independiente:

`python3 -I -B CyberSecurity-Framework/tests/automation_sandbox_launch.py --cross-consent`

rc0:65 pruebas del aislador y9 casos nuevos,0fallos,0errores,0omitidos.
Nueve workers con permisos exactos y Landlock ABI7 observado.
Recibos: `/tmp/opencode/automation-isolated-a0eafe7f552e4932af7862e53c2924fe/evidence/`.

Mismo launcher con `--suite`:rc0,65 pruebas del aislador y179 de integración,
0fallos,0errores,1SKIP explícito por ausencia de pwsh.
Recibos: `/tmp/opencode/automation-isolated-d3672bd4fa174a0f98a1a0eacee12ae9/evidence/`.

Pruebas solo en copias allowlist y scratch nuevos, configuración/HOME/sesión
sintéticos y dobles obligatorios de red/GUI/sudo/backends. RED históricos,
fuentes, fixtures finales, parciales y logs se conservan. El primer intento
ENOSPC no ejecutó tests; su ruta parcial desapareció externamente, sin acción
de borrado de este controlador. No se reconstruyen recibos históricos ausentes.

Revisión final: `.superpowers/sdd/2026-11-14-cross-module-consent/final-evidence-review.md`.
Decisiones/gates completos: `progress.md` del mismo directorio.

## Decisiones y límites

Se difirió ejecución hasta revisión de cada combinación; la ausencia de un
controlador deniega permisos, nunca los concede. Se evitaron copias innecesarias
de hojas de coordinadores sin relajar protección de datos. Se corrigieron los
menores además de los importantes; no se amplió el inventario histórico25.
El único baseline operacional conciliado es el del gestor modificado, con
procedencia exacta. Sin sudo automático para evitar una reapertura privilegiada
por pathname; esto cambia la comodidad anterior, no promete compatibilidad.

La lectura de estado/puerto o un HTTP no certifican captura/propiedad. Sin garantía
de control de daemons/descendientes, host/kernel hostil, realtime/cgroups por árbol,
Windows/Docker, custodia legal ni operación real de herramientas. La URL sigue
visible en argv a observadores locales. ABI3 no media toda metadata/ioctl.

Este cierre no termina Task9/global09, toda la rama ni los planes web/local/menores.
Sin merge/push, instalación, auditoría o limpieza real; workspace y artefactos
preservados. Los siguientes bloques requieren sus propios gates y resultados.
