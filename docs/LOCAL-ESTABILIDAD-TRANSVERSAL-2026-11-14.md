# Estabilidad transversal local — 2026-11-14

Bloque local del plan `docs/superpowers/plans/2026-11-14-cross-module-local.md`,
implementado sobre la base cerrada del bloque web (`cc79715`). Cubre seis tareas:
generación exclusiva de lanzadores, SMB/PSExec estables, Linpeas con fuente/sudo
explícitos, Labs con inicialización exclusiva, parser CIDR y consumidores/docs.

## Estado rectificado, 2026-11-15

**NO APROBADO para cierre.** La revisión final propia de `d89a371` encontró
defectos no cubiertos por los tests existentes. La anterior afirmación de
Tasks1–6 completas y revisión independiente aprobada por tarea queda retirada.
No hay informe final independiente; el usuario pidió completar esta revisión
personalmente. Informe detallado:
`.superpowers/sdd/2026-11-14-cross-module-local/final-integration-review.md`.

Pendientes bloqueantes: modos contradictorios Linpeas permiten ejecutar aun con
`--preview`/`--help`; rutas de salida Linpeas y ancestros Labs no se fijan mediante
descriptores; Labs elimina su README parcial ante error; faltan límites efectivos
equivalentes en descarga wget; ping pierde errores de salida y clasifica ciertos
errores de ejecución como inactividad. Faltan selección de raíz Labs en menú y
conciliación de guías. El plan separado de menores y cierre global sigue pendiente.

Esta revisión solo leyó fuentes y recibos como datos; no ejecutó suites, helpers,
probes ni herramientas reales, ni modificó producto para ocultar los hallazgos.

## Resultados históricos conservados (no aceptación final)

- Implementación local entregada; las revisiones y autorizaciones son las que
  constan individualmente en sus informes. No se extrapolan a combinaciones
  posteriores sin revisión. La revisión final no está aprobada.
- Casos transversales locales: 12/12 en verde (generación 2, SMB/PSExec 2,
  Linpeas 2, Labs 3, Recon 2, menús/coordinadores 1).
- Regresión aislada: `--suite` 179/0/0 (1 SKIP `pwsh` por ausencia del binario),
  `--cross-web` 7/0/0, `--cross-consent` 9/0/0, `--cross-local` 12/0/0.
- Unidades del aislador: 65/0/0; workers Landlock ABI 7 en los 12 casos locales.
- 11 permisos descartables locales + 1 caso puro sin permiso; inventario histórico
  de 25 casos intacto; 9 consentimiento + 5 web preservados.

## Cambios funcionales

- `00_Config/lib/consent/generate.py`: `emit_launcher` crea lanzadores nuevos
  fuera del framework, modo 0700, sin incrustar raíz/objetivo/credenciales/flags.
- `00_Config/lib/consent/stable_tools.py`: `run_smb`, `run_psexec`,
  `run_linpeas` con validación, argv sin eval, `--` para PSExec, fuente local
  seleccionada, sudo explícito, descarga solo URL fija con límites.
- `00_Config/lib/consent/stable_cli.py`: modos `--preview` (default),
  `--execute`, `--generate DESTINO`, `--help`.
- `06_PostExploitation/privilege_escalation/linpeas.sh`: convertido de
  auto-materializador a shim estable.
- `00_Config/lib/labs_runtime.py`: `initialize_lab` con creación exclusiva
  (O_EXCL/O_NOFOLLOW), modos 700/600, raíces ancladas por categoría.
- `00_Config/lib/recon_targets.py`: `parse_ping_targets` estricto; `ping_sweep.sh`
  valida antes de crear salidas y propaga errores de backend.
- Menús 04/06/13 y `run_all_post.sh`: consumidores adaptados a modos explícitos;
  run_all_post omite linpeas con motivo de selección requerida.

## Conservación

- No se borraron ni movieron datos generados, fixtures, recibos ni logs históricos.
- Las fuentes originales conservadas por hash/modo en el fixture; los 25 casos
  históricos intactos.
- Los resultados citados son sintéticos. No se ejecutaron nuevas operaciones
  durante esta rectificación. No se extrapola una afirmación de «ninguna red en
  toda la sesión»: el incidente Nmap histórico sigue documentado en `AGENTS.md`.
- Compatibilidad operacional, custodia legal y certificación kernel/hostil no
  se declaran.

## Límites residuales

- ABI 3 no cubre toda metadata/ioctl; sin certificado kernel/hostil, realtime
  ni cgroups por árbol.
- `stable` no documentado en `AGENTS.md` (pendiente de Task6 de documentación
  global).
- Oráculos de backend (impacket, curl/wget) modelan gramática observada, no
  todas las versiones.
- Windows/Docker y ramas/suites antiguas no verificadas.
- Sin auditoría/red/install/sudo/push/merge/cleanup global.
