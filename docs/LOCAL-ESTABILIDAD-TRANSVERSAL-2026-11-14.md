# Estabilidad transversal local — 2026-11-14

Bloque local del plan `docs/superpowers/plans/2026-11-14-cross-module-local.md`,
implementado sobre la base cerrada del bloque web (`cc79715`). Cubre seis tareas:
generación exclusiva de lanzadores, SMB/PSExec estables, Linpeas con fuente/sudo
explícitos, Labs con inicialización exclusiva, parser CIDR y consumidores/docs.

## Alcance y resultados

- Tareas 1–6 completadas con revisión estática independiente por tarea y gates
  de runtime autorizados por SHA.
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
- Ninguna auditoría real, instalación, sudo, red, Docker, merge ni push.
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
