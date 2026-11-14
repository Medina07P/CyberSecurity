# Entrega — puertos e historial automático de informes

Diseño/plan del2026-11-13; implementación y verificación final el2026-11-14.
Estado: cambios locales sin commit, integración ni push, en el worktree nativo
`/home/kali/.local/share/opencode/worktree/f6569d/reports-evidence-fixes`.
Se conserva la base anterior descrita en `INFORMES-EVIDENCIAS-2026-11-13.md`;
las rutas fijas de salida de aquel bloque quedan sustituidas por este historial.

## Qué cambia

- Masscan JSON y RustScan texto estructurado aportan puertos abiertos como
  observaciones info, no vulnerabilidades. Los registros mandan sobre nombres
  de archivo; IP/host, protocolo y puerto se validan. Sin DNS ni herramientas.
- Masscan exige array completo; JSON truncado/archivo vacío no se interpreta
  como escaneo limpio. RustScan admite `Open HOST:PORT` y `HOST -> [PORT,PORT]`;
  IPv6 de Open exige corchetes. Se permiten colores SGR, no otros controles.
- La cobertura declara **finalización y actualidad no acreditadas**: RustScan
  puede conservar salida anterior al fallar y Masscan puede dejar archivo parcial.
  Un hallazgo de otro host no hace evaluable el host seleccionado sin puertos.
- Puertos comunes se unen a Nmap preservando sus IDs, ficha de servicio/producto
  y evidencia de cada lector. TCP y UDP no se confunden; banners no generan CVEs.
- Cada generación reserva `generated/<slug>/runs/run-<UTC>-<uuid>/`. Para
  `--todos`, raíz `_todos`, sin presentar el host de sesión como alcance agregado.
- **`--salida DIR`/`REPORT_OUT_DIR=DIR` ahora son raíces:** la salida efectiva
  es `DIR/runs/<id>/`. No se sobrescriben ni migran documentos legacy, no hay
  modo de sobrescritura ni enlace latest. La concurrencia reserva directorios
  exclusivos y una colisión no autoriza reutilizar el destino.
- `run.json`600 inicia ESCRIBIENDO y cierra COMPLETADO/rc0 o NO_EVALUABLE/rc3
  solo tras escribir todos los documentos del tipo solicitado. `--json` devuelve
  run_id, salida real y archivos, incluido run.json. El gestor abre solo su HTML.
- Rerender crea otro run, actualiza fecha de generación y conserva la entrada;
  no relee fuentes ni cambia esa fecha en fecha de nueva adquisición.
- La fase11 comprueba recibo final y archivos regulares, además de presencia
  legacy sin seguir enlaces. No abre cuerpos ni verifica hashes/autenticidad.

## Uso y compatibilidad

Desde `CyberSecurity-Framework/`, sobre evidencias ya existentes:

```bash
bash 11_Reports/report_generator.sh ambos --objetivo example.invalid --json
python3 11_Reports/report_engine.py --objetivo example.invalid \
  --scans /trabajo/scans --salida /trabajo/informes --json
```

El recibo identifica `/trabajo/informes/runs/<id>/`; no buscar un archivo nuevo
en `/trabajo/informes/findings.json`. Un archivo antiguo ahí queda intacto.
Para re-renderizar, seleccionar el findings.json de un run existente y pasar
`--desde-json` con una raíz de salida; se creará otro run.

Guía: `CyberSecurity-Framework/11_Reports/USE.md`.
Diseño: `docs/superpowers/specs/2026-11-13-reportes-puertos-historial-design.md`.
Plan: `docs/superpowers/plans/2026-11-13-reportes-puertos-historial.md`.
Ledger y logs: `.superpowers/sdd/2026-11-13-reportes-puertos-historial/`.

## Verificación

Suite final dedicada:

`bash CyberSecurity-Framework/tests/run_reports_evidence.sh`

**175 tests / rc0 / GUARD OK**: 78 motor existente, 11 postexplotación,
53 contratos del bloque anterior, 2 guardas del runner, 11 lectores de puertos,
10 biblioteca de historial y 10 integración de historial. Allowlist de fuentes,
config/HOME/sesión sintéticos y PATH cerrado. Logs RED/GREEN por tarea y de las
correcciones de revisión conservados; el último estado está en `final-suite.log`.

Sintaxis:29 AST Python y6 Bash sin stderr; `git diff --check` rc0. Verificación
adicional: productores03, scope.yaml y targets.txt sin modificaciones en este
worktree. No se leyó ni copió la configuración local del checkout original.

Regresiones antiguas se ejecutan solo en archivo git+overlay de fuentes actuales
con configuración/HOME sintéticos. La primera ola pasó seis suites en
`/tmp/opencode/reports-history-regressions-6xx83s38/`, pero precede correcciones
de revisión; la ola definitiva, posterior a todas las correcciones de código,
está en `/tmp/opencode/reports-history-regressions-wby13xow/`:

| Suite | Resultado |
|---|---|
| run_reports.sh | rc0;78 tests Python y28 comprobaciones shell |
| run_scanners_menu.sh | rc0;27 tests |
| run_enumeration.sh | rc0;39 tests |
| run_evidence.sh | rc0;145 tests/GUARD OK |
| run_smoke.sh | rc0 |
| run_e2e.sh | rc0;11 comprobaciones |

`regressions-result.txt` del workspace registra esas rutas y códigos. No atribuir
la primera ola a la revisión final. Una comprobación adicional whole-file detectó
una línea con espacios heredados de HEAD en model.py: se dejó intacta; no hay
incidencias en diff ni en archivos nuevos.

## Revisión y límites

Revisión propia, sin subagentes según aprobación del usuario; no es revisión
independiente. Cuatro hallazgos importantes se reprodujeron y corrigieron:
controles convertidos en líneas RustScan, evaluación heredada de otro host,
IPv6 CLI/alcance agregado y presencia legacy siguiendo enlaces. Pruebas
`final-review-red.log`→`final-review-green.log`, más suite final175.

No se identificaron menores nuevos diferidos. Sin firmas ni cadena de custodia,
sin compatibilidad operacional universal de RustScan/Masscan, sin explorador
o comparación automática de históricos. La publicación es atómica por archivo
con marcador final, no transacción completa ni protección frente a escritor
hostil del mismo UID. Un error tardío conserva un run incompleto propio, sin
recibo stdout ni apertura automática; no se borra para disimular el fallo.

La única decisión adicional registrada fue usar snapshot de fuentes junto al
BASE de git para esta ejecución sin commits, preservando la base anterior:
coste, no existe un rango de commits exclusivo de esta entrega; revisar el diff
y snapshot del ledger. Las demás decisiones de formatos, rutas y permisos
proceden del diseño aprobado.

Persisten los cuatro fallos observados y timeout de `run_tests.sh` documentados
en la entrega anterior. No se relanzó ni se declara resuelto ese gate global;
no se declara toda la rama verde. No ejecutar el flujo99 como smoke test.

Conservar worktree y logs. Sin commit/merge/push automáticos; integración
requiere decisión expresa futura del usuario.
