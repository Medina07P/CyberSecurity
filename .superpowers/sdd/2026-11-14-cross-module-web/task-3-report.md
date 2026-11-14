# WEB Task3 — entrega inicial estrictamente estática

Estado: **IMPLEMENTACIÓN PROPUESTA / NOT RUN / pendiente revisión independiente y autorización exacta del controlador**. No cierre Task3, Task4,09 ni global.

## Autoridad y procedencia

- Worktree enlazado: `/home/kali/.local/share/opencode/worktree/f6569d/automation-integral-20261113`; HEAD inicial limpio `65f506d`.
- Contratos leídos: `task-3-brief.md`, introducción/Global Constraints/Task3 de `task-1-context.md`, diseño vinculante `docs/superpowers/specs/2026-11-14-cross-module-corrections-design.md` §7/12–14, instrucciones AGENTS y contexto histórico de cleanup.
- Tasks1–2 aceptadas según controlador; no se modificaron compositor, biblioteca compartida ni login/manual. WM1 manual queda expresamente pendiente de Task4.
- RED **del controlador**, no ejecución de este implementador: `/tmp/opencode/automation-isolated-3bf6247d45e542b3879e6033b16b42b9/evidence/`, sobre `65f506d`:65 unidades sandbox PASS;7 casos,7 fallos,0 errores. `cross-web.json` confirma el resumen de casos. Leídos como datos los stderr de casos5/6 antes de implementar; stdout de ambos vacío.
- Caso5:5 fallos; puertos443/8443/8080 y Host sin puerto aceptaban falta de esquema; Host sin puerto+EOF invocaba GET HTTPS antes de cancelar. El recibo crudo del log muestra `https://example.test/` fuera del contador.
- Caso6:2 fallos;403 estable rápido0.010s/lento2.000s enviaba12 solicitudes y devolvía SIN FRENO/rc0. Resto de casos PASS según el controlador; no constituyen GREEN del nuevo SHA.

## Cambios e interfaces

Commit de implementación: `2ffb8dd` (`fix(web): select rate scheme locally and stop unsignalled 403`). Este informe se incorpora en commit documental posterior.

1. `05_Exploitation/web/rate_limit_probe.sh`: elimina el curl de autodetección y la inferencia TLS por puerto. Override `RATE_LIMIT_ESQUEMA` presente debe ser exactamente `http`/`https` (vacío también inválido); sin override solo sirve esquema de target absoluto HTTP(S) cuya autoridad coincide exactamente con Host. Normalización solo en memoria; target relativo debe empezar por `/`, no `//`, y no tener fragmento. Sin evidencia local, rc1 y cero transporte.
2. Después de elegir campo, `hr_request_pair ubicación nombre wrong-1` valida identidad/ambigüedad antes de consentimiento y de envíos. Cada intento compone desde HR_TARGET/HR_BODY originales y extrae target/cuerpo comprobando todos los rc; centinela conserva saltos finales del cuerpo. No se envían pares parciales. Sustitución única conserva codificación y valores ajenos mediante Task1, sin alterar los helpers legacy.
3. `rl_freno` permanece intacta y se evalúa primero:429/503, Retry-After literal o cuota0 conservan prioridad.403 sin señal tiene estado propio `PROHIBIDO_EN`, causa `403_sin_senal`, columna `403 SIN SEÑAL DE FRENO`, corte inmediato y NO_DETERMINADO/rc1, antes del posible retardo. No se finge cambio de código; informe explica la denegación ambigua.
4. Solo se amplían los dos métodos rate ya registrados en `tests/test_cross_web.py`; ningún ID, grant, fuente, runtime o política nuevos. Oráculos existentes de HTTP sobre443/8443, HTTPS sobre8080, rc de rangos inválidos, cero invocaciones antes del permiso y tabla literal de veredictos permanecen intactos.
5. Nuevos subcasos estáticos: captura absoluta/override contradictorio; ambigüedad form/query/JSON; mismatch Host/target, target `//`, override vacío; composición real en query/form/JSON con bytes ajenos y número JSON diminuto conservados; contador crudo igual a envíos;403 después de diez401 ya lentos no se convierte en freno;401→403 con Retry-After sí frena. Las expectativas son literales e independientes del compositor, sin funciones de negocio no-op.

## Preservación de capacidades y límites

| Contrato | Antes → propuesta |
|---|---|
| Petición capturada, método, sesión/cookies | Conservados; se cambia exclusivamente password seleccionado |
| Candidatos y volumen | `wrong-1…wrong-N`, default20/tope200, sin candidatos ni paralelismo nuevos |
| Permiso propio | RATE_LIMIT_SI=1 o confirmación TTY; cancelación/EOF sin transporte; no permiso heredado/global |
| Esquema | Inferencia/GET previo retirados por contrato; selección explícita o captura inequívoca local |
| Señales explícitas | Prioridad y Retry-After literal intactos, sin dormir/reinterpretar ni reintentar |
| Retardo401 | Medianas5+5, mínimo10, >2× y >100ms intactos |
| Otros códigos |000/2xx/3xx/cambio de código sin generalizaciones nuevas |
| TSV/contadores | Una fila por llamada real de login; eliminado GET oculto |
| Artefactos | Rutas y directorios únicos por ejecución intactos; pruebas de preservación existentes sin debilitar |

No se ejecutó producto, helper, import del repo, curl doble, launcher, test, probe, backend, red, sudo, GUI, descarga ni borrado. No se leyeron datos/configuración/evidencias operacionales ni se tocaron fixtures, informes o logs antiguos. Solo fuentes versionadas y recibos sintéticos expresamente indicados. No merge/push/reset/cleanup.

## Cierre estático exacto

Comandos de verificación tras el último cambio de fuentes (todos rc0):

```text
bash -n CyberSecurity-Framework/05_Exploitation/web/rate_limit_probe.sh 2>&1
  stdout/stderr combinado: vacío (ningún aviso de heredoc).

python3 -I -B -c 'import ast, pathlib; p = pathlib.Path("CyberSecurity-Framework/tests/test_cross_web.py"); ast.parse(p.read_text(), filename=str(p)); print("AST OK:", p)'
  AST OK: CyberSecurity-Framework/tests/test_cross_web.py

git diff --check
  salida: vacía.

git diff --stat
  rate_limit_probe.sh:102 líneas de diff; test_cross_web.py:65 añadidas.
  2 files changed,117 insertions(+),50 deletions(-).
```

Self-review: diff completo revisado; único curl de producto queda dentro de `rl_peticion`, llamada después del gate propio. APIs de composición y fuentes ya están en WEB_SOURCE_FILES/manifest; no es necesario ampliar mapas ni runtime. Casos nuevos permanecen dentro de los dos IDs rate/grants existentes. No revisión independiente propia ni afirmación de aceptación.

`git hash-object` (Git blob IDs, no hashes de evidencia):

| Fuente | Blob |
|---|---|
| rate_limit_probe.sh | `649b02f9613d2ff014419fa21b6a65f6fefd8965` |
| tests/test_cross_web.py | `c8c655df9149e9edc940cc62458617f6502df760` |
| lib/http_fields.py (intacto) | `075266fc89c7dbef1bf3b29ecb6b1aa3cdac227c` |
| lib/http_request.bash (intacto) | `4d908fc41782364338e6f34bd68230f4d1eaf4a6` |
| tests/cross_module_fixture.py (intacto) | `c810227c7ca8449c48f6638f4abaacf780043972` |
| tests/automation_sandbox_sources.json (intacto) | `b691ef408327c54a21993fc6efefa024ef8e0f1e` |

## Pendientes y preocupaciones

- **Todos los tests nuevos y GREEN del conjunto: NOT RUN.** El RED citado precede a estos cambios; los subcasos añadidos no tienen RED/GREEN propio observado. Requieren revisión independiente de este SHA y autorización exacta del controlador antes de cualquier ejecución.
- Composición incorpora el presupuesto1MiB existente de Task1 a esta hoja; requiere Python también para form/query, sin fallback a sustitución ambigua. Si falla composición/extracción se retorna1 sin enviar ese intento; no se inventa respuesta ni fila TSV. Fallo posterior a salidas puede dejar run parcial conservado, no resultado válido.
- La coincidencia de autoridad absoluta con Host es deliberadamente estricta (no se infiere equivalencia por puertos/defaults). No ampliar formatos ni inferirTLS para hacer pasar capturas ambiguas.
- Encabezados, temporales propios, sobrescritura histórica de resumen.txt/TSV y demás operaciones heredadas no se rediseñaron; no se promete preservación universal fuera del contrato existente de runs separados.
- Task4 conserva documentación pública/migración, regresiones heredadas equivalentes, WM1 y revisión final del bloque. No se ejecutan run_tests/run_exploitation ni selecciones amplias por esta entrega.
- No compatibilidad operacional/Windows/Docker, auditoría real, custodia legal ni rama completa verde acreditadas.
