# Revisión final propia — bloque local transversal

Fecha: 2026-11-15. Código examinado: `d89a371a110b2cbf944e42d36d54d6a0c03ec263`;
base local `cc79715`. Realizada personalmente por petición del usuario.
**Es revisión propia, no independiente. Especificación: NEEDS_CHANGES.
Calidad: NEEDS_CHANGES. Cierre local y global: NO APROBADOS.**

## Método y frontera

Lectura de fuentes, plan local, diseño §§8–14, plan de cierre y ledger; Git
solo lectura; JSON de recibos históricos mediante biblioteca estándar, sin
imports del repositorio. No suites/helpers/probes/backends nuevos, no lectura
de configuración/credenciales/notas/evidencia operacional, no red, sudo,
instalación, merge, push, migración ni eliminación. Esta revisión corrige prosa
y ledger, no altera producto ni fabrica RED/GREEN. No constituye auditoría
exhaustiva de cada hoja del framework.

## Hallazgos bloqueantes

### I1 — Linpeas: preview/help no son excluyentes

`CyberSecurity-Framework/00_Config/lib/consent/stable_cli.py:36–78`: al encontrar
`--preview` o `--help` en una lista mixta simplemente continúa; `execute` sigue
True y acaba llamando a `run_linpeas` cuando hay fuente y `--allow-sudo`.
Ejemplo derivado de fuente (NO ejecutado): `--binary FILE --execute --allow-sudo
--preview`. Contradice los modos exclusivos anunciados en líneas19–23 y el
diseño§8. Los tests verifican `--preview` aislado, no esta combinación.
Requiere rechazo de modos contradictorios y regresiones negativas con cero
despachos para preview/help mezclados con ejecución.

### I2 — Labs: comprobación parcial de ancestros y TOCTOU

`labs_runtime.py:59–74,108–116,123–148`: `_mkdir_nofollow` solo hace lstat de
cada ruta completa, no de todos sus ancestros; los componentes previos a la
raíz alternativa pueden ser enlaces. Aperturas por pathname vuelven a resolver
el árbol. O_NOFOLLOW en README no protege sus ancestros. El chequeo lstat de
README seguido de O_EXCL también trata cualquier FileExistsError posterior
como reuso, sin comprobar que el objeto aparecido sea regular. El test actual
cubre un enlace en el laboratorio, no un enlace anterior a la raíz.
Requiere recorrido por descriptores sin seguir enlaces y revalidación del objeto
en colisión; pruebas de ancestro enlazado y de colisión no regular.

### I3 — Labs: eliminación de parciales

`labs_runtime.py:138–146`: ante fallo de escritura llama a `os.unlink(readme)`.
Contradice preservación explícita de fuentes/fixtures/recibos y parciales del
diseño§12 y plan local. La ruta se vuelve a resolver al eliminar, por lo que
además podría haberse reemplazado. Requiere conservar el parcial y propagar el
fallo; prueba de escritura fallida y verificación de bytes/modo/identidad.

### I4 — Linpeas: árbol de salida adoptado y límites de descarga insuficientes

`stable_tools.py:195–211`: mkdir(exist_ok=True) seguido de chmod del padre
existente adopta un directorio previo o un enlace a él; no fija ancestros y
modifica modos existentes. `:231–245` no impone deadline paterno; wget usa
`--timeout` (no límite total de ejecución) y `--max-filesize` cuya compatibilidad
con el backend no se acreditó. No hay comprobación del tamaño final antes de
sudo en `:255–258`. El doble solo reconoce `-o/-O` y escribe su cuerpo: no
comprueba límites ni compatibilidad de esas opciones. Requiere salida nueva
fijada, preservación de modos previos y límites verificables para ambos canales.
No invocar wget/curl reales para investigarlo en este checkout.

### I5 — Ping: errores de IO y clasificación incompleta

`ping_sweep.sh:45,54,59–64`: no comprueba mkdir ni append; FOUND aumenta aunque
falle persistir el resultado. Solo rc2 se clasifica como error; rc126/127 o
terminación por señal se presentan como «Inactivo». `:25,54,72–74` acumula un
archivo diario y presenta su ruta sin delimitar aportes nuevos/históricos;
`:42` muestra el CIDR original, no la normalización de bits de host exigida.
Requiere regresiones de IO fallida, rc distintos de 0/1, y normalización visible.

### I6 — Integración/documentación y plan global incompletos

El menú Labs sigue anclando crear/listar/editar a SCRIPT_DIR, sin selección de
raíz alternativa en memoria ni paso de --root exigidos por Task4. La revisión
Task4 registrada inicialmente NO aprobó su gate; las correcciones posteriores
no tienen una aprobación final equivalente en el workspace. Tasks5/6 tampoco
tienen revisión propia individual documentada anterior al supuesto cierre.

El plan `docs/superpowers/plans/2026-11-14-cross-module-closure.md` es un bloque
separado de seis tareas, NO una repetición de Task6 local. Faltan
`automation/summary.py`, `tests/test_cross_closure.py`,
`tests/test_cross_documentation.py`, selector `--cross-closure`, helper terminal
y matriz `docs/CORRECCIONES-TRANSVERSALES-2026-11-14.md`. No existe evidencia de
conciliación final130hojas/217filas ni carreras sobre la combinación final.
No se puede declarar todo terminado a partir de12tests locales.

## Evidencia histórica reconsultada, no nueva ejecución

Raíz: `.superpowers/sdd/isolated-runtime-runs/automation-isolated-<ID>/evidence/`.
Los inside-result.json y resultados de selección se leyeron de nuevo:

| Selección | ID conservado | Resultado registrado |
|---|---|---|
| local |30a54372f3c142e2a3238411a0ec2470|PASS/rc0;12tests,0fallos,0errores,0SKIP|
| web |94ef564f8f944d508aa7b41f7f6503da|PASS/rc0;7tests,0fallos,0errores,0SKIP|
| consentimiento |297a42f955bf4310baea74b7105e3dfb|PASS/rc0;9tests,0fallos,0errores,0SKIP|
| suite09 |5aef567148544ef4a3fee3b60e89d9f7|PASS/rc0;179tests,0fallos,0errores,1SKIP|

Estos resultados no se invalidan ni se borran, pero sus oráculos no cubren I1–I6.
No se inventa atribución SHA a partir de un JSON que no la registra. Según el
historial conversacional, local se ejecutó con el cambio de modos aún sin commit,
luego incorporado en d2d7edf. No afirmar que todos los gates tuvieron revisión
independiente y autorización exacta previa: la conversación acredita omisiones.

## Invariantes comprobados estáticamente

- Generación conserva tres tipos y las rutas públicas; SMB/PSExec mantienen
  las posiciones e introducen --execute, backend argv y separador --.
- Labs/recon helpers existen e ingresaron en fuente allowlist y fixture.
- JSON local enumera12IDs/11grants; test_cross_local mantiene12métodos.
- El inventario NO es idéntico a cc79715: añade el grupo local; los grupos web
  y consentimiento se deben comparar por contenido, no afirmar diff vacío total.
- dangerous.txt contiene Linpeas. develop observado en1e6d0fe; HEAD detached.
  Eso acredita el estado local, no demuestra por sí solo ausencia histórica
  de toda escritura remota.

## Disposición

Validación estática de entrega en esta sesión: script independiente stdlib
AST/JSON/read-only Git rc0 (`STATIC DATA VALIDATION OK`): grupos previos iguales
a cc79715, local12/11,12métodos AST, manifiesto de ambos helpers, entrada sensible
y seis hallazgos presentes. `git diff --check` sin incidencias. Esto valida el
registro y sus inventarios, no reproduce los defectos ni sustituye regresiones.

Terminada esta revisión, NO la implementación de todos los planes. Se retira
la aprobación documental prematura de d89a371 y se dejan Tasks3–6 locales
abiertas a los hallazgos; avances y recibos conservados. Tasks1/2 mantienen
su evidencia histórica, sin certificar todas sus propiedades por esta revisión.

No lanzar nuevas pruebas para cerrar I1–I6 sin revisión de la selección/código
y gate correspondiente; no ampliar grants ni usar tools reales. La petición
«completa tú» cambia ejecutor, no elimina restricciones de seguridad. Hay que
resolver estos hallazgos, terminar el plan de menores/conciliación y obtener los
gates faltantes antes de aprobar. Sin compatibilidad operacional, Windows/Docker,
custodia legal, certificado kernel/hostil ni cierre Task9/global09.
