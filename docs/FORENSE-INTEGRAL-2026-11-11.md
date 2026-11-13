# 08_Forensics — implementación integral y límites de entrega

Diseño aprobado el 2026-11-11; continuación el 2026-11-12. Tasks1–8 tienen gates
aprobados hasta `38196e0`; `0913b0e` integra diseño/plan. La revisión GLOBAL
encontró cuatro Important I1–I4, resueltos en `25912ef`. La re-review confirmó
esos fixes y detectó N1 pre-GO; el usuario autorizó su corrección adicional.
N1 quedó resuelto en `278ec1b` y aprobado por revisión independiente. Cierre de
implementación/revisión confirmado el 2026-11-13: controlador296tests/rc0 y
Bash/AST sin incidencias sobre `278ec1b`; implementador296unittest/296runner
rc0/GUARD OK. Ocho regresiones rc0 sobre `25912ef`, sin repetirlas por el último
diff acotado al helper y sus pruebas. No hay bloqueantes abiertos. Los dos
menores siguen diferidos y no se declara validación operacional ni rama verde.
La nota de pausa de `RETOMAR-FORENSE-2026-11-12.md` es histórica, no un mandato
de repetir Tasks1–3. No se ejecutó operación forense real ni se usaron datos reales.

## Síntomas, causas y correcciones

| Síntoma anterior / riesgo comprobado | Causa y corrección |
|---|---|
| Defaults sensibles al entrar/recorrer flujo | Fuentes implícitas, glob y adquisición histórica: selección explícita, permisos independientes y validación de producto nuevo exacto |
| Resultados fijos/éxito por existencia o eco | Runs exclusivos privados, pasos con rc real y cobertura; metadata estricta/sidecars/hash antes de presentar vigencia |
| Original expuesto a analizadores | Copias independientes y cotejo original/copia; bloqueo de dependientes por integridad |
| Cronología incorrecta de copia o timestamps | Metadata mtime original; offset ISO completo y precisión ns; año/zona no conocidos quedan unresolved |
| PCAP corrupto/errores parecían ausencia de tráfico | capinfos y productor completo antes de filtros, rc preservado, vacío válido separado de fallo |
| Memoria Linux tratada como Windows / perfiles inventados | Backend/familia/plugin detectados; v2 Windows con perfil, v3 Windows realmente offline con símbolos locales |
| Montaje original/replay y cleanup contradictorio | Metadata sin mount, copia explícita con opciones filesystem, identidad de vista separada del inode subyacente, cleanup verificable antes del cierre |
| Confusión hash del producto e integridad de soporte físico | Observación dev/ino/rdev/tamaño, ddrescue directo explícito con mapa nuevo, sin hash exhaustivo del origen dañado |
| Ayuda bloqueada sobrevivía cancelación | Preflight bajo supervisor común; límite10s exclusivamente ayuda de compatibilidad, sudo no interactivo cancelable |
| SIGINT al grupo permitía siguiente fuente | Coordinador sticky espera hoja/cleanup y bloquea nuevas fuentes/prompts, sin confundir fallos ordinarios independientes |
| Verificación manual sin contrato de salida | Task8 lector estricto de solo lectura, rc0/1/2 y rechazo seguro de contenedores corruptos |
| Runner podía ocultar fallo o mutación | Task8 descubrimiento forense, rc verdadero y guardas de inventario/hash/modo incluidos nuevos archivos, sin recorrer evidencia real |
| I1 integridad corrupta impedía cleanup propio | Cleanup tras reapear escritores independiente de confianza del contenido; ownership intacto, recibos explícitos `cleanup.json` ligados a inode/dev/UID sin reparar metadata ni relajar validador |
| I2 Scalpel leía rutas desde bytes de imagen | Imagen posicional para Scalpel; Foremost conserva -i. Stub estricto modela -i como lista y demuestra que no se lee un segundo archivo no elegido |
| I3 señal solo al PID coordinador no llegaba a hoja | Supervisor común/gate/pidfd entrega INT/TERM a hoja concreta y espera cleanup sin deadline; sticky bloquea hojas y prompts posteriores, rc1/130/143 no implica señal |
| I4 staging fallido sin identidad revivía ACTUAL anterior | Selector y visor comparten reconciliación conservadora: intento offline no atribuible bloquea vigencia incluso filtrando digest, sin unir identidades ni inventar copia usable |
| N1 cancelar worker inerte antes de GO bloqueaba wait | Retirar/cerrar gate antes de esperar y cosechar grupo propio no autorizado; post-GO conserva cancelación por pidfd y cleanup cooperativo sin deadline |

Los diez puntos originales y métodos permanecen en
[`README08`](../CyberSecurity-Framework/08_Forensics/README.md). CLI completa,
tokens, permisos, rutas, sistemas/backend y límites en
[`USE08`](../CyberSecurity-Framework/08_Forensics/USE.md). No nuevos parsers11,
atribución por IP ni retirada de capacidades por dependencia ausente.

## Contratos que no deben sobreinterpretarse

- Hojas0=completo solicitado,1=parcial/fallido/cancelado,2=uso/precondición antes
  de empezar. Pasos preservan rc backend; signal es cancelación observada por
  wrapper, no señal terminadora inferida. Sin pasos no hay éxito.
- Runs privados, directorios700/archivos600 desde creación; lectura/hash consume
  espacio/tiempo y puede cambiar atime. No garantiza detectar cambios transitorios.
- Raíces externas se registran con HMAC/recibos/identidad/UID y confinamiento;
  no autentican contra escritor malicioso mismo UID. Externos no están cubiertos
  por gitignore del proyecto. No mover ni migrar resultados históricos.
- Físico solo metadata/adquisición/recuperación explícitas: identidad observada
  no hash del soporte. Mount solo copia ext2ro, ext3/4ro,noload, XFSro,norecovery;
  offset/length explícitos para partición; no fallback inseguro. Cleanup propio
  registra rc/hash y cancelación espera sus recursos, no recursos ajenos.
- Adquisición Linux AVML/wrapper LiME preparado no garantiza RAM consistente:
  `completitud_memoria=no_verificada`; dd explícito <=1GiB siempre muestra PARCIAL.
  Volatility Windows v2/v3 no es analizador Linux genérico, sin símbolos en red.
- Supervisor requiere Bash/Python>=3.11/Linux pidfd/prctl; sin fallback inseguro.
  No hay timeout operacional nuevo;10s exclusivamente ayuda de compatibilidad.
  No cubre escape deliberado de sesión ni cleanup garantizado ante SIGKILL.
- Visor puede devolver0 mostrando FALLIDO porque consultó correctamente.
  Intento offline sin identidad bloquea conservadoramente ACTUAL de la selección;
  puede afectar otras identidades, sin atribuirles el fallo ni mezclarlas.
  Verificador devuelve0 solo completo coherente,1 inconsistente/parcial/fallido,
  2 incompleto/sin datos. No relee originales ni crea bytecode, incluso sin -B.
  Ninguno certifica ausencia de intrusión, integridad actual del origen ni legalidad.

## Evidencia y estado de revisión

Coordinación duradera (no datos de clientes):
`.superpowers/sdd/2026-11-11-forensics-integral/task-8-report.md`,
`task-8-logs/`, `progress.md` y reportes Tasks1–7. Allí se registran logs RED/GREEN,
comandos, rc explícitos, guardas y cotejo de fuentes comprometidas/probadas.
Task8 prueba verificador con Python normal sin -B, originales eliminados,
schema/versionbool/módulo/sidecars/rc/hash/confinamiento/permisos y contenedores
corruptos; runner con fixture representativa de fallo y mutación, no suite
recursiva completa anidada. La guarda detecta archivos nuevos sin seguir enlaces.

La ola global conserva RED→GREEN nuevos y comandos/resultados en
`.superpowers/sdd/2026-11-11-forensics-integral/final-fix-logs/` y estado/API en
`final-fix-report.md`. Estos registros no sustituyen los históricos perdidos.
El diario de cleanup tiene validación independiente explícita: no implica run
válido ni certifica integridad de copias/artefactos de análisis corruptos.

Verificación exigida para entrega: runner y unittest forenses completos; Bash-n de
todo08/bibliotecas/gestor con stderr vacío, AST/LF; reports, smoke, e2e,
postexploitation, wireless_maintenance, config_menu, scanners_menu, enumeration
en copia de solo fuentes/config sintética,900s por suite, logs íntegros/rc.
No usar un GREEN de commit prefijo para acreditar fixes posteriores.

Todo usa fuentes/HOME/PATH/config/evidencia sintéticos en `/tmp/opencode` y
backends/sudo/journal/mount/adquisición/install stubs cerrados, sin fallback.
Las regresiones antiguas se aíslan; no se ejecuta `run_tests` sobre checkout ni
se debilita su rojo heredado: cierre06 374 pasan/11 fallan, SSTI intermitente sin
causa determinada. No declarar toda la rama verde.

Menores DEFERRED tras triage global: Task5 M1 logs históricos RED/GREEN perdidos
por reinicio (NO recreados como históricos); Task7 M1 seis avisos esperados de
roots en fixture. No entran en esta ola ni se pulen fuera de alcance.
La evidencia de stubs no acredita hardware, instalación, adquisición, montaje,
recuperación ni compatibilidad operacional real. No hay cadena de custodia legal
validada ni autorización de push. Scope y tres pendientes06 permanecen ajenos.
