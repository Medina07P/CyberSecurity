# Integración local de las correcciones globales — 2026-11-14

## Autorización y operación

El usuario pidió: «Haz el merge a develop para cerrar las correcciones».
Esta petición posterior autoriza los commits necesarios y el merge local;
las prohibiciones de commit/merge de las notas de implementación son históricas.
No autoriza push, instalaciones, pruebas con datos reales ni iniciar otro módulo.

Se creó `fix/global-tests-2026-11-14` desde el worktree nativo, antes en HEAD
desacoplado. Commit de correcciones: `87d7ce8`.
`develop` avanzó por **fast-forward de `8435c05` a `87d7ce8`**.
No hubo pull, acceso al remoto, rebase, stash, reset ni push.

## Contenido integrado

Siete fuentes de producto/pruebas y tres documentos: baseline SSTI, contratos
del parser, rutas/layout SQLi/HTTP/sqlmap, ciclo de vida/cleanup de fixtures,
recibo PID/puerto posterior al bind, fixture de sesión legacy de informes y
regresiones deterministas. Detalle en `PRUEBAS-GLOBALES-2026-11-14.md`.

La revisión independiente identificó I1 (readiness de listener ajeno), corregido
en un pase RED→GREEN con verificación integrada. No se atribuye una segunda
revisión al revisor. No hay hallazgos importantes pendientes ni menores diferidos.

## Verificación premerge

Copia sintética `/tmp/opencode/global-verify-7asegd_h`, con fuentes de staging
comparadas por SHA-256 con los siete hashes del overlay:

- Global:520/0, rc0,131.482s.
- Runtime HTTP:7/7, rc0.
- SSTI:5 métodos/7casos, rc0.
- Informes:29shell/78Python, rc0.
- 4Bash con rc0/stderr vacío,3AST y diffcheckOK.

Regresión integral previa de nueve ejecuciones rc0:
`/tmp/opencode/global-verify-hbt7vqh9`; incluye e2e, smoke, enumeration,
scanners_menu y exploitation. No confundirla con verificación posmerge.

## Verificación posmerge

Desde develop en `87d7ce8`, mediante copia sintética del commit integrado:
`/tmp/opencode/global-verify-vwf6h2e1`.

- Global: **520 pasan / 0 fallan**, rc0,129.343s.
- Runtime HTTP: **7/7**, rc0,1.466s.
- SSTI: **5 métodos/7casos**, rc0,15.207s.
- Informes: **29shell/78Python**, rc0,2.968s.

Los siete hashes de `overlay.json` coinciden tanto con el commit integrado como
con las fuentes actuales de develop. Los4Bash pasan sintaxis con stderr vacío;
3AST Python correctos, diffcheckOK y hash/modo de configuración local intactos.
Guardas y merge registrados en `/tmp/opencode/merge-global-tests-m09ojhpn/`.

La integración local queda cerrada. El commit posterior de cierre modifica solo
este documento y el enlace de estado de `PRUEBAS-GLOBALES-2026-11-14.md`, no el
código examinado. AGENTS y la nota de pausa siguen como notas locales preservadas.

## Preservación y límites

Evidencia de integración: `/tmp/opencode/merge-global-tests-m09ojhpn/`.
AGENTS local y la nota de reanudación se preservaron sin incluirlos en el commit.
Los plan/spec no versionados del checkout original se conservaron primero en
`original-local-notes/` y se movieron a `moved-original-notes/` antes del merge,
para no sobrescribirlos con sus versiones ahora versionadas. El plan original
no incluía los dos ajustes de revisión/regresión que añade la versión integrada.

scope.yaml/targets.txt locales quedan fuera de los commits; se comparan SHA-256
y modo antes/después sin publicar contenido. No se copian a fixtures.
Se conservan rama, worktree y logs. No se elimina ni limpia otro workspace.

Las pruebas se ejecutan con HOME/config/sesión sintéticos, PATH allowlist sin
sqlmap real ni escáneres, namespaces de red/PID y solo loopback. Nunca se lanza
run_tests directamente en el checkout con datos. El caso opcional de sqlmap real
se omite; otras suites de la rama no se extrapolan de este resultado.
No certifica compatibilidad operacional, auditorías reales ni custodia legal.
