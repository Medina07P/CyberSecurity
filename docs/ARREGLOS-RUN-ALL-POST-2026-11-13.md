# Correcciones acotadas del coordinador pendiente de 06

El usuario pidió corregir los defectos diagnosticados en el parcial existente.
No es una implementación del plan integral de 06 ni validación operacional.
El parcial anterior de run_all se conserva en
`/tmp/opencode/post-pending-preservation/run_all_post.before.sh`.

## Correcciones

- Capturar rc después de Bash sin negación: antes `if ! ...; rc=$?` obtenía0
  en la rama de error. Cada hoja deja ahora su rc real en el log de ejecución.
- No truncar `errores.log` anterior: cada invocación crea un subdirectorio
  exclusivo `scans/postexploitation/run_all_XXXXXXXX/`, privado700, log600.
- Fallar antes de ejecutar hojas si no se puede preparar el log, sin fallback
  silencioso al árbol de fuentes.
- `Uso:` declara TARGET obligatorio; falta, argumentos extra y valores con
  espacios/barras u opción inicial se rechazan antes de efectos.
- Exportar `POSTEXPLOIT_TARGET` sin modificar los posicionales históricos de las
  hojas. Es contexto declarado, NO ejecuta consultas remotamente ni atribuye
  evidencia automáticamente: las hojas actuales siguen siendo locales.

No se eliminaron ni ejecutaron capacidades. Los directorios añadidos previamente
en logs_cleaner y port_forward no se usan después: se dejaron intactos, no se
inventaron productos para justificar esas variables. scope.yaml permanece intacto.

## Pruebas

Nuevo test: `CyberSecurity-Framework/tests/test_post_run_all_pending.py`.
Ejecutar con `python3 -B -m unittest discover -s CyberSecurity-Framework/tests
-p test_post_run_all_pending.py -v`. Copia SOLO el coordinador a un árbol
sintético y sustituye TODAS las hojas por fixtures inocuas; PATH cerrado,
sin sudo, SSH, lectura de credenciales/logs del host ni post-explotación real.

RED:8 métodos/8 fallos contando subcasos. GREEN:8 métodos/rc0. Logs:
`/tmp/opencode/post-pending-red.log` y `post-pending-green.log`.

Regresión en copia limpia de HEAD con solo script/test nuevos superpuestos:
`/tmp/opencode/forensics-verify-u3y_uzjz/`. Resultados rc0: nueva suite8,
postexploitation84, reports78Python+28shell, smoke0fallos, e2e11. Logs completos
y `pending-results.json` en esa copia. Bash-n con stderr vacío, AST/LF y
diff-check correctos; fuentes probadas=checkout2/2, guardas scope y dos hojas
ajenas3/3 intactas. No se reejecutó run_tests heredada ni se declara rama verde.

Cambios sin commit/push: se mantiene la instrucción vigente de conservar los
pendientes fuera de commits. Esto no los convierte en parte del cierre de 08.
