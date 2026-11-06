# El objetivo de sesión se registra solo en scope.yaml y targets.txt (2026-11-06)

## Lo que pasaba

El objetivo se fijaba en `00_Config/.session` (menú `T`) y la autorización se declaraba a
mano en `00_Config/scope.yaml`, que **ningún script escribía**. Antes de cada trabajo había
que acordarse de editar el YAML; si no, el gestor avisaba de "fuera de alcance" sobre el
propio objetivo que acababas de teclear, y `targets.txt` no se enteraba.

## Lo que hace ahora

`session_set_target` (el único punto por el que pasa un objetivo: menú `T` y tests) escribe
en tres sitios:

| Fichero | Qué se escribe |
|---|---|
| `00_Config/.session` | el objetivo, como antes |
| `00_Config/scope.yaml` | IP en `targets.ips`; dominio **y** `*.dominio` en `targets.domains` |
| `00_Config/targets.txt` | `<host>|—|—|Registrado al fijar el objetivo|B` bajo cabecera fechada |

Salida real al fijar un objetivo desde el gestor (copia del framework, para no tocar el de
verdad):

```
Nuevo objetivo (IP o dominio):    ➕ scope.yaml: nuevo-dominio.com
   ➕ scope.yaml: *.nuevo-dominio.com
   ➕ targets.txt: nuevo-dominio.com
✅ Objetivo guardado: nuevo-dominio.com
```

Y el `scope.yaml` resultante sigue parseando, con los comentarios y el resto del fichero
intactos:

```
targets:
  ips:
    - "192.168.1.0/24"
    - "10.10.10.0/24"
  domains:
    - "example.com"
    - "*.example.com"
    - "nuevo-dominio.com"
    - "*.nuevo-dominio.com"
  excluded:
    - "192.168.1.1"
```

## Reglas que respeta

- **Idempotente**: se compara sin comillas, sin comentario, sin `\r` y sin distinguir
  mayúsculas. Repetir el objetivo no añade nada ni crea `.bak`.
- **No inventa**: si el `scope.yaml` no tiene la clave, no se escribe y se avisa; lo mismo si
  el YAML resultante no parsea, en cuyo caso se descarta el temporal y el original queda intacto (`.bak` guarda el estado previo al último cambio bueno).
- **Un fallo no cancela la sesión**: el aviso va a stderr y `.session` ya está escrito.
- **Puerto y protocolo desconocidos** se escriben como `—`, el marcador que
  `00_Config/scripts/parse_targets.py` traduce a `null`. Inventar `443` sería mentir sobre el
  servicio.
- **Dos entradas por dominio** (`dominio` y `*.dominio`) porque `scope_allows` compara por
  sufijo con comodín; de paso se arregló que una entrada sin comodín no coincidiera nunca.

## El precio, dicho claro

`scope_allows` ya no puede avisar de un objetivo que tú mismo has fijado: el gestor lo
registra antes de que nadie compruebe nada. La comprobación de alcance pasa a ser un
**registro** de lo usado, no un control. La barrera es el documento de
`authorization.document`. Es la decisión que se tomó (ver
`docs/superpowers/specs/2026-11-06-auto-scope-design.md`).

## Evidencia

`tests/run_tests.sh` pasó de 344 a **386 asserts**, con tres secciones nuevas:

- «El objetivo se registra en scope.yaml»: dominio pelado + comodín, IP a `ips`, idempotencia,
  mayúsculas, `.bak`, YAML válido, comentarios preservados, valor inválido, fichero sin la
  clave (código 2 y fichero intacto), CRLF, clave `domains:` duplicada fuera de `targets:`.
- «El objetivo se registra en targets.txt»: formato de cinco campos con `—`, cabecera fechada,
  idempotencia, fichero sin salto final, fichero inexistente, `parse_targets.py` lo entiende.
- «session_set_target registra en los dos ficheros»: la integración.

Y dos guardas que se ganaron el sueldo:

- `md5sum` del `scope.yaml` y del `targets.txt` reales antes y después de la suite. La primera
  pasada **falló** porque el test de zsh (`unset SESSION_FILE SESSION_TARGETS_FILE`) dejaba
  sin aislar el `targets.txt` real y el gestor le añadió `prueba.example`. Se corrigió el test
  (ahora solo hace `unset` de `SESSION_FILE`, que es lo que ese test mide) y el fichero se
  restauró. Sin la guarda, la suite habría contaminado la lista de objetivos del operador.
- `tests/run_e2e.sh` aísla `SESSION_SCOPE_FILE` y `SESSION_TARGETS_FILE` en un directorio
  temporal antes de llamar a `session_set_target`.

Suites tras el cambio:

| Suite | Resultado |
|---|---|
| `tests/run_tests.sh` | 386 pasan, 0 fallan |
| `tests/run_e2e.sh` | 11 pasan, 0 fallan |
| `tests/run_smoke.sh` | 0 fallos |

## Deshacerlo

No hay comando de borrado: se quita a mano la línea de `targets.txt` y las entradas de
`scope.yaml` (o se restaura `scope.yaml.bak`, que es el estado previo al último cambio bueno).
Documentado en `docs/MANUAL-GESTOR.md`.

## Lo que encontró la revisión y se corrigió

La revisión independiente del branch encontró un fallo crítico y cuatro importantes, ya
cerrados con test RED→GREEN:

1. **La escritura asumía la plantilla de dos espacios.** Con una clave `domains:` anidada
   (p. ej. `targets.excluded.domains`) o con sangría de cuatro espacios, la inserción caía en
   el bloque equivocado y el YAML dejaba de parsear: el gestor avisaba «código 2» para siempre
   en ese fichero. Ahora la clave y la sangría se localizan por nivel (se toma la del primer
   hijo de `targets:` y la de la última entrada) y hay fixtures para ambos casos.
2. **`scope_allows` leía dominios de todo el fichero**, así que una regla en `excluded:` o el
   email de contacto autorizaban. Ahora lee solo `targets.domains`. Además, «había reglas y
   ninguna encaja» devuelve 1 (fuera de alcance) y no 2.
3. **`mv -f` reseteaba los permisos** del `scope.yaml` a los del `umask`. Ahora se copian con
   `chmod --reference` antes de sustituir (test con `640`).
4. **PyYAML ausente se confundía con YAML roto.** Se sondea `import yaml` por separado: si
   falta, se escribe y se avisa; solo un `safe_load` fallido aborta.
5. **La suite filtraba `SESSION_SCOPE_FILE`** al test que aísla `SESSION_CONFIG_DIR`, y ese
   assert pasaba por el motivo equivocado. Corregido en la llamada de `http_inject.sh`.

Diferidos (menores, en el ledger): finales de línea mixtos en ficheros CRLF, cabecera «una por
día» en lugar de «una por tanda», duplicado si la línea existente lleva espacios delante, y la
marca `# auto: gestor` que el spec prometía y el plan no escribió.
