# run_all_osint: del "✅ completado" en falso al contrato con dominio (2026-11-06)

## Síntoma

Desde el gestor, `01_OSINT` → `1. run_all_osint.sh` terminaba así:

```
Sin argumentos

  EJECUTANDO OSINT
▶️  Ejecutando: scripts/email_harvester.sh
Uso: ./email_harvester.sh <dominio>
Ejemplo: ./email_harvester.sh example.com
▶️  Ejecutando: scripts/metadata_extractor.sh
Uso: ./metadata_extractor.sh <archivo>
...
✅ OSINT completado
```

Los cinco hijos imprimían su `Uso:` y salían `1`, y el script acababa con
**`exit 0` y "✅ OSINT completado"**. Ninguna herramienta llegó a ejecutarse:
el fallo total se presentaba como éxito.

## Causa

`01_OSINT/run_all_osint.sh` era el único `run_all_*` sin contrato de
parámetros, y eso encadenaba tres defectos:

1. **Sin línea `Uso:`/`Ejemplo:`** → `params_mode` devolvía `none`, el gestor
   mostraba "Sin argumentos" y nunca preguntaba el dominio.
2. **El bucle llamaba a los hijos sin argumentos** (`bash "$script"`), así que
   todos se quedaban en su validación de argumentos y salían `1`.
3. **Ese `exit 1` se ignoraba y el `2>/dev/null` tapaba cualquier error**; el
   `echo "✅ OSINT completado"` era incondicional.

Dos hijos además no aceptan un dominio: `metadata_extractor.sh` trabaja sobre
un **archivo local** y `social_media_search.sh` sobre un **nombre de empresa**.

## Arreglo

- `Uso: ./run_all_osint.sh <dominio> [archivo]`, con `Ejemplo:` de un solo
  token a propósito: `params_example_values` solo usa el ejemplo si el número
  de tokens cuadra con los huecos, así que el hueco opcional *no* se rellena
  con un `documento.pdf` que quizá no exista.
- El dominio se pasa a `email_harvester.sh`, `osint_harvester.sh` y
  `subdomain_finder.sh`; a `social_media_search.sh` se le pasa el dominio sin
  la última etiqueta (el TLD) y **se anuncia el término usado**. Si el objetivo
  es una IP, ese paso se omite con un mensaje explícito en vez de buscar
  "192.168.1" en LinkedIn.
- `metadata_extractor.sh` solo se ejecuta si se da `<archivo>`, y un archivo
  inexistente corta con `exit 1` antes de lanzar nada.
- Cada hijo se lanza con `2>>osint_errores.log` (se añade, no se vacía: lleva
  cabecera con fecha y dominio). Un hijo que devuelve ≠0 se cuenta; al final,
  si hubo alguno, se imprime `⚠️ OSINT terminó con N de M pasos fallidos` y se
  sale `1`. El "✅ completado" solo aparece cuando los pasos salieron bien.
- El script se autolocaliza (`cd "$(dirname "${BASH_SOURCE[0]}")"`), así que
  `bash 01_OSINT/run_all_osint.sh example.com` desde `/tmp` invoca a los hijos
  correctos. Era uno de los diez `run_all_*` que asumían el `cwd`.
- `.gitignore`: `01_OSINT/*.log` (el log cita hosts y rutas reales).

## Evidencia

Tests añadidos en `tests/run_tests.sh` (`section "run_all_osint acepta dominio
(y archivo opcional)"`, 14 asserts) con hijos dobles en un árbol temporal:

```
ok   run_all_osint: declara sus huecos en Uso:
ok   run_all_osint: 2 huecos (dominio + archivo)
ok   run_all_osint: el archivo es opcional y FICHERO
ok   run_all_osint: descarta el ejemplo incompleto
ok   run_all_osint: funciona desde cualquier cwd
ok   run_all_osint: deriva el nombre de empresa para redes sociales
ok   run_all_osint: no ejecuta metadatos sin archivo
ok   run_all_osint: con archivo ejecuta metadatos
ok   run_all_osint: sale ≠0 si un hijo falla
ok   run_all_osint: no anuncia éxito si algo falló
ok   run_all_osint: guarda el stderr del hijo fallido
ok   run_all_osint: sigue con los demás hijos
ok   run_all_osint: sin dominio sale 1
ok   run_all_osint: archivo inexistente sale 1
```

Antes del arreglo esa sección daba 12 fallos (la salida era la del síntoma).

Suites completas tras el cambio:

| Suite | Resultado |
|---|---|
| `tests/run_tests.sh` | 344 pasan, 0 fallan (el recuento de "scripts con 2+ huecos" sube de 39 a 40) |
| `tests/run_smoke.sh` | 0 |
| `tests/run_e2e.sh` | 0 |

Y el gestor ya pregunta (stdout solo lleva el valor; la interfaz va a stderr):

```
➜ Dominio (dominio): ➜ Ruta de fichero (archivo):
```

## Lo que no se probó

No se lanzó contra un dominio real: eso ejecuta `theHarvester`, `whois`,
`dnsrecon` y `whatweb`, y queda fuera de esta corrección. Lo verificado es el
contrato, el paso de argumentos y el manejo de fallos, con dobles.
