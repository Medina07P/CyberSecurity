# Diseño — Claves de API en el gestor (enfoque A: registro único y materialización)

- **Fecha:** 2026-11-06
- **Estado:** aprobado e implementado (2026-11-06)
- **Origen:** pendiente nº 1 del handoff. Hoy ninguna herramienta pide su clave y el fallo es
  mudo: `email_harvester.sh` solo intenta Dehashed si existe `$DEHASHED_API_KEY`, que nadie
  define, y las dos llamadas a `theHarvester` tiran a `/dev/null` justo los avisos de clave
  ausente.

## Intención y por qué

El operador no tiene hoy ninguna clave declarada y quiere que el gestor se las pida a todas
las herramientas que las usan, las guarde y le diga cuáles le faltan. El daño actual no es
un error visible: es un informe OSINT que parece completo porque las fuentes con clave se
saltaron en silencio.

Decisión del operador: **un registro único como fuente de verdad, y desde él se escriben
los ficheros que cada herramienta lee** (enfoque A).

## Objetivo

1. Un único fichero donde declarar las claves de todas las herramientas, sin salir del
   repo y sin poder subirse a git.
2. Que al guardar una clave quede escrita, en el acto, donde su herramienta la lee.
3. Un estado consolidado: por herramienta, cuántas hay de cuántas, y la lista de las que
   faltan.
4. Que nada de esto pueda dejar una herramienta peor de lo que estaba: si un adaptador
   falla, la clave sigue en el registro y se avisa.

## No objetivos

- Probar las claves contra la API (ver «Validación»): no hay ninguna clave real todavía y
  una prueba de red gasta cuota y confunde «clave mala» con «servicio caído».
- Cablear las claves en los scripts OSINT (`email_harvester.sh` seguirá igual). Eso es el
  pendiente nº 2; este diseño solo deja el punto de consulta (`estado --faltan`).
- Sustituir `00_Config/credentials/` como carpeta de credenciales de *objetivos*
  (usuarios/contraseñas hallados). Las claves de API son otra cosa y van en su fichero.
- Gestión de perfiles, caducidad, rotación ni historial de claves.

## Anti-objetivos

- **Imprimir una clave.** Ni en pantalla, ni en `errores.log`, ni en `set -x`, ni al pedirla.
- **Duplicar el secreto sin saberlo**: el registro es la fuente; el fichero de la
  herramienta es una proyección suya. La divergencia se detecta y se dice, nunca se ignora.
- **Pisar configuración ajena**: al escribir un INI se fusiona, no se reemplaza. Las claves
  que la herramienta ya tenía y el registro no conoce se conservan y se reportan.
- **Tocar el HOME real durante los tests**, ni el registro real del operador.
- **Escribir con `sudo`.** Si algo exige root, se avisa y no se hace.

## La decisión incómoda, dicha en voz alta

A duplica cada secreto en disco: una vez en `00_Config/credentials/api-keys.yaml` y otra en
el fichero de la herramienta. Las dos copias pueden separarse (editores, reinstalaciones,
una herramienta que reescriba su configuración). El diseño lo asume y lo hace visible:

- el registro **manda**: `sincronizar` reescribe todas las proyecciones desde él;
- `estado` compara proyección y registro y marca `diverge` cuando no coinciden;
- lo que exista solo en la proyección se **conserva** (nunca se borra) y se lista como
  «no está en el registro», con la orden para importarlo.

## Enfoques considerados

- **A. Registro único + materialización** — elegido por el operador. Todo en un fichero, una
  sola pantalla, reconstruible si se pierde una herramienta. Coste: dos copias por secreto.
- **B. Cada clave solo donde su herramienta la lee** — descartado por el operador. Cero
  duplicación, pero seis formatos como fuente de verdad y ningún sitio único donde mirar.
- **C. `keys.env` exportado por el gestor** — descartado: theHarvester, amass y el CLI de
  shodan no leen variables de entorno, así que los 36 campos seguirían vacíos.

## Cómo queda

### El registro

`00_Config/credentials/api-keys.yaml` (ya cubierto por `00_Config/.gitignore`, que ignora
`credentials/*` salvo `README.md` y `.gitkeep`). Directorio `700`, fichero `600`, LF.

```yaml
version: 1
# Una sección por herramienta. Los nombres de campo son los que la herramienta espera.
theharvester:            # espejo completo de api-keys.yaml (33 huecos, 36 campos)
  shodan:
    key: ""
  censys:
    id: ""
    secret: ""
  # … los 33 huecos de la plantilla, todos presentes desde el primer día
shodan:
  key: ""
amass:
  censys: {id: "", secret: ""}
h8mail:
  hunterio: ""
  dehashed_email: ""
  dehashed_key: ""
recon-ng:
  shodan_api: ""
spiderfoot:
  sfp_shodan:
    api_key: ""
```

Las claves **no** se ordenan ni se renombran al gusto del adaptador: cada sección usa los
nombres que la herramienta documenta, para que la proyección sea una traducción de formato y
no una traducción de vocabulario.

**Dirección de un campo** (`pedir --campo`, `poner`, `importar`, `--json`): siempre es una
ruta con puntos dentro de la sección de la herramienta — `theharvester.censys.secret`,
`spiderfoot.sfp_shodan.api_key`. Para spiderfoot el último punto separa el módulo (`scope`)
de la opción (`opt`) al proyectar; en el registro es anidamiento normal, como todo lo demás.

**Contenido inicial**: la sección `theharvester` se siembra con los 36 campos de la
plantilla instalada, no con los dos que el operador vaya a rellenar. Así el fichero que se
proyecta es siempre completo (theHarvester indexa `['bevigil']['key']` directamente y un
fichero parcial revienta con `KeyError`) y los totales del estado significan algo.

### Los adaptadores

| Herramienta | Destino | Formato | Modo |
|---|---|---|---|
| theHarvester | `~/.theHarvester/api-keys.yaml` | YAML `apikeys:` | fichero completo (33 huecos, 36 campos) |
| shodan CLI | `~/.shodan/api_key` | una línea | fichero completo |
| h8mail | `~/.h8mail_config.ini` | INI `[h8mail]` | fichero completo |
| amass | `~/.config/amass/datasources.yaml` | YAML (v5) | fusión sobre fichero de amass |
| recon-ng | `~/.recon-ng/keys.db` | SQLite `keys(name, value)` | `INSERT OR REPLACE` |
| spiderfoot | `~/.spiderfoot/spiderfoot.db` | SQLite `tbl_config(scope, opt, val)` | `REPLACE` de una fila |

Reglas de adaptador:

- **theHarvester** busca `api-keys.yaml` en `~/.theHarvester`, `/etc/theHarvester`,
  `/usr/local/etc/theHarvester`, y se queda con el primero que exista. Escribir en `~` gana
  sin `sudo`, pero **deja ciego el `/etc`**: al crear el registro por primera vez, los
  valores no vacíos que haya en `/etc/theHarvester/api-keys.yaml` se importan y se anuncian.
  Los 33 nombres de hueco se leen de la plantilla instalada
  (`/usr/lib/python3/dist-packages/theHarvester/api-keys.yaml`); si theHarvester no está
  instalado, no se piden y se dice.
- **h8mail no lee ese fichero por su cuenta**: solo usa el INI si se le pasa
  `-c ~/.h8mail_config.ini`. La proyección se escribe igual (es la ruta convencional y el
  pendiente nº 2 la cableará), pero el estado la llama `puesta (h8mail necesita -c)` para no
  prometer que ya la está usando. Sus 14 campos son los de la plantilla que genera
  `h8mail --gen-config`.
- **amass** en este Kali es v5.1.1 y no lee `config.ini`: su configuración son
  `~/.config/amass/config.yaml` + `datasources.yaml`, con una lista de entradas que llevan
  `creds:`. Escribir un INI de v4 sería justo el no-op silencioso que este diseño existe para
  quitar, así que el adaptador **fusiona sobre el `datasources.yaml` que haya creado amass**,
  buscando la entrada por `name` y rellenando solo hojas que ya existan en su `creds` (nunca
  inventa estructura); si el fichero no existe, `sin inicializar`.
- **recon-ng y spiderfoot** solo se tocan si su base ya existe. No se crea una base a mano:
  la crea la herramienta en su primer arranque, y hasta entonces el estado es
  `sin inicializar` (aviso, no error).
- Una herramienta ausente (`command -v` falla y no hay fichero) se marca `no instalada` y no
  se escribe nada.

### Fusión, divergencia y `.bak`

- **El registro manda campo a campo.** Al proyectar, un valor del registro gana; un campo del
  fichero de la herramienta que el registro tiene vacío **se conserva tal cual**.
- **`diverge` solo mira lo no vacío**: un valor no vacío en la herramienta que el registro no
  explica (o distinto del registrado) marca `diverge` y `importar` lo trae. Los 30 huecos de
  la plantilla que están vacíos no son divergencia, obviamente.
- **`.bak` solo en las proyecciones de fichero completo** (theHarvester, shodan, h8mail). Las
  fusiones se escriben a un temporal y se renombran (nada que respaldar: no se borra nada), y
  las dos SQLite cambian una fila — respaldar la base entera duplicaría secretos y megabytes
  para nada.

### Órdenes

`00_Config/scripts/api_keys.py`, subcomandos (todo el texto en español):

| Orden | Qué hace |
|---|---|
| `estado [--json]` | tabla herramienta / puestas de totales / estado; `--json` para consumo de scripts. **Nunca escribe**: sin registro, todo vacío |
| `estado --faltan <herramienta>` | lista las vacías de esa herramienta; código 0 si no falta ninguna, 1 si falta alguna, 2 si la herramienta no existe |
| `pedir <herramienta> [--campo X]` | pide las vacías (o solo `--campo`) por stdin, enmascarado |
| `poner <herramienta> <campo> [--stdin]` | escribe un valor sin preguntar (para scripts y tests); `-` borra |
| `sincronizar [<herramienta>]` | reescribe las proyecciones desde el registro |
| `importar <herramienta>` | trae al registro lo que la herramienta tenga y el registro no |

### Pedir una clave

- Se lee sin eco con `getpass`, y **si no hay terminal** (todo el harness de tests empuja
  stdin por tubería) cae a `stdin` normal avisando de que el eco es visible. Así el submenú
  `K` se puede recorrer de punta a punta en `run_keys.sh`, y en una terminal real no se ve
  nada. `poner --stdin` existe para no depender de la caída: es la vía de scripts y tests.
- Nunca pasa por `prompt_for_slots` ni por el `Uso:` del gestor: esas rutas ponen el valor en
  stdout y acabaría en un log o en el historial.
- Entrada vacía = dejar como está. `-` = borrar. Cualquier otra cosa = guardar (se recortan
  espacios de los extremos; un salto de línea o un NUL se rechazan con código 1).
- Confirmación sin revelar: `✅ theharvester/dehashed: definida (32 caracteres)`.
- Al guardar se escribe primero el registro y después se materializa sola esa herramienta;
  si el adaptador falla, se avisa por stderr y el registro queda escrito (código 3).

### Validación

Ninguna comprobación de red. Se valida forma: no vacía, sin espacios internos ni saltos,
mínimo 8 caracteres (avisando, no bloqueando). El estado se llama `puesta (sin verificar)`
para no prometer lo que no se ha comprobado. Una orden `probar` con una llamada real por
herramienta queda como trabajo futuro, cuando haya claves.

### Estados

`puesta (sin verificar)` · `vacía` · `no instalada` · `sin inicializar` (recon-ng/spiderfoot
sin base) · `diverge` (la proyección no coincide con el registro, o tiene claves que el
registro no conoce).

### El gestor

Opción `K` en el menú principal (`cyber_framework.sh`), con su línea en la ayuda `?`:

```
K) Claves de API          6 herramientas · N puestas · M vacías
```

(N y M se cuentan sobre los campos del registro, 36 de ellos de theHarvester; la cifra es la
suma de todos los adaptadores, no una constante escrita a mano.)

Dentro: `1` pedir todas las que falten, `2` una herramienta, `3` estado detallado,
`4` sincronizar, `5` importar. `K` no entra en `dangerous.txt`: pedir una clave no ejecuta
nada contra un objetivo.

### Seguridad

- Registro `600` en directorio `700`, y `chmod` también sobre las proyecciones que creamos
  (`~/.shodan/api_key`, `~/.theHarvester/api-keys.yaml`).
- El valor completo no se imprime nunca: ni el usuario ni la contraseña de Censys ni el
  token. `estado --json` publica presencia y longitud, no contenido.
- Nada de `set -x` en el helper; los errores se escriben sin incluir la línea de entrada.
- `sincronizar` deja `.bak` de la proyección anterior antes de sustituirla, solo en los
  adaptadores de fichero completo (ver «Fusión, divergencia y `.bak`»).
- El registro no se versiona: `00_Config/.gitignore` ya lo cubre, y el test lo comprueba con
  `git check-ignore`.

## Tests

Suite nueva `tests/run_keys.sh` (las otras cuatro no se tocan salvo el smoke, que gana el
assert del menú). Aislamiento por entorno, sin tocar nada real:

| Variable | Para qué |
|---|---|
| `HOME` (temporal) | todas las proyecciones `~/…` |
| `KEYS_FILE` | el registro, en vez del de verdad |
| `KEYS_HARVESTER_DIRS` | la lista de directorios donde se busca `api-keys.yaml`, para poder simular el `/etc` sin root |
| `KEYS_HARVESTER_TEMPLATE` | la plantilla de huecos a usar (la fixture en los tests, la instalada en real) |

Y una fixture propia `tests/fixtures/theharvester-api-keys.yaml` con tres huecos (uno de un
campo y otro de dos) que **no** es la plantilla de theHarvester sino un doble con su forma:
los asserts de mecánica (espejo completo, campos de dos valores) corren siempre; los que
comparan con la plantilla real (36 campos) se saltan con aviso si theHarvester no está
instalado, para que la suite siga pasando en un clon limpio, como las otras cuatro.

1. **Registro**: se crea con `600` y YAML válido; los campos de theHarvester salen de la
   plantilla (la fixture); `git check-ignore` lo confirma.
2. **Poner/borrar**: escribe, es idempotente, `-` borra, vacío conserva, rechaza salto de
   línea, recorta espacios.
3. **theHarvester**: la proyección es espejo exacto (mismos huecos, `censys.id` y
   `censys.secret`), `600`, y `~/.theHarvester` gana al `/etc` simulado.
4. **shodan**: contenido exacto y `600`.
5. **h8mail**: INI con `[h8mail]` y los campos curados.
6. **amass**: fusiona `creds` sobre un `datasources.yaml` ya existente sin borrar el resto;
   sin fichero → `sin inicializar` y no se escribe nada.
7. **recon-ng**: fila en `keys.db`; base ausente → aviso y código 3 sin crear nada.
8. **spiderfoot**: fila en `tbl_config` con `scope`/`opt` partidos; base ausente → aviso.
9. **Estado**: totales correctos, `--faltan` con sus tres códigos, `--json` sin secretos.
10. **Divergencia**: proyección con una clave extra no vacía → `diverge` e `importar` la trae;
    con un hueco vacío extra → no diverge.
11. **Seguridad**: la salida de `estado`, `--json` y `--faltan` no contiene el valor.
12. **Guardas**: `md5sum` del registro real y del `api-keys.yaml` real de `~` antes/después
    de la suite; falla el test si cambian.

## Documentación a tocar

- `docs/API-KEYS-2026-11-06.md` (nuevo): qué hace, dónde vive, cómo se deshace.
- `docs/MANUAL-GESTOR.md`: apartado `K`.
- `AGENTS.md`: una línea en el estado actual y la tabla de sitios donde se escribe.
- `00_Config/credentials/README.md`: qué es este fichero y qué no.

## Deshacerlo

Borrar `00_Config/credentials/api-keys.yaml` deja el gestor como estaba; las herramientas
siguen con sus claves (nadie las borra). Para vaciar una herramienta: `poner <herramienta>
<campo> -`, o restaurar su `.bak`.

## Lo que queda para después

- `probar <herramienta>`: una llamada mínima por adaptador para verificar la clave.
- Cablear `estado --faltan` en `run_all_osint.sh` y en `email_harvester.sh` (pendiente nº 2).
- Sellar el registro con GPG (`*.gpg` ya está ignorado): hoy no está pedido.
