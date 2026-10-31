# Asistente interactivo para `targets.txt` — diseño

Cambio pequeño. Aprobado el enfoque "añadidor guiado" (opción 1 de las tres
presentadas); este documento es lo acordado, escrito para poder planificarlo.

## Intención y por qué

Hoy la configuración se edita a mano. `validate_config.sh` y
`verify_00_config.sh` solo comprueban que los ficheros existan y
`parse_targets.py` únicamente lee y resume. El usuario quiere poder **darse de
alta los objetivos preguntándole los datos**, sin dejar de poder editarlos a
mano.

`targets.txt` se elige como único destinatario porque es el fichero que alimenta
el flujo real: `02_Recon/run_all_recon.sh`, la lista de objetivos del gestor
(`targets_from_config`) y `phase_status`. `scope.yaml` solo lo lee
`scope_allows` con un `grep` de rangos y cambia una vez por trabajo.

## Objetivos

- Un script nuevo, `00_Config/scripts/config_wizard.sh`, que aparezca solo en el
  menú de `00_Config` (el gestor descubre `scripts/*.sh`).
- Pedir un objetivo campo a campo, validando cada respuesta, y escribirlo en
  `targets.txt` en el formato `IP|PUERTO|PROTOCOLO|DESCRIPCIÓN|PRIORIDAD`.
- Ofrecer "empezar lista nueva" además de "añadir a la actual", con copia de
  seguridad.
- No escribir nada hasta que el usuario confirme el conjunto completo.

## No objetivos (fuera de alcance, decidido)

- `scope.yaml` no se toca.
- No se editan ni se borran líneas existentes (para eso, un editor).
- No se añaden líneas de exclusión (`—|—|… EXCLUIDO`) ni entradas sin puerto.
- No se escribe `00_Config/.session` ni se cambia el objetivo de la sesión: el
  gestor ya tiene su opción para eso.
- Nada de red ni de root.

## Anti-objetivos

- Que `run_all_config.sh` se quede colgado esperando entrada.
- Que un fallo a mitad deje `targets.txt` a medias: o se escribe entero o no se
  escribe.
- Que el asistente acepte una línea que rompa el formato (un `|` en la
  descripción, un puerto no numérico).

## Restricciones de la casa

- `#!/bin/bash`, cabecera con `Uso:`/`Ejemplo:`, mensajes en español, sin
  `set -e`, `mkdir -p` donde haga falta.
- `Uso: ./config_wizard.sh` **sin huecos ni banderas** → `params_mode` devuelve
  `none` y el gestor lo ejecuta sin pedir argumentos (comprobado en
  `00_Config/lib/params.bash`).
- Autolocalización: rutas desde `${BASH_SOURCE[0]}`.
- La validación de host se reutiliza: `source ../lib/session.bash` y
  `validate_target` (ese fichero solo define funciones y variables de ruta; no
  ejecuta nada). El fichero destino es `$SESSION_TARGETS_FILE`, que la librería
  ya permite sobrescribir — es lo que usará la prueba.

## Cómo se comporta

1. Lee `targets.txt` y muestra los objetivos actuales en una tabla compacta
   (host, puerto, protocolo, prioridad), saltando comentarios y `EXCLUIDO`.
2. Pregunta: `1` añadir a la lista actual · `2` empezar lista nueva · `0` salir.
   En "nueva", la actual pasa a `targets.txt.bak` solo al escribir.
3. Bucle de alta:
   - **host**: obligatorio, `validate_target`; vacío = terminar.
   - **puerto**: entero 1–65535.
   - **protocolo**: texto libre sin `|`; se propone por defecto según el puerto
     (22→SSH, 21→FTP, 25→SMTP, 53→DNS, 80/8080→HTTP, 443→HTTPS, 445→SMB,
     3389→RDP, 3306→MySQL, 5432→PostgreSQL, 6379→Redis); Enter lo acepta.
   - **descripción**: texto libre sin `|`; vacío → el nombre del protocolo.
   - **prioridad**: `C`, `A`, `M` o `B`; por defecto `M`.
   - Duplicado (`host|puerto` ya presente, o repetido en el lote): avisa y
     pregunta si añadirlo igualmente.
   - Muestra la línea resultante y pide confirmación (`s` por defecto).
   - Pregunta si hay otro objetivo.
4. Resumen de lo que se va a escribir + confirmación final. Si se dice que no,
   o si se interrumpe con Ctrl-C/EOF, **no se modifica nada**.
5. Escritura: en "añadir", comenta la fecha
   (`# ─── AÑADIDOS POR config_wizard (YYYY-MM-DD HH:MM) ───`) y añade las
   líneas; en "nueva", crea un temporal en el mismo directorio con la cabecera
   estándar y las líneas, y lo mueve sobre `targets.txt` al final.
6. Cierra ejecutando `python3 scripts/parse_targets.py --summary` (el resumen
   que ya conoce el usuario) y recordando `./scripts/validate_config.sh`.

## Ficheros

| Fichero | Cambio |
|---|---|
| `00_Config/scripts/config_wizard.sh` | nuevo |
| `00_Config/run_all_config.sh` | saltar `config_wizard.sh`: es interactivo y colgaría el "run all" |
| `00_Config/README.md` | documentarlo en el uso rápido |
| `tests/run_wizard.sh` | suite nueva, con `SESSION_TARGETS_FILE` apuntando a un temporal |
| `AGENTS.md` | de "tres suites" a cuatro, y una línea sobre el asistente |

## Decisiones mías (revisables)

- Copia de seguridad única, `targets.txt.bak` (ya la ignora
  `00_Config/.gitignore` con `*.bak`), sobrescrita en cada "lista nueva".
- Escritura diferida en memoria: permite el resumen y evita ficheros a medias.
- Reutilizar `session.bash` en vez de duplicar la validación de host.
- Suite de pruebas propia en lugar de meterlo en `run_smoke.sh`: son cosas
  distintas (navegación del menú vs. escritura de un fichero).

## Verificación

- `bash -n` del script y de `run_all_config.sh`.
- `tests/run_wizard.sh`: alta con entrada canalizada, prioridad por defecto,
  rechazo de puerto y de `|` en la descripción, duplicado, lista nueva con
  `.bak`, y aborto sin escribir.
- `tests/run_tests.sh`, `run_e2e.sh` y `run_smoke.sh` siguen en verde (más la
  comprobación de que `00_Config` lista el asistente).
- `run_all_config.sh` termina sin pedir entrada.
- Prueba manual: añadir `127.0.0.1|8080|HTTP|Prueba|M`, ver el resumen y
  restaurar `targets.txt` desde el `.bak`.
