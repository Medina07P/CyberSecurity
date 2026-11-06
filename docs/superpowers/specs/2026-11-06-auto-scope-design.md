# Diseño — El objetivo de sesión se registra solo en scope.yaml (enfoque A)

- **Fecha:** 2026-11-06
- **Estado:** pendiente de aprobación
- **Origen:** conversación con el operador tras ejecutar OSINT sobre un dominio propio:
  `scope.yaml` seguía siendo la plantilla y hubo que editarlo a mano.

## Intención y por qué

Hoy el objetivo se fija en un sitio (menú `T` → `00_Config/.session`) y la autorización
se declara en otro (`00_Config/scope.yaml`), que ningún script escribe. El operador tiene
que recordar editar el YAML a mano antes de cada trabajo o el gestor le dirá que su
objetivo está fuera de alcance. El coste de olvidarlo no es un error visible: es trabajar
sin constancia de alcance.

Decisión del operador: **el gestor da el objetivo por autorizado y lo escribe él**.

## Objetivo

Que fijar el objetivo de sesión (`T`, o el valor que se hornea en `.session`) deje
constancia automática en `scope.yaml`, sin duplicados, sin romper el formato del fichero
y sin poder dejarlo corrupto.

## No objetivos

- Sustituir el documento legal: `authorization.document` sigue siendo del operador.
- Comprobar que el operador es dueño del dominio. No hay forma de saberlo desde aquí.
- Registrar objetivos que se teclean en un script y no se aceptan como objetivo de sesión.
- Elegir puerto ni prioridad reales en `targets.txt`: se escriben como desconocidos (`—`) y
  prioridad `B`, que es lo que se sabe al fijar el objetivo.

## Anti-objetivos

- **Corromper `scope.yaml`.** Es el fichero del que dependen `scope_allows` y
  `phase_status`; un YAML inválido rompe la comprobación de alcance en silencio. Cualquier
  escritura que no parsee se deshace.
- **Duplicar entradas** en cada ejecución.
- **Reformatear el fichero**: los comentarios y el orden existentes se conservan.
- **Tocar el `scope.yaml` real durante los tests.**

## La decisión incómoda, dicha en voz alta

Si el gestor añade lo que tecleas, `scope_allows` deja de ser un control y pasa a ser un
registro de lo que has usado: siempre dirá que sí. Es lo que se ha pedido y tiene sentido
en un framework de un solo operador, pero conviene que conste: la barrera real es el
documento de autorización, no el YAML. Por eso el diseño mantiene el aviso de "fuera de
alcance" para objetivos añadidos a mano en `.session` sin pasar por `T`… salvo que también
se registren: se registran siempre, así que el aviso ya no aparecerá por esta vía.

## Enfoques considerados

- **A. Gancho único en `session_set_target`** — elegido. Todo objetivo de sesión pasa por
  ahí (menú `T`, selección de `targets.txt`, tests). Un solo punto que mantener.
- **B. Solo desde el menú `T`, con confirmación** — descartado: un objetivo aceptado dentro
  de un script no quedaría registrado, justo el caso que motivó la petición.
- **C. `scope_auto.yaml` aparte** — descartado: dos fuentes de verdad y código nuevo en
  cada lectura de alcance.

## Cómo queda

### API nueva (`00_Config/lib/session.bash`)

```
SESSION_SCOPE_FILE="${SESSION_SCOPE_FILE:-$SESSION_CONFIG_DIR/scope.yaml}"

scope_add_target <ip|dominio>
   0  añadido (o ya estaba: idempotente)
   1  valor no válido
   2  no se pudo escribir (fichero ausente, sección ausente, YAML no parsea)
```

`session_set_target` la llama tras guardar `.session`. **Un fallo de escritura no cancela
la sesión**: se avisa por stderr (una línea) y se sigue; el objetivo ya está en `.session`.

### Qué escribe

- IP → `targets.ips`, entrada `- "10.0.0.9"`.
- Dominio → `targets.domains`, **dos** entradas: `- "dominio"` y `- "*.dominio"`.
  Hacen falta las dos: `scope_allows` compara dominios por sufijo con comodín, y OSINT de
  un dominio quiere sus subdominios. Un subdominio (`sub.dominio`) se registra como él
  mismo y `*.sub.dominio`, nunca como el dominio padre (autorizaría a sus hermanos).
- Cada entrada lleva `# auto: gestor YYYY-MM-DD`.

### Cómo escribe (sin romper nada)

- `awk` sobre el texto: localiza `ips:` / `domains:` dentro de `targets:` e inserta tras
  la última entrada de esa clave (o tras la clave si está vacía). No reescribe el resto.
- Idempotencia por comparación normalizada (sin comillas, comentarios ni espacios): si el
  valor ya está, no se añade.
- Antes de escribir: copia a `scope.yaml.bak`.
- Después de escribir: `python3 -c 'yaml.safe_load(...)'`. Si falla, se restaura el `.bak`
  y se devuelve 2. Si no hay `python3`, se escribe igual y se avisa de que no se pudo
  verificar (PyYAML está instalado en este equipo).
- Si `scope.yaml` no existe o no tiene la clave, **no se inventa**: se avisa y no se toca.

### El pequeño arreglo que va con esto

`scope_allows` solo entiende dominios con comodín (`*.dominio`); una entrada pelada
`- "dominio"` no coincide nunca con el objetivo. Se corrige para que una entrada sin
comodín coincida exactamente. No cambia lo que autoriza hoy, cierra una trampa.

### También en `targets.txt` (añadido aprobado el 2026-11-06)

`session_set_target` llama además a `targets_add_entry <host>`, que añade al final de
`00_Config/targets.txt`:

```
# ─── AÑADIDOS POR EL GESTOR (2026-11-06 15:30) ───
cliente.example|—|—|Registrado al fijar el objetivo|B
```

- `—` en puerto y protocolo es el marcador de "desconocido" que ya entiende
  `00_Config/scripts/parse_targets.py`; inventar `443` o `22` sería mentir sobre el servicio.
- Prioridad `B`: no se conoce al fijar el objetivo.
- Idempotente: si ya hay una línea que empieza por `<host>|`, no se añade.
- La cabecera fechada imita la del `config_wizard.sh`, para que el fichero se lea igual
  venga de donde venga.
- Efecto secundario deseado: el objetivo aparece en el menú `T` la próxima vez
  (`targets_from_config`).

### Lo que ve el operador

```
✅ Objetivo guardado: cliente.example
   ➕ scope.yaml: cliente.example, *.cliente.example
```

Si ya estaba: no imprime nada más. Si no se pudo: `⚠️ No se pudo registrar en
scope.yaml: <motivo>`.

## Tests (en `tests/run_tests.sh`, sección nueva)

Fixture con `scope.yaml` temporal y `SESSION_SCOPE_FILE` apuntando a él:

- el dominio se añade con su comodín; la IP va a `ips`;
- segunda llamada no duplica (mismo número de líneas);
- `scope.yaml.bak` se crea;
- comentarios y el resto del YAML se conservan (`diff` de las líneas no tocadas);
- el YAML resultante parsea con PyYAML;
- un `scope.yaml` sin `domains:` no se modifica y devuelve 2;
- el `scope.yaml` real no cambia durante la suite (md5 antes/después);
- `scope_allows` acepta el dominio pelado (tras el arreglo).

Y sobre `targets.txt` (fixture con `SESSION_TARGETS_FILE`, que ya está aislado en la suite):

- añade `<host>|—|—|Registrado al fijar el objetivo|B` bajo cabecera fechada;
- segunda llamada no duplica;
- el `targets.txt` real no cambia (md5 antes/después);
- `00_Config/scripts/parse_targets.py` sigue parseando el fixture (`port` y `protocol` a
  `null`).

Además `tests/run_tests.sh` y `tests/run_e2e.sh` deben exportar `SESSION_SCOPE_FILE`
para no escribir nunca en el fichero real.

## Lo que queda al constructor

- Dónde exactamente insertar cuando hay varias claves `domains:` (se elige la primera
  dentro de `targets:`).
- Formato final del aviso en el gestor (respetando el contrato: valores por stdout, UI por
  stderr; aquí es UI, va a stdout en `change_target`, que no captura nada).
- Si conviene un `--dry-run` para `scope_add_target` (no hace falta hoy).

## Riesgos

- **`awk` y YAML a mano.** Mitigado con `.bak` + validación + restauración.
- **Tests que escriben el fichero real.** Mitigado con `SESSION_SCOPE_FILE` y el md5.
- **Falsa sensación de control.** Ver arriba; es una decisión del operador, documentada.
