# Asistente de objetivos (`config_wizard.sh`) — plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Añadir `00_Config/scripts/config_wizard.sh`, un asistente que da de alta objetivos en `targets.txt` preguntando host, puerto, protocolo, descripción y prioridad, con confirmación antes de escribir.

**Architecture:** Un script bash autónomo y *source-safe* (el `main` solo se lanza si se ejecuta, no si se hace `source`), que reutiliza `00_Config/lib/session.bash` para `validate_target` y para resolver el fichero (`$SESSION_TARGETS_FILE`). Acumula las entradas en memoria, imprime un resumen, y solo escribe si el usuario confirma. Dos modos: añadir al final (con una línea de fecha) o empezar lista nueva (la actual pasa a `.bak`).

**Tech Stack:** Bash 4+, `python3` (`parse_targets.py` para el resumen final), suites de prueba en bash del propio repo.

**Spec:** `docs/superpowers/specs/2026-10-31-config-wizard-design.md`

## Global Constraints

- Mensajes de usuario en español; sin `set -e`; errores silenciados con `2>/dev/null` como el resto del repo.
- `Uso: ./config_wizard.sh` **sin huecos ni banderas**: `params_mode` debe devolver `none` para que el gestor lo ejecute directo.
- La línea `Uso:`/`Ejemplo:` nunca lleva `|` (rompe `params_slots`).
- Formato de línea escrito: `IP|PUERTO|PROTOCOLO|DESCRIPCIÓN|PRIORIDAD`, con prioridad en mayúsculas `C|A|M|B`.
- Nunca se toca `scope.yaml` ni `00_Config/.session`.
- La copia de seguridad se llama exactamente `<fichero>.bak` (ya cubierta por `00_Config/.gitignore`).
- Rutas resueltas desde `${BASH_SOURCE[0]}`; ninguna ruta absoluta personal.
- Ficheros en LF.
- El árbol tiene 51 ficheros sin commitear de la sesión del 2026-10-31: **nunca `git add -A`**; cada commit añade solo los ficheros que nombra su tarea.

## Review Focus

- **EOF o Ctrl-D en mitad del flujo**: un `read` que falla no puede dejar el fichero escrito a medias ni un bucle infinito; debe salir sin modificar nada.
- **`targets.txt` sin salto de línea final**: al añadir, la primera línea nueva no puede quedar pegada a la última existente.
- **`|` dentro de descripción o protocolo**: se rechaza y se vuelve a preguntar; una sola línea con `|` de más rompe a todos los consumidores (`targets_from_config`, `parse_targets.py`, `02_Recon`).
- **`targets.txt` inexistente o vacío**: el asistente funciona igual (lista vacía) y no falla al mostrarla.
- **Modo "lista nueva" con un `.bak` previo**: se sobrescribe; `targets.txt` nunca debe desaparecer si la escritura falla.

---

### Task 1: Esqueleto source-safe y validadores

**Files:**
- Create: `CyberSecurity-Framework/00_Config/scripts/config_wizard.sh`
- Test: `CyberSecurity-Framework/tests/run_wizard.sh`
- Modify: `CyberSecurity-Framework/tests/run_smoke.sh:89-96`

**Interfaces:**
- Produces (funciones que usan las tareas 2–3 y las pruebas):
  - `wz_default_protocol <puerto>` → imprime el protocolo sugerido (`SSH`, `HTTP`, …) o nada.
  - `wz_valid_port <valor>` → `0` si es entero 1–65535, `1` si no.
  - `wz_valid_priority <valor>` → `0` si es `C|A|M|B` (sin distinguir mayúsculas), `1` si no.
  - `wz_valid_text <valor>` → `0` si no contiene `|` ni caracteres de control, `1` si no.
  - Variables: `SCRIPT_DIR`, `TARGETS_FILE` (= `$SESSION_TARGETS_FILE`).
  - El script termina en `if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main; fi`.

- [ ] **Step 1: Escribir la prueba que falla**

Crea `CyberSecurity-Framework/tests/run_wizard.sh` con este arranque (el resto de tareas añaden secciones antes del resumen final):

```bash
#!/bin/bash
# ============================================================
#  PRUEBAS DEL ASISTENTE DE OBJETIVOS (00_Config/scripts/config_wizard.sh)
#  Uso: bash tests/run_wizard.sh
# ============================================================

FW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WZ="$FW_DIR/00_Config/scripts/config_wizard.sh"
FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/wizard.XXXXXX")"
trap 'rm -rf "$FIXTURE"' EXIT

pasan=0; fallan=0
ok()  { echo "  ok   $1"; pasan=$((pasan + 1)); }
ko()  { echo "  FALLO $1"; fallan=$((fallan + 1)); }

# Carga las funciones sin lanzar el main
# shellcheck source=/dev/null
source "$WZ"

echo ""
echo "=== validadores ==="
[[ "$(wz_default_protocol 22)" == "SSH" ]]   && ok "22 → SSH"   || ko "22 → SSH"
[[ "$(wz_default_protocol 443)" == "HTTPS" ]] && ok "443 → HTTPS" || ko "443 → HTTPS"
[[ -z "$(wz_default_protocol 9999)" ]]       && ok "puerto raro sin defecto" || ko "puerto raro sin defecto"

for p in 1 8080 65535; do
    wz_valid_port "$p" && ok "puerto válido $p" || ko "puerto válido $p"
done
for p in 0 65536 abc "" 8080x; do
    wz_valid_port "$p" && ko "puerto inválido '$p'" || ok "puerto inválido '$p'"
done

for pr in C A M B c a m b; do
    wz_valid_priority "$pr" && ok "prioridad válida $pr" || ko "prioridad válida $pr"
done
for pr in X "" CC 1; do
    wz_valid_priority "$pr" && ko "prioridad inválida '$pr'" || ok "prioridad inválida '$pr'"
done

wz_valid_text "Portal Web" && ok "texto normal" || ko "texto normal"
wz_valid_text "a|b" && ko "texto con |" || ok "texto con |"
wz_valid_text "" && ko "texto vacío" || ok "texto vacío"

echo ""
echo "----------------------------------------"
echo "pasan: $pasan   fallan: $fallan"
[[ "$fallan" -eq 0 ]]
```

Y en `CyberSecurity-Framework/tests/run_smoke.sh`, antes del resumen final:

```bash
out=$(printf '00\n0\nQ\n' | timeout 20 bash ./cyber_framework.sh 2>&1)
printf '%s' "$out" | grep -qF "config_wizard.sh" \
    && echo "  OK       configuración lista config_wizard.sh" \
    || { echo "  FALLO    no lista config_wizard.sh"; fail=$((fail + 1)); }
```

- [ ] **Step 2: Ejecutar y ver que falla**

Run: `cd CyberSecurity-Framework && bash tests/run_wizard.sh; bash tests/run_smoke.sh`
Expected: `run_wizard.sh` falla en el `source` (el fichero no existe) y `run_smoke.sh` marca `FALLO    no lista config_wizard.sh`.

- [ ] **Step 3: Implementar `config_wizard.sh` (esqueleto y validadores)**

Cabecera y utilidades, sin flujo todavía:

```bash
#!/bin/bash
# ============================================================
#  CONFIG WIZARD - Alta guiada de objetivos en targets.txt
#  Uso: ./config_wizard.sh
#  Ejemplo: ./config_wizard.sh
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# shellcheck source=../lib/session.bash
source "$CONFIG_DIR/lib/session.bash"
TARGETS_FILE="$SESSION_TARGETS_FILE"
```

`wz_default_protocol` con este mapa exacto (puerto → protocolo): 21 FTP, 22 SSH, 25 SMTP, 53 DNS, 80 HTTP, 443 HTTPS, 445 SMB, 3306 MySQL, 3389 RDP, 5432 PostgreSQL, 6379 Redis, 8080 HTTP.

`wz_valid_port`: `^[0-9]{1,5}$` y valor entre 1 y 65535.
`wz_valid_priority`: `^[CcAaMmBb]$`.
`wz_valid_text`: no vacío, sin `|` y sin caracteres de control (`^[[:cntrl:]]`).

Cierra el fichero con:

```bash
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main
fi
```

(deja `main()` como `main() { :; }` en esta tarea).

Y dale permiso de ejecución, como a sus hermanos:

```bash
chmod +x CyberSecurity-Framework/00_Config/scripts/config_wizard.sh
```

- [ ] **Step 4: Ejecutar la prueba y ver que pasa**

Run: `cd CyberSecurity-Framework && bash tests/run_wizard.sh | tail -2; bash tests/run_smoke.sh | tail -2`
Expected: `fallan: 0` y `fallos: 0` (el menú ya lista el asistente por descubrimiento automático).

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/00_Config/scripts/config_wizard.sh CyberSecurity-Framework/tests/run_wizard.sh CyberSecurity-Framework/tests/run_smoke.sh
git commit -m "feat(00_Config): esqueleto y validadores del asistente de objetivos"
```

---

### Task 2: Captura de entradas, duplicados y resumen

**Files:**
- Modify: `CyberSecurity-Framework/00_Config/scripts/config_wizard.sh`
- Modify: `CyberSecurity-Framework/tests/run_wizard.sh`

**Interfaces:**
- Consumes: `wz_valid_port`, `wz_valid_priority`, `wz_valid_text`, `wz_default_protocol`, `$TARGETS_FILE`.
- Produces: `main` completo hasta la confirmación final; array `WZ_LINES` con las líneas a escribir; funciones `wz_show_targets`, `wz_exists <host> <puerto>`, `wz_ask <texto> <defecto>` → imprime el texto por **stderr** y la respuesta por **stdout** (la misma regla que `00_Config/lib/prompt.bash`: nunca mezclar la UI con el valor); con Enter devuelve el defecto; en EOF `return 1`.
- La secuencia exacta de `read` por entrada es: host → puerto → protocolo → descripción → prioridad → (duplicado: `s/n`) → confirmación de línea → ¿otro?

- [ ] **Step 1: Añadir las pruebas que fallan**

Añade antes del resumen final de `tests/run_wizard.sh`:

```bash
echo ""
echo "=== captura y resumen (sin escribir) ==="
f="$FIXTURE/targets.txt"
cat > "$f" <<'EOF'
# cabecera
192.168.1.10|80|HTTP|Portal|C
EOF
antes=$(md5sum "$f" | cut -d' ' -f1)

# Flujo válido, respuesta "no" en la confirmación final: no debe escribir
out=$(printf '1\n10.9.9.9\n8080\n\nPrueba\n\ns\nn\nn\n' | \
      SESSION_TARGETS_FILE="$f" bash "$WZ" 2>&1)
printf '%s' "$out" | grep -qF '10.9.9.9|8080|HTTP|Prueba|M' \
    && ok "monta la línea con defectos (HTTP, M)" || ko "monta la línea con defectos (HTTP, M)"
[[ "$(md5sum "$f" | cut -d' ' -f1)" == "$antes" ]] \
    && ok "no escribe si se dice que no" || ko "no escribe si se dice que no"

# Puerto inválido y luego válido
out=$(printf '1\n10.9.9.9\n70000\n8080\n\n\n\ns\nn\nn\n' | \
      SESSION_TARGETS_FILE="$f" bash "$WZ" 2>&1)
printf '%s' "$out" | grep -qE '70000.*no válid|no válid.*70000|Puerto no válido' \
    && ok "avisa del puerto inválido" || ko "avisa del puerto inválido"
printf '%s' "$out" | grep -qF '10.9.9.9|8080|HTTP|HTTP|M' \
    && ok "acepta el puerto válido después" || ko "acepta el puerto válido después"

# Descripción con | se rechaza y se vuelve a pedir
out=$(printf '1\n10.9.9.9\n8080\n\nmal|aqui\nBuena\n\ns\nn\nn\n' | \
      SESSION_TARGETS_FILE="$f" bash "$WZ" 2>&1)
printf '%s' "$out" | grep -qF '10.9.9.9|8080|HTTP|Buena|M' \
    && ok "rechaza | en la descripción" || ko "rechaza | en la descripción"

# Muestra la lista actual antes de preguntar
out=$(printf '1\n\nn\n' | SESSION_TARGETS_FILE="$f" bash "$WZ" 2>&1)
printf '%s' "$out" | grep -qF '192.168.1.10' \
    && ok "muestra los objetivos actuales" || ko "muestra los objetivos actuales"

# Duplicado: avisa y no lo añade si se dice que no
out=$(printf '1\n192.168.1.10\n80\n\n\n\nn\nn\nn\n' | \
      SESSION_TARGETS_FILE="$f" bash "$WZ" 2>&1)
printf '%s' "$out" | grep -qiE 'ya existe|duplicado' \
    && ok "detecta duplicado" || ko "detecta duplicado"
printf '%s' "$out" | grep -qF '192.168.1.10|80|HTTP|HTTP|M' \
    && ko "no añade el duplicado rechazado" || ok "no añade el duplicado rechazado"

# Host vacío al principio: nada que añadir
out=$(printf '1\n\nn\n' | SESSION_TARGETS_FILE="$f" bash "$WZ" 2>&1)
printf '%s' "$out" | grep -qi 'nada' && ok "sin entradas avisa y sale" || ko "sin entradas avisa y sale"

# EOF a mitad: no escribe y no se cuelga
out=$(printf '1\n10.9.9.9\n' | SESSION_TARGETS_FILE="$f" timeout 10 bash "$WZ" 2>&1)
[[ "$(md5sum "$f" | cut -d' ' -f1)" == "$antes" ]] \
    && ok "EOF a mitad no escribe" || ko "EOF a mitad no escribe"
```

- [ ] **Step 2: Ejecutar y ver que falla**

Run: `cd CyberSecurity-Framework && bash tests/run_wizard.sh`
Expected: los casos nuevos fallan (el `main` es vacío, no hay resumen).

- [ ] **Step 3: Implementar el flujo de captura**

Requisitos exactos que la prueba fija:

- Antes de preguntar el modo, mostrar los objetivos actuales (tabla simple leyendo `$TARGETS_FILE`; si no existe, decir que está vacía).
- Modo: `1` añadir, `2` lista nueva, `0` salir; cualquier otra respuesta se repite.
- Orden de preguntas y valores por defecto entre corchetes: `host` (vacío = terminar), `puerto`, `protocolo [<defecto>]` (si no hay defecto, es obligatorio), `descripción [<protocolo>]`, `prioridad [M]`. **Un campo vacío se sustituye por su defecto antes de validar**, así que `wz_valid_text` nunca ve la descripción vacía cuando hay protocolo.
- Rechazo (mensaje `❌ … no válido` y repetir la pregunta): puerto, protocolo/descripción con `|`, prioridad fuera de `C/A/M/B`, host que no pase `validate_target`.
- Duplicado (ya en `$TARGETS_FILE` o repetido en `WZ_LINES`): `⚠️  Ya existe … ¿añadir igualmente? (s/n) [n]`; `n` no añade y pasa a "¿otro objetivo?".
- Confirmación de la línea: `  → <host>|<puerto>|<proto>|<desc>|<PRIO>` y `¿Correcto? (s/n) [s]`.
- "¿Otro objetivo? (s/n) [s]".
- Resumen: una línea por entrada en el mismo formato, y `¿Escribir N objetivo(s)? (s/n) [s]`; `n` → `Nada se ha modificado.` y salida 0.
- Cualquier `read` en EOF → mensaje `Nada se ha modificado.` y salida 0, sin escribir.
- Al final de `main`, si hay entradas confirmadas, **no escribir todavía** (lo hace la tarea 3): deja `WZ_LINES` y salta a la función `wz_write` (vacía en esta tarea).

- [ ] **Step 4: Ejecutar y ver que pasa**

Run: `cd CyberSecurity-Framework && bash tests/run_wizard.sh`
Expected: `fallan: 0`.

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/00_Config/scripts/config_wizard.sh CyberSecurity-Framework/tests/run_wizard.sh
git commit -m "feat(00_Config): captura validada de objetivos en el asistente"
```

---

### Task 3: Escritura del fichero (añadir y lista nueva)

**Files:**
- Modify: `CyberSecurity-Framework/00_Config/scripts/config_wizard.sh`
- Modify: `CyberSecurity-Framework/tests/run_wizard.sh`

**Interfaces:**
- Consumes: `WZ_LINES`, `$TARGETS_FILE`, el modo elegido en una variable global `WZ_MODE` (`1` añadir / `2` nueva).
- Produces: `wz_write` → escribe y deja el resultado en disco; `wz_header` → imprime por stdout la cabecera estándar.

- [ ] **Step 1: Añadir las pruebas que fallan**

```bash
echo ""
echo "=== escritura ==="
# Añadir conservando lo anterior
f="$FIXTURE/targets.txt"
printf '%s\n' "# cabecera" "192.168.1.10|80|HTTP|Portal|C" > "$f"
out=$(printf '1\n10.9.9.9\n8080\n\nPrueba\n\ns\nn\ns\n' | \
      SESSION_TARGETS_FILE="$f" bash "$WZ" 2>&1)
grep -qF '192.168.1.10|80|HTTP|Portal|C' "$f" && ok "añadir conserva lo previo" || ko "añadir conserva lo previo"
grep -qF '10.9.9.9|8080|HTTP|Prueba|M' "$f" && ok "añadir escribe la línea nueva" || ko "añadir escribe la línea nueva"
grep -qE '^# ─── AÑADIDOS POR config_wizard' "$f" && ok "añadir deja marca de fecha" || ko "añadir deja marca de fecha"
printf '%s' "$out" | grep -qF 'RESUMEN DE OBJETIVOS' && ok "cierra con el resumen del parser" || ko "cierra con el resumen del parser"

# Sin salto de línea final: la línea nueva no se pega
f="$FIXTURE/sin_salto.txt"
printf '%s' "192.168.1.10|80|HTTP|Portal|C" > "$f"
printf '1\n10.9.9.9\n22\n\n\n\ns\nn\ns\n' | SESSION_TARGETS_FILE="$f" bash "$WZ" >/dev/null 2>&1
grep -qE '^192\.168\.1\.10\|80\|HTTP\|Portal\|C$' "$f" && ok "no pega la línea al final sin \n" || ko "no pega la línea al final sin \n"

# Lista nueva: .bak con lo anterior, fichero con cabecera y solo lo nuevo
f="$FIXTURE/nueva.txt"
printf '%s\n' "192.168.1.10|80|HTTP|Portal|C" "10.0.0.1|22|SSH|Viejo|A" > "$f"
printf '2\n10.9.9.9\n443\n\n\nA\ns\nn\ns\n' | SESSION_TARGETS_FILE="$f" bash "$WZ" >/dev/null 2>&1
grep -qF '10.0.0.1|22|SSH|Viejo|A' "$f.bak" && ok "lista nueva guarda .bak" || ko "lista nueva guarda .bak"
grep -qF '192.168.1.10|80|HTTP|Portal|C' "$f" && ko "lista nueva descarta lo viejo" || ok "lista nueva descarta lo viejo"
grep -qF '10.9.9.9|443|HTTPS|HTTPS|A' "$f" && ok "lista nueva escribe la entrada" || ko "lista nueva escribe la entrada"
head -1 "$f" | grep -q '^# =====' && ok "lista nueva lleva cabecera estándar" || ko "lista nueva lleva cabecera estándar"

# .bak previo se sobrescribe
f="$FIXTURE/rebak.txt"
printf '%s\n' "1.1.1.1|80|HTTP|X|B" > "$f"
printf '%s\n' "viejo backup" > "$f.bak"
printf '2\n10.9.9.9\n22\n\n\n\ns\nn\ns\n' | SESSION_TARGETS_FILE="$f" bash "$WZ" >/dev/null 2>&1
grep -qF 'viejo backup' "$f.bak" && ko ".bak previo se sobrescribe" || ok ".bak previo se sobrescribe"

# Fichero inexistente: se crea con cabecera
f="$FIXTURE/no_existe.txt"
printf '1\n10.9.9.9\n22\n\n\n\ns\nn\ns\n' | SESSION_TARGETS_FILE="$f" bash "$WZ" >/dev/null 2>&1
[[ -f "$f" ]] && grep -qF '10.9.9.9|22|SSH|SSH|M' "$f" && ok "crea el fichero si falta" || ko "crea el fichero si falta"

# Fichero vacío: no falla y escribe cabecera + entrada
f="$FIXTURE/vacio.txt"
: > "$f"
printf '1\n10.9.9.9\n22\n\n\n\ns\nn\ns\n' | SESSION_TARGETS_FILE="$f" bash "$WZ" >/dev/null 2>&1
grep -qF '10.9.9.9|22|SSH|SSH|M' "$f" && ok "escribe sobre fichero vacío" || ko "escribe sobre fichero vacío"
```

- [ ] **Step 2: Ejecutar y ver que falla**

Run: `cd CyberSecurity-Framework && bash tests/run_wizard.sh`
Expected: fallan los casos de escritura (no existe `wz_write`).

- [ ] **Step 3: Implementar `wz_header` y `wz_write`**

- `wz_header` imprime exactamente el bloque de cabecera de 14 líneas de
  `00_Config/targets.txt` actual (`# ====…` hasta la línea en blanco tras la
  leyenda de prioridades).
- `wz_write`:
  - Modo añadir: crea el fichero si no existe (con `wz_header`); asegura un
    salto de línea final (`[[ -s "$f" ]] && [[ "$(tail -c1 "$f")" != "" ]] && echo >> "$f"`);
    añade `# ─── AÑADIDOS POR config_wizard ($(date '+%Y-%m-%d %H:%M')) ───` y las líneas.
  - Modo lista nueva: escribe cabecera + líneas en `"$TARGETS_FILE.tmp"` del
    mismo directorio, `mv -f` el actual a `"$TARGETS_FILE.bak"` (si existe) y
    `mv -f` el temporal sobre `"$TARGETS_FILE"`.
  - Después: `command -v python3 >/dev/null && python3 "$SCRIPT_DIR/parse_targets.py" --input "$TARGETS_FILE" --summary`.
    Ojo: `--input` con ruta absoluta, porque `parse_targets.py` resuelve rutas
    relativas contra su propio directorio.
  - Cierra recordando `./scripts/validate_config.sh`.

- [ ] **Step 4: Ejecutar y ver que pasa**

Run: `cd CyberSecurity-Framework && bash tests/run_wizard.sh`
Expected: `fallan: 0`.

- [ ] **Step 5: Commit**

```bash
git add CyberSecurity-Framework/00_Config/scripts/config_wizard.sh CyberSecurity-Framework/tests/run_wizard.sh
git commit -m "feat(00_Config): escritura con copia de seguridad en el asistente"
```

---

### Task 4: No colgar el "run all" y documentar

**Files:**
- Modify: `CyberSecurity-Framework/00_Config/run_all_config.sh`
- Modify: `CyberSecurity-Framework/00_Config/README.md`
- Modify: `AGENTS.md`
- Test: `CyberSecurity-Framework/tests/run_wizard.sh`

**Interfaces:**
- Consumes: `tests/run_wizard.sh` (ya creado).
- Produces: nada que otras tareas usen.

- [ ] **Step 1: Añadir la prueba que falla**

En `tests/run_wizard.sh`, antes del resumen:

```bash
echo ""
echo "=== integración ==="
# run_all_config no debe lanzar el asistente (se colgaría esperando entrada)
out=$(printf '' | timeout 30 bash "$FW_DIR/00_Config/run_all_config.sh" 2>&1)
printf '%s' "$out" | grep -q 'config_wizard' && ko "run_all_config salta el asistente" || ok "run_all_config salta el asistente"
```

- [ ] **Step 2: Ejecutar y ver que falla**

Run: `cd CyberSecurity-Framework && bash tests/run_wizard.sh | tail -3`
Expected: `FALLO run_all_config salta el asistente` (el bucle ejecuta todo `scripts/*`).

- [ ] **Step 3: Saltar el asistente en `run_all_config.sh`**

Añade el caso en el bucle que ya filtra `run_all*`:

```bash
case "$(basename "$script")" in
    run_all*|config_wizard.sh) continue ;;
esac
```

- [ ] **Step 4: Documentar**

- `00_Config/README.md`, en "🚀 Uso Rápido": añadir
  ```bash
  # Alta guiada de objetivos (pregunta host, puerto, protocolo, descripción y prioridad)
  ./scripts/config_wizard.sh
  ```
- `AGENTS.md`: en la sección `## The manager and its library`, cambiar "three test scripts for that library and the manager" por "four: the library, the end-to-end run, the smoke menu, and the config wizard". Y en `## Config and data formats`, añadir una línea: `00_Config/scripts/config_wizard.sh` es la vía guiada para dar de alta objetivos; escribe el mismo formato y no toca `scope.yaml`.

- [ ] **Step 5: Ejecutar la batería completa**

```bash
cd CyberSecurity-Framework
bash tests/run_wizard.sh | tail -2
bash tests/run_tests.sh | tail -1
bash tests/run_e2e.sh | tail -1
bash tests/run_smoke.sh | tail -2
bash -n 00_Config/scripts/config_wizard.sh && bash -n 00_Config/run_all_config.sh && echo "sintaxis OK"
```
Expected: `fallan: 0` en las cuatro; `pasan: 61` y `pasan: 11`; `sintaxis OK`. Además, sin stderr en los `bash -n`.

- [ ] **Step 6: Commit**

```bash
git add CyberSecurity-Framework/00_Config/run_all_config.sh CyberSecurity-Framework/00_Config/README.md CyberSecurity-Framework/tests/run_wizard.sh AGENTS.md
git commit -m "docs(00_Config): asistente de objetivos en el menú y en la documentación"
```

---

## Cierre

Tras la última tarea, prueba a mano una vez y deshaz el cambio:

```bash
cd CyberSecurity-Framework
cp 00_Config/targets.txt /tmp/opencode/targets.antes
./00_Config/scripts/config_wizard.sh     # añade 127.0.0.1|8080|HTTP|Prueba|M
python3 00_Config/scripts/parse_targets.py --summary
cp /tmp/opencode/targets.antes 00_Config/targets.txt
```

Comprueba en el menú (`./cyber_framework.sh` → `00`) que aparece como opción y que al elegirla no pide argumentos.
