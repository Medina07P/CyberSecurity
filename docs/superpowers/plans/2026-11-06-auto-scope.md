# Objetivo de sesión → scope.yaml y targets.txt — Plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Que `session_set_target` deje constancia automática del objetivo en `00_Config/scope.yaml` y en `00_Config/targets.txt`, sin duplicados ni corrupción.

**Architecture:** Dos funciones nuevas en `00_Config/lib/session.bash` (`scope_add_target`, `targets_add_entry`) que `session_set_target` invoca tras escribir `.session`. Escritura textual con `awk` sobre los ficheros existentes, copia de seguridad y validación con PyYAML; un fallo avisa y no cancela la sesión.

**Tech Stack:** Bash, `awk`, `grep`, `python3`+PyYAML (solo para validar). Sin dependencias nuevas.

**Spec:** `docs/superpowers/specs/2026-11-06-auto-scope-design.md`

## Global Constraints

- Las funciones que devuelven un valor imprimen **solo** el valor por stdout; los avisos van a stderr (`00_Config/lib/prompt.bash`, cabecera).
- Rutas siempre desde `${BASH_SOURCE[0]:-$0}`; nada de `$PWD` (soporta zsh, que deja `BASH_SOURCE` vacío).
- Códigos de retorno: `0` hecho o ya estaba · `1` valor no válido · `2` no se pudo escribir.
- Nunca se escribe en el `scope.yaml` ni en el `targets.txt` reales durante los tests (`SESSION_SCOPE_FILE`, `SESSION_TARGETS_FILE`).
- Marca de "desconocido" en `targets.txt`: `—` (em dash), que `00_Config/scripts/parse_targets.py` traduce a `null`.
- Ficheros `.sh`/`.bash` en LF; `bash -n` no basta (un heredoc sin cerrar pasa), así que se revisa stderr.

## Review Focus

- `scope.yaml` con más de una clave `domains:` (p. ej. bajo `targets.excluded`): solo debe insertarse en la de `targets:`.
- Objetivo con mayúsculas (`Example.com`) cuando ya está `example.com`: no debe duplicarse.
- `targets.txt` sin salto de línea final: la entrada nueva no debe pegarse a la última.
- `targets.txt` inexistente: debe crearse con su cabecera, no fallar.
- `scope.yaml` editado en Windows (CRLF): no debe corromperse ni duplicar entradas ya presentes.

---

### Task 1: `scope_add_target` y el arreglo de `scope_allows`

**Files:**
- Modify: `CyberSecurity-Framework/00_Config/lib/session.bash` (añadir `SESSION_SCOPE_FILE` tras las líneas 11-12; `scope_add_target` tras `session_clear`; `scope_allows` en 130-136)
- Test: `CyberSecurity-Framework/tests/run_tests.sh` (sección nueva tras «Validación del objetivo», ~línea 105)

**Interfaces:**
- Consumes: `validate_target` (ya existe, línea 18).
- Produces:
  - `SESSION_SCOPE_FILE` — ruta, por defecto `$SESSION_CONFIG_DIR/scope.yaml`.
  - `scope_add_target <valor>` → `0` añadido o ya estaba · `1` no válido · `2` no se pudo escribir (fichero ausente, sin la clave, o YAML inválido).
  - `scope_allows` (sin cambio de firma) pasa a aceptar entradas sin comodín como coincidencia exacta.

- [ ] **Step 1: Aislar el fichero real en la suite antes de nada**

En `tests/run_tests.sh`, junto a los `export SESSION_FILE`/`SESSION_TARGETS_FILE` (líneas 15-16), añadir:

```bash
export SESSION_SCOPE_FILE="$TMPD/scope.yaml"
MD5_SCOPE_REAL=$(md5sum "$FW/00_Config/scope.yaml" 2>/dev/null | cut -d' ' -f1)
MD5_TARGETS_REAL=$(md5sum "$FW/00_Config/targets.txt" 2>/dev/null | cut -d' ' -f1)
```

Y al final del fichero, antes de `rm -rf "$TMPD"`, dos asserts:

```bash
eq "el scope.yaml real no cambió" \
   "$(md5sum "$FW/00_Config/scope.yaml" 2>/dev/null | cut -d' ' -f1)" "$MD5_SCOPE_REAL"
eq "el targets.txt real no cambió" \
   "$(md5sum "$FW/00_Config/targets.txt" 2>/dev/null | cut -d' ' -f1)" "$MD5_TARGETS_REAL"
```

- [ ] **Step 2: Escribir los tests de `scope_add_target` (deben fallar)**

Sección nueva en `run_tests.sh`:

```bash
section "El objetivo se registra en scope.yaml"
cp "$FW/00_Config/scope.yaml" "$TMPD/scope.yaml"
scope_add_target example.com;        eq "añade el dominio"            "$?" "0"
eq "añade el dominio pelado"         "$(grep -c '^ *- "example\.com"$' "$TMPD/scope.yaml")" "1"
eq "añade el comodín"                "$(grep -c '^ *- "\*\.example\.com"$' "$TMPD/scope.yaml")" "1"
antes=$(wc -l < "$TMPD/scope.yaml")
scope_add_target example.com
eq "no duplica"                      "$(wc -l < "$TMPD/scope.yaml")" "$antes"
scope_add_target 10.1.2.3;           eq "añade la IP"               "$?" "0"
eq "la IP va a ips"                  "$(sed -n '/^  ips:/,/^  [a-z]/p' "$TMPD/scope.yaml" | grep -c '10.1.2.3')" "1"
eq "la IP no va a domains"           "$(sed -n '/^  domains:/,/^  [a-z]/p' "$TMPD/scope.yaml" | grep -c '10.1.2.3')" "0"
eq "crea la copia .bak"              "$([[ -f "$TMPD/scope.yaml.bak" ]] && echo si)" "si"
eq "el YAML sigue parseando"         "$(python3 -c 'import yaml,sys;yaml.safe_load(open(sys.argv[1]))' "$TMPD/scope.yaml" >/dev/null 2>&1; echo $?)" "0"
eq "conserva los comentarios"        "$(grep -c 'AUTORIZACIÓN' "$TMPD/scope.yaml")" "1"
scope_add_target "malo con espacios"; eq "rechaza un valor inválido"  "$?" "1"
printf 'targets:\n  ips:\n    - "1.2.3.4"\n' > "$TMPD/sin_domains.yaml"
SESSION_SCOPE_FILE="$TMPD/sin_domains.yaml" scope_add_target otra.com
eq "sin la clave domains no inventa" "$?" "2"
eq "y no toca el fichero"            "$(md5sum < "$TMPD/sin_domains.yaml" | cut -d' ' -f1)" \
                                     "$(printf 'targets:\n  ips:\n    - "1.2.3.4"\n' | md5sum | cut -d' ' -f1)"
printf 'targets:\n  domains:\n    - "solo.com"\n' > "$TMPD/exacto.yaml"
SESSION_SCOPE_FILE="$TMPD/exacto.yaml" scope_allows solo.com
eq "scope_allows acepta el dominio pelado" "$?" "0"
# Review Focus: mayúsculas, clave duplicada, CRLF
scope_add_target Example.com; eq "no duplica por mayúsculas" "$(grep -ic '^ *- "example\.com"$' "$TMPD/scope.yaml")" "1"
printf 'targets:\n  domains:\n    - "a.com"\n  excluded:\n    - "b.com"\n' > "$TMPD/dos_claves.yaml"
SESSION_SCOPE_FILE="$TMPD/dos_claves.yaml" scope_add_target c.com
eq "inserta solo en targets.domains" "$(sed -n '/^  excluded:/,$p' "$TMPD/dos_claves.yaml" | grep -c 'c\.com')" "0"
printf 'targets:\r\n  domains:\r\n    - "crlf.com"\r\n' > "$TMPD/crlf.yaml"
SESSION_SCOPE_FILE="$TMPD/crlf.yaml" scope_add_target crlf.com
eq "no duplica con CRLF" "$(grep -c 'crlf\.com' "$TMPD/crlf.yaml")" "1"
SESSION_SCOPE_FILE="$TMPD/scope.yaml"
```

- [ ] **Step 3: Verificar que fallan**

Run: `bash tests/run_tests.sh 2>&1 | grep -A2 'registra en scope'`
Expected: `command not found: scope_add_target` y asserts en FALLO.

- [ ] **Step 4: Implementar `SESSION_SCOPE_FILE`**

Tras `SESSION_TARGETS_FILE` (línea 12):

```bash
SESSION_SCOPE_FILE="${SESSION_SCOPE_FILE:-$SESSION_CONFIG_DIR/scope.yaml}"
```

- [ ] **Step 5: Implementar `scope_add_target`**

Signatura y reglas (cuerpo a criterio del implementador, con estas decisiones fijas):

```bash
# scope_add_target <ip|dominio>
#   0 añadido o ya estaba · 1 no válido · 2 no se pudo escribir
scope_add_target() { ... }
```

- `validate_target "$1" || return 1`.
- Sin `"$SESSION_SCOPE_FILE"` → `return 2`.
- IP (cuatro octetos) → clave `ips`, una entrada. Dominio → clave `domains`, dos entradas:
  el valor y `*.<valor>`.
- Normalización para comparar lo existente: quitar espacios, comillas dobles/simples, `\r` y
  todo lo que siga a `#`. Comparación exacta, **sin distinguir mayúsculas**.
- Si ninguna entrada falta → `return 0` sin tocar el fichero (no crear `.bak`).
- Inserción: `awk` en dos pasadas sobre el texto (primera recoge los valores ya presentes de la
  clave; segunda imprime las líneas y, tras la última entrada de la clave, las nuevas con el
  formato `    - "valor"`). Si la clave no existe dentro de `targets:` → `return 2` y no se
  escribe nada. Se ignora cualquier aparición de la clave fuera del bloque `targets:`.
- Antes de escribir: `cp -f "$SESSION_SCOPE_FILE" "$SESSION_SCOPE_FILE.bak"`.
- Escribir a un temporal en el mismo directorio y mover al final (`cat tmp > fichero` o `mv`),
  para no dejar el YAML a medias si algo falla.
- Después de escribir: `python3 -c 'import yaml,sys;yaml.safe_load(open(sys.argv[1]))' "$fichero"`.
  Si devuelve ≠0, restaurar el `.bak`, `return 2`. Si no hay `python3`, se deja escrito.
- Los avisos van a stderr; stdout no imprime nada.

- [ ] **Step 6: Arreglar `scope_allows` para dominios sin comodín**

En el bucle de dominios (líneas 130-136), tras el `case` del comodín, añadir la coincidencia
exacta: si la entrada no contiene `*`, comparar con el objetivo ignorando mayúsculas.

- [ ] **Step 7: Verificar que pasan**

Run: `bash tests/run_tests.sh 2>&1 | tail -5`
Expected: la sección nueva sin FALLO y `fallan: 0`.

- [ ] **Step 8: Commit**

```bash
cd /home/kali/Documentos/CyberSecurity
git add CyberSecurity-Framework/00_Config/lib/session.bash CyberSecurity-Framework/tests/run_tests.sh
git commit -m "feat(session): registrar el objetivo en scope.yaml sin duplicados"
```

---

### Task 2: `targets_add_entry`

**Files:**
- Modify: `CyberSecurity-Framework/00_Config/lib/session.bash` (tras `targets_from_config`, línea 85)
- Test: `CyberSecurity-Framework/tests/run_tests.sh` (misma sección nueva)

**Interfaces:**
- Consumes: `validate_target`; `SESSION_TARGETS_FILE` (ya existe).
- Produces: `targets_add_entry <host>` → `0` añadido o ya estaba · `1` no válido · `2` no se pudo escribir.

- [ ] **Step 1: Escribir los tests (deben fallar)**

```bash
section "El objetivo se registra en targets.txt"
printf '192.168.1.10|22|SSH|Servidor|C\n' > "$TMPD/targets.txt"
export SESSION_TARGETS_FILE="$TMPD/targets.txt"
targets_add_entry example.com;  eq "añade el objetivo"    "$?" "0"
eq "usa el formato de 5 campos" \
   "$(grep -cE '^example\.com\|—\|—\|Registrado al fijar el objetivo\|B$' "$TMPD/targets.txt")" "1"
eq "pone cabecera fechada"     "$(grep -cE '^# ─── AÑADIDOS POR EL GESTOR \([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}\) ───$' "$TMPD/targets.txt")" "1"
antes=$(wc -l < "$TMPD/targets.txt")
targets_add_entry example.com
eq "no duplica"                "$(wc -l < "$TMPD/targets.txt")" "$antes"
printf 'sin-salto|80|HTTP|x|B' > "$TMPD/sin_salto.txt"
SESSION_TARGETS_FILE="$TMPD/sin_salto.txt" targets_add_entry ejemplo.org
eq "no pega la línea a la anterior" "$(grep -c '^sin-salto|80|HTTP|x|B$' "$TMPD/sin_salto.txt")" "1"
targets_add_entry "malo con espacios"; eq "rechaza un valor inválido" "$?" "1"
rm -f "$TMPD/nuevo.txt"
SESSION_TARGETS_FILE="$TMPD/nuevo.txt" targets_add_entry ejemplo.net
eq "crea el fichero si no existe" "$(grep -c '^#  LISTA DE OBJETIVOS$' "$TMPD/nuevo.txt")" "1"
python3 "$FW/00_Config/scripts/parse_targets.py" --input "$TMPD/targets.txt" --json "$TMPD/t.json" >/dev/null 2>&1
eq "parse_targets.py lo entiende" \
   "$(python3 -c "import json;d=json.load(open('$TMPD/t.json'));print([t['port'] for t in d if t['ip']=='example.com'][0])")" "None"
export SESSION_TARGETS_FILE="$TMPD/targets.txt"
```

- [ ] **Step 2: Verificar que fallan**

Run: `bash tests/run_tests.sh 2>&1 | grep -A2 'registra en targets'`
Expected: FALLO / `command not found`.

- [ ] **Step 3: Implementar `targets_add_entry`**

```bash
# targets_add_entry <host>
#   0 añadido o ya estaba · 1 no válido · 2 no se pudo escribir
targets_add_entry() { ... }
```

- `validate_target "$1" || return 1`.
- Ya presente: alguna línea del fichero que empiece por `<host>|` (sin distinguir
  mayúsculas) → `return 0` sin escribir.
- Cabecera `# ─── AÑADIDOS POR EL GESTOR (YYYY-MM-DD HH:MM) ───` **solo** si la última línea
  del fichero no es ya una cabecera del gestor con la misma fecha (evita una cabecera por
  objetivo).
- Línea de entrada, exacta:
  `<host>|—|—|Registrado al fijar el objetivo|B`.
- Si el fichero no existe: crearlo con las cuatro líneas de cabecera estándar de
  `config_wizard.sh` (`wz_header`) y luego la sección fechada. No crear `.bak` (solo se añade).
- Si el fichero no acaba en salto de línea, añadir uno antes de la cabecera.
- Error de escritura → `return 2` con aviso a stderr.

- [ ] **Step 4: Verificar que pasan**

Run: `bash tests/run_tests.sh 2>&1 | tail -5`
Expected: `fallan: 0`.

- [ ] **Step 5: Commit**

```bash
cd /home/kali/Documentos/CyberSecurity
git add CyberSecurity-Framework/00_Config/lib/session.bash CyberSecurity-Framework/tests/run_tests.sh
git commit -m "feat(session): registrar el objetivo en targets.txt"
```

---

### Task 3: Enganchar en `session_set_target`, avisar en el gestor y documentar

**Files:**
- Modify: `CyberSecurity-Framework/00_Config/lib/session.bash` (`session_set_target`, líneas 45-48)
- Modify: `CyberSecurity-Framework/cyber_framework.sh` (`change_target`, líneas 165-190)
- Modify: `tests/run_e2e.sh` (aislar `SESSION_SCOPE_FILE` en la copia del framework, si no lo está)
- Modify: `AGENTS.md`, `docs/MANUAL-GESTOR.md`
- Test: `CyberSecurity-Framework/tests/run_tests.sh` (assert de integración)

**Interfaces:**
- Consumes: `scope_add_target`, `targets_add_entry` (Tasks 1 y 2).
- Produces: `session_set_target` mantiene su contrato (0/1) y añade los dos efectos laterales.

- [ ] **Step 1: Test de integración (debe fallar)**

```bash
section "session_set_target registra en los dos ficheros"
cp "$FW/00_Config/scope.yaml" "$TMPD/scope2.yaml"
printf '' > "$TMPD/targets2.txt"
SESSION_SCOPE_FILE="$TMPD/scope2.yaml" SESSION_TARGETS_FILE="$TMPD/targets2.txt" \
    session_set_target integra.com
eq "scope.yaml recibe el dominio" "$(grep -c 'integra.com' "$TMPD/scope2.yaml")" "2"
eq "targets.txt recibe el dominio" "$(grep -c '^integra\.com|' "$TMPD/targets2.txt")" "1"
```

- [ ] **Step 2: Verificar que falla**

Run: `bash tests/run_tests.sh 2>&1 | grep -A2 'registra en los dos'`
Expected: dos FALLO (0 líneas encontradas).

- [ ] **Step 3: Enganchar**

En `session_set_target`, tras escribir `.session`:

```bash
    printf '%s\n' "$1" > "$SESSION_FILE" || return 1
    # El registro es informativo: si falla, la sesión sigue siendo válida.
    scope_add_target "$1" || printf '⚠️  No se pudo registrar en scope.yaml (código %s)\n' "$?" >&2
    targets_add_entry "$1" || printf '⚠️  No se pudo registrar en targets.txt (código %s)\n' "$?" >&2
    return 0
```

Ojo: `$?` se evalúa tras la función; capturarlo en una variable antes de usarlo en `printf`
si el mensaje debe llevar el código real (en ese caso, `local rc=$?`).

- [ ] **Step 4: Avisar en el gestor**

En `change_target` (`cyber_framework.sh`), tras el `✅ Objetivo guardado:` de las dos ramas,
informar de lo registrado solo si había algo nuevo. La forma más simple sin duplicar lógica:
`scope_add_target` imprime a stderr una línea por entrada añadida
(`➕ scope.yaml: dominio, *.dominio`) y nada si ya estaba; el gestor no filtra nada. Ajustar
Task 1 para que esos avisos salgan por stderr y se vean en la terminal.

- [ ] **Step 5: Aislar la copia del e2e**

En `tests/run_e2e.sh`, tras copiar el framework, exportar
`SESSION_SCOPE_FILE="$COPIA/00_Config/scope.yaml"` y `SESSION_TARGETS_FILE="$COPIA/00_Config/targets.txt"`
si no lo están ya, para que `session_set_target "10.9.9.9"` (línea 103) escriba en la copia.

- [ ] **Step 6: Verificar todas las suites**

Run:
```bash
bash tests/run_tests.sh 2>&1 | tail -3
bash tests/run_e2e.sh 2>&1 | tail -3
bash tests/run_smoke.sh 2>&1 | tail -3
```
Expected: `fallan: 0` / sin FALLO / sin FALLO. Además:
`git diff --stat CyberSecurity-Framework/00_Config/scope.yaml CyberSecurity-Framework/00_Config/targets.txt`
debe salir vacío (las suites no tocan los reales).

- [ ] **Step 7: Documentar**

- `AGENTS.md`: una línea en «Current state» y, en la sección del gestor, que
  `session_set_target` escribe en `.session`, `scope.yaml` y `targets.txt`.
- `docs/MANUAL-GESTOR.md`: qué pasa al fijar el objetivo y cómo deshacerlo (editar el YAML o
  borrar la línea de `targets.txt`; no hay comando de borrado).
- `docs/ORIGEN-AUTOMATICO-2026-11-06.md`: aproximación, decisiones y evidencia (salida real de
  los tests), siguiendo el estilo de los demás `docs/`.

- [ ] **Step 8: Commit**

```bash
cd /home/kali/Documentos/CyberSecurity
git add -A CyberSecurity-Framework/00_Config/lib/session.bash CyberSecurity-Framework/cyber_framework.sh \
          CyberSecurity-Framework/tests AGENTS.md docs
git commit -m "feat(gestor): registrar el objetivo en scope.yaml y targets.txt al fijarlo"
```
