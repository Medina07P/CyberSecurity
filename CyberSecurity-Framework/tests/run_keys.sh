#!/bin/bash
# Pruebas de 00_Config/scripts/api_keys.py — sin terminal y sin tocar nada real
FW="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEYS="$FW/00_Config/scripts/api_keys.py"
FIXTURE_HT="$FW/tests/fixtures/theharvester-api-keys.yaml"
REAL_HOME="$(python3 -c 'import os,pwd;print(pwd.getpwuid(os.getuid()).pw_dir)')"
TMPD="$(mktemp -d)"; trap 'rm -rf "$TMPD"' EXIT
export HOME="$TMPD/home"; mkdir -p "$HOME"
export KEYS_FILE="$TMPD/registro.yaml"
export KEYS_HARVESTER_DIRS="$TMPD/ht:$TMPD/etc"
export KEYS_HARVESTER_TEMPLATE="$FIXTURE_HT"
pasan=0; fallan=0
ok()  { echo "  ok   $1"; pasan=$((pasan+1)); }
ko()  { echo "  FALLO $1"; fallan=$((fallan+1)); }
eq()  { [[ "$2" == "$3" ]] && ok "$1" || ko "$1 (esperado '$3', obtenido '$2')"; }
py()  { python3 "$KEYS" "$@"; }
est() { python3 -c 'import json,sys;print([h for h in json.load(sys.stdin)["herramientas"] if h["nombre"]==sys.argv[1]][0]["estado"])' "$1"; }
PY="$(command -v python3)"

# Guardas: estas dos huellas se comparan al final de la suite (tarea 9)
MD5_REG_REAL=$(md5sum "$FW/00_Config/credentials/api-keys.yaml" 2>/dev/null | cut -d' ' -f1)
MD5_HT_REAL=$(md5sum "$REAL_HOME/.theHarvester/api-keys.yaml" 2>/dev/null | cut -d' ' -f1)

echo ""; echo "=== registro y campos ==="
out=$(py poner theharvester shodan.key sk-prueba-123456 2>&1)
eq "poner guarda la clave" "$(py estado --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["herramientas"][0]["campos"][0]["longitud"])')" "16"
[[ "$(stat -c %a "$KEYS_FILE")" == "600" ]] && ok "registro 600" || ko "registro 600"
python3 -c "import yaml;yaml.safe_load(open('$KEYS_FILE'))" && ok "YAML válido" || ko "YAML válido"
[[ "$(python3 -c "import yaml;print(len(yaml.safe_load(open('$KEYS_FILE'))['theharvester']))")" == "3" ]] \
    && ok "sembrado desde la plantilla" || ko "sembrado desde la plantilla"

# Recorte de espacios y rechazo de un valor con salto de línea
py poner theharvester dehashed.key '  sk-con-espacios-123456  ' >/dev/null 2>&1
eq "recorta espacios" "$(python3 -c "import yaml;print(yaml.safe_load(open('$KEYS_FILE'))['theharvester']['dehashed']['key'])")" "sk-con-espacios-123456"
printf 's\nk\n' | py poner theharvester dehashed.key --stdin >/dev/null 2>&1
eq "rechaza salto de línea" "$?" "1"
py poner theharvester inexistente.key valor >/dev/null 2>&1; eq "campo desconocido: 1" "$?" "1"
# Un registro ilegible no se sobrescribe
cp "$KEYS_FILE" "$TMPD/registro.bueno"
printf 'esto: [no es yaml\n' > "$KEYS_FILE"
py poner theharvester shodan.key otro-valor >/dev/null 2>&1; eq "registro ilegible: 2" "$?" "2"
eq "registro ilegible intacto" "$(cat "$KEYS_FILE")" "esto: [no es yaml"
cp "$TMPD/registro.bueno" "$KEYS_FILE"

# Errores de uso deben salir con 1, no con 2
py poner theharvester shodan.key >/dev/null 2>&1; eq "falta valor: uso sale 1" "$?" "1"
py poner >/dev/null 2>&1; eq "sin argumentos: uso sale 1" "$?" "1"

# Registro que parsea a no-dict se trata como ilegible (sale 2, intacto)
printf -- '- uno\n- dos\n' > "$KEYS_FILE"
py poner theharvester shodan.key valor >/dev/null 2>&1; eq "registro no-dict: 2" "$?" "2"
eq "registro no-dict intacto" "$(cat "$KEYS_FILE")" "- uno
- dos"
cp "$TMPD/registro.bueno" "$KEYS_FILE"

echo ""; echo "=== theHarvester ==="
py poner theharvester censys.id censys-id-123456 >/dev/null 2>&1
py poner theharvester censys.secret censys-secret-123456 >/dev/null 2>&1
HT="$HOME/.theHarvester/api-keys.yaml"
[[ -f "$HT" ]] && ok "proyecta en ~/.theHarvester" || ko "proyecta en ~/.theHarvester"
eq "espejo: 3 huecos" "$(python3 -c "import yaml;print(len(yaml.safe_load(open('$HT'))['apikeys']))")" "3"
eq "espejo: censys.secret" "$(python3 -c "import yaml;print(yaml.safe_load(open('$HT'))['apikeys']['censys']['secret'])")" "censys-secret-123456"
[[ "$(stat -c %a "$HT")" == "600" ]] && ok "proyección 600" || ko "proyección 600"
[[ -f "$HT.bak" ]] && ok "theHarvester deja .bak" || ko "theHarvester deja .bak"
[[ "$(stat -c %a "$HT.bak")" == "600" ]] && ok "theHarvester .bak 600" || ko "theHarvester .bak 600"
# Gana ~ sobre el /etc simulado
mkdir -p "$TMPD/etc"; printf 'apikeys:\n  shodan:\n    key: del-etc\n' > "$TMPD/etc/api-keys.yaml"
MD5_ETC=$(md5sum "$TMPD/etc/api-keys.yaml" | cut -d' ' -f1)
py poner theharvester shodan.key sk-propia-123456 >/dev/null 2>&1
eq "~ gana al /etc" "$(python3 -c "import yaml;print(yaml.safe_load(open('$HT'))['apikeys']['shodan']['key'])")" "sk-propia-123456"
eq "/etc simulado intacto" "$(md5sum "$TMPD/etc/api-keys.yaml" | cut -d' ' -f1)" "$MD5_ETC"
# Un valor ajeno no vacío que el registro no conoce se conserva y se ingiere
py poner theharvester dehashed.key - >/dev/null 2>&1
python3 - "$HT" <<'EOS'
import sys, yaml
p = sys.argv[1]; d = yaml.safe_load(open(p))
d["apikeys"]["dehashed"]["key"] = "ajena-123456"
yaml.safe_dump(d, open(p, "w"), sort_keys=False)
EOS
py sincronizar theharvester >/dev/null 2>&1
eq "conserva la ajena" "$(python3 -c "import yaml;print(yaml.safe_load(open('$HT'))['apikeys']['dehashed']['key'])")" "ajena-123456"
py importar theharvester >/dev/null 2>&1
eq "importar la trae" "$(python3 -c "import yaml;print(yaml.safe_load(open('$KEYS_FILE'))['theharvester']['dehashed']['key'])")" "ajena-123456"
# Valor con caracteres que rompen YAML
py poner theharvester hunter.key 'a#b:c "d"' >/dev/null 2>&1
eq "valor con # y comillas" "$(python3 -c "import yaml;print(yaml.safe_load(open('$HT'))['apikeys']['hunter']['key'])")" 'a#b:c "d"'
# Estado por defecto (sin KEYS_HARVESTER_DIRS): aunque exista /etc, escribe en ~
SAVED_DIRS="$KEYS_HARVESTER_DIRS"
unset KEYS_HARVESTER_DIRS
rm -rf "$HOME/.theHarvester"
py poner theharvester censys.id default-censys-id >/dev/null 2>&1
[[ -f "$HOME/.theHarvester/api-keys.yaml" ]] && ok "default escribe en ~" || ko "default escribe en ~"
export KEYS_HARVESTER_DIRS="$SAVED_DIRS"
# Fallo de proyección: advertencia y exit 3, registro igualmente guardado
rm -rf "$HOME/.theHarvester"
mkdir -p "$HOME/.theHarvester"
chmod 500 "$HOME/.theHarvester"
out=$(py poner theharvester shodan.key sk-falla-123456 2>&1)
code=$?
chmod 700 "$HOME/.theHarvester"
eq "fallo de proyección: exit 3" "$code" "3"
[[ "$out" == *"theHarvester: no se pudo escribir"* ]] && ok "fallo de proyección: aviso" || ko "fallo de proyección: aviso"
eq "fallo de proyección: registro guardado" "$(python3 -c "import yaml;print(yaml.safe_load(open('$KEYS_FILE'))['theharvester']['shodan']['key'])")" "sk-falla-123456"
# Proyección no-dict: aviso en español, no revienta, no sobrescribe
printf -- '- uno\n' > "$HOME/.theHarvester/api-keys.yaml"
chmod 600 "$HOME/.theHarvester/api-keys.yaml"
md5_antes=$(md5sum "$HOME/.theHarvester/api-keys.yaml" | cut -d' ' -f1)
out=$(py sincronizar theharvester 2>&1)
code=$?
eq "proyección no-dict: exit 3" "$code" "3"
[[ "$out" == *"no contiene un diccionario"* ]] && ok "proyección no-dict: mensaje" || ko "proyección no-dict: mensaje"
md5_despues=$(md5sum "$HOME/.theHarvester/api-keys.yaml" | cut -d' ' -f1)
eq "proyección no-dict: sin sobrescribir" "$md5_despues" "$md5_antes"

echo ""; echo "=== shodan y h8mail ==="
py poner shodan key shodan-key-123456 >/dev/null 2>&1
eq "shodan: contenido" "$(cat "$HOME/.shodan/api_key")" "shodan-key-123456"
[[ "$(stat -c %a "$HOME/.shodan/api_key")" == "600" ]] && ok "shodan 600" || ko "shodan 600"
[[ "$(stat -c %a "$HOME/.shodan")" == "700" ]] && ok "shodan dir 700" || ko "shodan dir 700"
py poner h8mail dehashed_key h8-dehashed-123456 >/dev/null 2>&1
py poner h8mail hibp hibp-key-123456 >/dev/null 2>&1
INI="$HOME/.h8mail_config.ini"
[[ -f "$INI" ]] && ok "h8mail: escribe el INI" || ko "h8mail: escribe el INI"
eq "h8mail: sección" "$(python3 -c "import configparser;c=configparser.ConfigParser();c.read('$INI');print(c['h8mail']['dehashed_key'])")" "h8-dehashed-123456"
[[ "$(stat -c %a "$INI")" == "600" ]] && ok "h8mail 600" || ko "h8mail 600"
# .bak antes de sustituir
py poner shodan key shodan-key-999999 >/dev/null 2>&1
[[ -f "$HOME/.shodan/api_key.bak" ]] && ok "shodan deja .bak" || ko "shodan deja .bak"
eq "shodan: valor nuevo" "$(cat "$HOME/.shodan/api_key")" "shodan-key-999999"
# importar desde fichero
py poner shodan key - >/dev/null 2>&1
rm -rf "$HOME/.shodan"; mkdir -p "$HOME/.shodan"
printf 'shodan-importada-123456\n' > "$HOME/.shodan/api_key"
py importar shodan >/dev/null 2>&1
eq "importar shodan" "$(python3 -c "import yaml;print(yaml.safe_load(open('$KEYS_FILE'))['shodan']['key'])")" "shodan-importada-123456"
py poner h8mail hibp - >/dev/null 2>&1
rm -f "$INI"
printf '[h8mail]\nhibp=hibp-importada-123456\n' > "$INI"; chmod 600 "$INI"
py importar h8mail >/dev/null 2>&1
eq "importar h8mail" "$(python3 -c "import yaml;print(yaml.safe_load(open('$KEYS_FILE'))['h8mail']['hibp'])")" "hibp-importada-123456"
# %-survival en h8mail
py poner h8mail intelx_key 'abc%def' >/dev/null 2>&1
eq "h8mail: porcentaje sobrevive" "$(python3 -c "import configparser;c=configparser.ConfigParser(interpolation=None);c.read('$INI');print(c['h8mail']['intelx_key'])")" "abc%def"
# estado exacto
out=$(py poner h8mail dehashed_key h8-dehashed-123456 2>&1)
[[ "$out" == *"puesta (h8mail necesita -c)"* ]] && ok "h8mail: status exacto" || ko "h8mail: status exacto"
# h8mail .bak
[[ -f "$INI.bak" ]] && ok "h8mail deja .bak" || ko "h8mail deja .bak"
[[ "$(stat -c %a "$INI.bak")" == "600" ]] && ok "h8mail .bak 600" || ko "h8mail .bak 600"
# conservación: shodan (vía sincronizar, con el registro sin ese valor)
rm -rf "$HOME/.shodan"; mkdir -p "$HOME/.shodan"
printf 'shodan-conservada-123456\n' > "$HOME/.shodan/api_key"
KEYS_SAVE="$KEYS_FILE"; export KEYS_FILE="$TMPD/registro-shodan.yaml"
py sincronizar shodan >/dev/null 2>&1
eq "shodan: conserva valor ajeno" "$(cat "$HOME/.shodan/api_key")" "shodan-conservada-123456"
export KEYS_FILE="$KEYS_SAVE"
# conservación: h8mail, un campo ajeno sobrevive a poner otro
py poner h8mail dehashed_key - >/dev/null 2>&1
rm -f "$INI"
printf '[h8mail]\nhibp=hibp-ajena-123456\ndehashed_key=dehashed-ajena-123456\n' > "$INI"; chmod 600 "$INI"
py poner h8mail hibp hibp-nueva-123456 >/dev/null 2>&1
eq "h8mail: conserva dehashed ajena" "$(python3 -c "import configparser;c=configparser.ConfigParser(interpolation=None);c.read('$INI');print(c['h8mail']['dehashed_key'])")" "dehashed-ajena-123456"
eq "h8mail: actualiza hibp" "$(python3 -c "import configparser;c=configparser.ConfigParser(interpolation=None);c.read('$INI');print(c['h8mail']['hibp'])")" "hibp-nueva-123456"

echo ""; echo "=== amass (v5) ==="
py poner amass shodan.key amass-shodan-123456 >/dev/null 2>&1; eq "sin fichero: código 3" "$?" "3"
[[ -e "$HOME/.config/amass/datasources.yaml" ]] && ko "no inventa el fichero" || ok "no inventa el fichero"
mkdir -p "$HOME/.config/amass"
cat > "$HOME/.config/amass/datasources.yaml" <<'EOS'
datasources:
  - name: shodan
    ttl: 4320
    creds:
      key: ""
  - name: censys
    ttl: 4320
    creds:
      id: ""
      secret: ""
  - name: crtsh
    ttl: 4320
EOS
py poner amass shodan.key amass-shodan-123456 >/dev/null 2>&1
eq "fusiona creds.key" "$(python3 -c "import yaml;d=yaml.safe_load(open('$HOME/.config/amass/datasources.yaml'));print([x for x in d['datasources'] if x['name']=='shodan'][0]['creds']['key'])")" "amass-shodan-123456"
eq "no toca otras fuentes" "$(python3 -c "import yaml;d=yaml.safe_load(open('$HOME/.config/amass/datasources.yaml'));print(len(d['datasources']))")" "3"
py poner amass securitytrails.key st-123456 >/dev/null 2>&1
eq "fuente desconocida: no se inventa" "$(python3 -c "import yaml;d=yaml.safe_load(open('$HOME/.config/amass/datasources.yaml'));print(len(d['datasources']))")" "3"
# fichero ilegible por permisos: aviso en español, código 3, sin traceback
chmod 000 "$HOME/.config/amass/datasources.yaml"
out=$(py poner amass shodan.key amass-ilegible-123456 2>&1)
code=$?
chmod 600 "$HOME/.config/amass/datasources.yaml"
eq "fichero ilegible: código 3" "$code" "3"
[[ "$out" == *"amass: no se pudo leer"* ]] && ok "fichero ilegible: aviso en español" || ko "fichero ilegible: aviso en español"
[[ "$out" != *"Traceback"* ]] && ok "fichero ilegible: sin traceback" || ko "fichero ilegible: sin traceback"
# importar amass round-trip (registro nuevo, para que el campo esté vacío)
printf 'datasources:\n  - name: shodan\n    ttl: 4320\n    creds:\n      key: "importada-amass-123456"\n' > "$HOME/.config/amass/datasources.yaml"; chmod 600 "$HOME/.config/amass/datasources.yaml"
KEYS_SAVE="$KEYS_FILE"; export KEYS_FILE="$TMPD/registro-amass.yaml"
py importar amass >/dev/null 2>&1
eq "importar amass" "$(python3 -c "import yaml;print(yaml.safe_load(open('$KEYS_FILE'))['amass']['shodan']['key'])")" "importada-amass-123456"
export KEYS_FILE="$KEYS_SAVE"
# entrada con name no-string no rompe el merge
printf 'datasources:\n  - name: 123\n    ttl: 4320\n  - name: shodan\n    ttl: 4320\n    creds:\n      key: ""\n' > "$HOME/.config/amass/datasources.yaml"; chmod 600 "$HOME/.config/amass/datasources.yaml"
py poner amass shodan.key amass-malformado-123456 >/dev/null 2>&1
eq "name no-string no rompe" "$?" "0"
eq "name no-string: merge sigue" "$(python3 -c "import yaml;d=yaml.safe_load(open('$HOME/.config/amass/datasources.yaml'));print([x for x in d['datasources'] if isinstance(x.get('name'),str) and x['name']=='shodan'][0]['creds']['key'])")" "amass-malformado-123456"

echo ""; echo "=== recon-ng y spiderfoot ==="
py poner recon-ng shodan_api rn-shodan-123456 >/dev/null 2>&1 && ko "no escribe sin base" || ok "no escribe sin base"
[[ -e "$HOME/.recon-ng/keys.db" ]] && ko "no crea la base de recon-ng" || ok "no crea la base de recon-ng"
mkdir -p "$HOME/.recon-ng"
python3 -c "import sqlite3;c=sqlite3.connect('$HOME/.recon-ng/keys.db');c.execute('CREATE TABLE keys (name TEXT PRIMARY KEY, value TEXT)');c.commit()"
py poner recon-ng shodan_api rn-shodan-123456 >/dev/null 2>&1
eq "recon-ng: fila" "$(python3 -c "import sqlite3;print(sqlite3.connect('$HOME/.recon-ng/keys.db').execute(\"select value from keys where name='shodan_api'\").fetchone()[0])")" "rn-shodan-123456"
mkdir -p "$HOME/.spiderfoot"
python3 -c "import sqlite3;c=sqlite3.connect('$HOME/.spiderfoot/spiderfoot.db');c.execute('CREATE TABLE tbl_config (scope TEXT, opt TEXT, val TEXT, UNIQUE(scope,opt))');c.commit()"
py poner spiderfoot sfp_shodan.api_key sf-shodan-123456 >/dev/null 2>&1
eq "spiderfoot: scope/opt" "$(python3 -c "import sqlite3;print(sqlite3.connect('$HOME/.spiderfoot/spiderfoot.db').execute(\"select val from tbl_config where scope='sfp_shodan' and opt='api_key'\").fetchone()[0])")" "sf-shodan-123456"

echo ""; echo "=== estado, faltan, divergencia ==="
py --help >/dev/null 2>&1 || ko "hay ayuda"
# estado no escribe nada ni crea el registro
rm -f "$KEYS_FILE"
py estado >/dev/null 2>&1
[[ -e "$KEYS_FILE" ]] && ko "estado no crea el registro" || ok "estado no crea el registro"
py poner theharvester shodan.key shodan-estado-123456 >/dev/null 2>&1
# h8mail con un único valor, para que su estado sea el del recordatorio del -c
rm -f "$HOME/.h8mail_config.ini"
py poner h8mail hibp hibp-tabla-123456 >/dev/null 2>&1
out=$(py estado)
printf '%s' "$out" | grep -q 'theHarvester' && ok "estado lista theHarvester" || ko "estado lista theHarvester"
printf '%s' "$out" | grep -q 'recon-ng' && ok "estado lista recon-ng" || ko "estado lista recon-ng"
printf '%s' "$out" | grep -q 'h8mail necesita -c' && ok "estado avisa del -c de h8mail" || ko "estado avisa del -c de h8mail"
eq "h8mail: estado en la tabla" "$(py estado --json | est h8mail)" "puesta (h8mail necesita -c)"
# Fichero/base con valores que el registro no explica: divergen aunque el registro esté vacío
eq "amass con valores ajenos diverge" "$(py estado --json | est amass)" "diverge"
eq "recon-ng con valores ajenos diverge" "$(py estado --json | est recon-ng)" "diverge"
# vacía: la herramienta está inicializada y no hay valor ni en el registro ni en su fichero
rm -rf "$HOME/.shodan"; mkdir -p "$HOME/.shodan"; : > "$HOME/.shodan/api_key"
eq "shodan vacía" "$(py estado --json | est shodan)" "vacía"
# sin inicializar: hay binario pero ni fichero ni base; sin binario tampoco, es no instalada
mkdir -p "$TMPD/bin3"; printf '#!/bin/sh\n' > "$TMPD/bin3/amass"; chmod +x "$TMPD/bin3/amass"
eq "con binario y sin fichero: sin inicializar" "$(HOME="$TMPD/home3" PATH="$TMPD/bin3" "$PY" "$KEYS" estado --json | est amass)" "sin inicializar"
eq "sin binario ni fichero: no instalada" "$(HOME="$TMPD/home3" PATH="$TMPD/bin3" "$PY" "$KEYS" estado --json | est shodan)" "no instalada"
eq "sin binarios: no instalada" "$(HOME="$TMPD/home2" PATH="$TMPD/bin" "$PY" "$KEYS" estado --json | python3 -c 'import json,sys;print({h["estado"] for h in json.load(sys.stdin)["herramientas"]})')" "{'no instalada'}"
py estado --faltan theharvester >/dev/null 2>&1 && ko "faltan: 0 si falta alguna" || ok "faltan: código 1 si falta alguna"
py estado --faltan inexistente >/dev/null 2>&1; eq "faltan: código 2 si no existe" "$?" "2"
py poner theharvester hunter.key hunter-key-123456 >/dev/null 2>&1
py estado --faltan theharvester >/dev/null 2>&1 && ko "faltan: sigue faltando shodan" || ok "faltan: sigue faltando shodan"
# divergencia: valor ajeno no vacío
python3 - "$HOME/.theHarvester/api-keys.yaml" <<'EOS'
import sys, yaml
p = sys.argv[1]; d = yaml.safe_load(open(p)); d["apikeys"]["censys"]["id"] = "ajena-123456"
yaml.safe_dump(d, open(p, "w"), sort_keys=False)
EOS
eq "diverge" "$(py estado --json | est theharvester)" "diverge"
py importar theharvester >/dev/null 2>&1
eq "importar quita la divergencia" "$(py estado --json | est theharvester)" "puesta (sin verificar)"
# seguridad: ninguna salida contiene el valor
py poner shodan key SUPER-SECRETO-999999 >/dev/null 2>&1
for o in estado "estado --json" "estado --faltan theharvester"; do
    py $o 2>&1 | grep -q 'SUPER-SECRETO-999999' && ko "no filtra en '$o'" || ok "no filtra en '$o'"
done

# sincronizar no fabrica ficheros vacíos para herramientas sin valores
H4="$TMPD/home4"; mkdir -p "$H4" "$TMPD/ht4"
HOME="$H4" KEYS_HARVESTER_DIRS="$TMPD/ht4" KEYS_FILE="$TMPD/reg4.yaml" "$PY" "$KEYS" sincronizar >/dev/null 2>&1
[[ -e "$H4/.shodan/api_key" ]] && ko "sincronizar no crea shodan vacío" || ok "sincronizar no crea shodan vacío"
[[ -e "$H4/.h8mail_config.ini" ]] && ko "sincronizar no crea h8mail vacío" || ok "sincronizar no crea h8mail vacío"
[[ -e "$H4/.theHarvester/api-keys.yaml" ]] && ko "sincronizar no crea theHarvester vacío" || ok "sincronizar no crea theHarvester vacío"
HOME="$H4" KEYS_HARVESTER_DIRS="$TMPD/ht4" KEYS_FILE="$TMPD/reg4.yaml" "$PY" "$KEYS" poner shodan key sk-solo-123456 >/dev/null 2>&1
HOME="$H4" KEYS_HARVESTER_DIRS="$TMPD/ht4" KEYS_FILE="$TMPD/reg4.yaml" "$PY" "$KEYS" sincronizar >/dev/null 2>&1
[[ -f "$H4/.shodan/api_key" ]] && ok "sincronizar escribe la que sí tiene valores" || ko "sincronizar escribe la que sí tiene valores"
[[ -e "$H4/.h8mail_config.ini" ]] && ko "sincronizar sigue sin crear h8mail" || ok "sincronizar sigue sin crear h8mail"

echo ""; echo "=== pedir ==="
# Por tubería: cae a stdin, no se cuelga, guarda y confirma con longitud
py poner shodan key - >/dev/null 2>&1
out=$(printf 'shodan-pipe-123456\n' | timeout 10 "$PY" "$KEYS" pedir shodan 2>&1)
printf '%s' "$out" | grep -q 'definida (18 caracteres)' && ok "confirma con longitud" || ko "confirma con longitud"
printf '%s' "$out" | grep -q 'shodan-pipe-123456' && ko "no imprime el valor" || ok "no imprime el valor"
eq "guardó lo tecleado" "$(cat "$HOME/.shodan/api_key")" "shodan-pipe-123456"
printf '\n' | timeout 10 "$PY" "$KEYS" pedir shodan --campo key 2>&1 | grep -q 'sin terminal' && ok "avisa del eco" || ko "avisa del eco"
# Sin --campo solo pide lo que falta: con todo puesto no pregunta y no pisa nada
out=$(printf 'otro-valor-123456\n' | timeout 10 "$PY" "$KEYS" pedir shodan 2>&1)
printf '%s' "$out" | grep -q 'no queda ningún campo vacío' && ok "sin --campo solo pide lo vacío" || ko "sin --campo solo pide lo vacío"
eq "no pisa lo ya puesto" "$(cat "$HOME/.shodan/api_key")" "shodan-pipe-123456"
# Enter deja como está; '-' borra
printf '\n' | timeout 10 "$PY" "$KEYS" pedir shodan --campo key >/dev/null 2>&1
eq "Enter conserva" "$(cat "$HOME/.shodan/api_key")" "shodan-pipe-123456"
printf -- '-\n' | timeout 10 "$PY" "$KEYS" pedir shodan --campo key >/dev/null 2>&1
eq "'-' borra" "$(cat "$HOME/.shodan/api_key")" ""
# valor inválido: espacios internos no son una clave
printf 'a b c\n' | timeout 10 "$PY" "$KEYS" pedir shodan --campo key >/dev/null 2>&1; eq "espacios internos" "$?" "1"
py pedir inexistente >/dev/null 2>&1; eq "herramienta desconocida: 1" "$?" "1"
printf 'x\n' | timeout 10 "$PY" "$KEYS" pedir shodan --campo noexiste >/dev/null 2>&1; eq "campo desconocido: 1" "$?" "1"
# --campo concreto
printf 'hunter-campo-123456\n' | timeout 10 "$PY" "$KEYS" pedir theharvester --campo hunter.key >/dev/null 2>&1
eq "pedir --campo" "$(python3 -c "import yaml;print(yaml.safe_load(open('$KEYS_FILE'))['theharvester']['hunter']['key'])")" "hunter-campo-123456"
# '-' borra de verdad: también del fichero de la herramienta
py poner shodan key shodan-borrar-123456 >/dev/null 2>&1
out=$(py poner shodan key - 2>&1)
[[ "$out" == *"borrada"* ]] && ok "poner - lo anuncia" || ko "poner - lo anuncia"
eq "poner - vacía el fichero" "$(cat "$HOME/.shodan/api_key")" ""
py importar inexistente >/dev/null 2>&1; eq "importar desconocida: 2" "$?" "2"

echo ""; echo "=== robustez: herramientas, /etc y ficheros raros ==="
# sincronizar con una herramienta inexistente: error de uso, sin traza
out=$(py sincronizar inexistente 2>&1); code=$?
eq "sincronizar desconocida: 2" "$code" "2"
[[ "$out" != *"Traceback"* ]] && ok "sincronizar desconocida: sin traceback" || ko "sincronizar desconocida: sin traceback"

# claves que solo están en /etc: se absorben al registro antes de crear ~
H5="$TMPD/home5"; ETC5="$TMPD/etc5"; R5="$TMPD/reg5.yaml"
mkdir -p "$H5" "$ETC5"
printf 'apikeys:\n  shodan:\n    key: "etc-shodan-123456"\n  censys:\n    id: "etc-censys-123456"\n    secret: ""\n' > "$ETC5/api-keys.yaml"
out=$(HOME="$H5" KEYS_HARVESTER_DIRS="$ETC5" KEYS_FILE="$R5" "$PY" "$KEYS" poner theharvester hunter.key hunter-nueva-123456 2>&1)
printf '%s' "$out" | grep -q '2 valores de' && ok "absorbe /etc: lo anuncia" || ko "absorbe /etc: lo anuncia"
eq "absorbe /etc: al registro" "$(python3 -c "import yaml;print(yaml.safe_load(open('$R5'))['theharvester']['shodan']['key'])")" "etc-shodan-123456"
eq "absorbe /etc: al fichero de ~" "$(python3 -c "import yaml;print(yaml.safe_load(open('$H5/.theHarvester/api-keys.yaml'))['apikeys']['censys']['id'])")" "etc-censys-123456"
eq "absorbe /etc: lo pedido manda" "$(python3 -c "import yaml;print(yaml.safe_load(open('$R5'))['theharvester']['hunter']['key'])")" "hunter-nueva-123456"
out=$(HOME="$H5" KEYS_HARVESTER_DIRS="$ETC5" KEYS_FILE="$R5" "$PY" "$KEYS" poner theharvester hunter.key hunter-otra-123456 2>&1)
printf '%s' "$out" | grep -q 'se importan al registro' && ko "no reabsorbe con ~ creado" || ok "no reabsorbe con ~ creado"

# theHarvester con fichero no UTF-8: aviso, código 3 y sin traza
H6="$TMPD/home6"; mkdir -p "$H6/.theHarvester"
printf '\xff\xfe\x00' > "$H6/.theHarvester/api-keys.yaml"
out=$(HOME="$H6" KEYS_FILE="$TMPD/reg6.yaml" "$PY" "$KEYS" sincronizar theharvester 2>&1); code=$?
eq "theHarvester no UTF-8: código 3" "$code" "3"
[[ "$out" != *"Traceback"* ]] && ok "theHarvester no UTF-8: sin traceback" || ko "theHarvester no UTF-8: sin traceback"
[[ "$out" == *"theHarvester: no se pudo leer"* ]] && ok "theHarvester no UTF-8: aviso en español" || ko "theHarvester no UTF-8: aviso en español"

# shodan y h8mail con ficheros no UTF-8: código 3 y sin traza
H7="$TMPD/home7"; mkdir -p "$H7/.shodan"
printf '\xff\xfe\x00' > "$H7/.shodan/api_key"
out=$(HOME="$H7" KEYS_FILE="$TMPD/reg7.yaml" "$PY" "$KEYS" poner shodan key sk-utf-123456 2>&1); code=$?
eq "shodan no UTF-8: código 3" "$code" "3"
[[ "$out" != *"Traceback"* ]] && ok "shodan no UTF-8: sin traceback" || ko "shodan no UTF-8: sin traceback"
printf '\xff\xfe\x00' > "$H7/.h8mail_config.ini"
out=$(HOME="$H7" KEYS_FILE="$TMPD/reg7.yaml" "$PY" "$KEYS" poner h8mail hibp hibp-utf-123456 2>&1); code=$?
eq "h8mail no UTF-8: código 3" "$code" "3"
[[ "$out" != *"Traceback"* ]] && ok "h8mail no UTF-8: sin traceback" || ko "h8mail no UTF-8: sin traceback"

# un registro no UTF-8 se trata como ilegible (código 2), sin traza
printf '\xff\xfe\x00' > "$TMPD/reg-binario.yaml"
out=$(KEYS_FILE="$TMPD/reg-binario.yaml" "$PY" "$KEYS" estado 2>&1); code=$?
eq "registro no UTF-8: código 2" "$code" "2"
[[ "$out" != *"Traceback"* ]] && ok "registro no UTF-8: sin traceback" || ko "registro no UTF-8: sin traceback"

# amass con un fichero no UTF-8: estado sigue funcionando, sin traza
H11="$TMPD/home11"; mkdir -p "$H11/.config/amass"
printf '\xff\xfe\x00' > "$H11/.config/amass/datasources.yaml"
out=$(HOME="$H11" KEYS_FILE="$TMPD/reg11.yaml" "$PY" "$KEYS" estado --json 2>&1); code=$?
eq "amass no UTF-8: estado sigue" "$code" "0"
[[ "$out" != *"Traceback"* ]] && ok "amass no UTF-8: sin traceback" || ko "amass no UTF-8: sin traceback"

# theHarvester con 'apikeys' que no es diccionario: código 3 y estado sin traza
H12="$TMPD/home12"; mkdir -p "$H12/.theHarvester"
printf 'apikeys: [1, 2]\n' > "$H12/.theHarvester/api-keys.yaml"
out=$(HOME="$H12" KEYS_FILE="$TMPD/reg12.yaml" "$PY" "$KEYS" sincronizar theharvester 2>&1); code=$?
eq "apikeys no-dict: código 3" "$code" "3"
[[ "$out" != *"Traceback"* ]] && ok "apikeys no-dict: sin traceback" || ko "apikeys no-dict: sin traceback"
out=$(HOME="$H12" KEYS_FILE="$TMPD/reg12.yaml" "$PY" "$KEYS" estado --json 2>&1); code=$?
eq "apikeys no-dict: estado sigue" "$code" "0"
[[ "$out" != *"Traceback"* ]] && ok "apikeys no-dict: estado sin traceback" || ko "apikeys no-dict: estado sin traceback"

# una plantilla de theHarvester con otra forma no tumba la CLI entera
printf 'solo-texto\n' > "$TMPD/plantilla-no-dict.yaml"
KEYS_HARVESTER_TEMPLATE="$TMPD/plantilla-no-dict.yaml" HOME="$H7" KEYS_FILE="$TMPD/reg7.yaml" \
    "$PY" "$KEYS" estado >/dev/null 2>&1 && ok "plantilla no-dict no tumba la CLI" || ko "plantilla no-dict no tumba la CLI"
printf '\xff\xfe\x00' > "$TMPD/plantilla-binaria.yaml"
KEYS_HARVESTER_TEMPLATE="$TMPD/plantilla-binaria.yaml" HOME="$H7" KEYS_FILE="$TMPD/reg7.yaml" \
    "$PY" "$KEYS" estado >/dev/null 2>&1 && ok "plantilla binaria no tumba la CLI" || ko "plantilla binaria no tumba la CLI"

# amass sin nada que escribir: 0, no un 3 espurio
H8="$TMPD/home8"; mkdir -p "$H8/.config/amass"
printf 'datasources:\n  - name: shodan\n    creds:\n      key: "ajena-amass-123456"\n' > "$H8/.config/amass/datasources.yaml"
out=$(HOME="$H8" KEYS_FILE="$TMPD/reg8.yaml" "$PY" "$KEYS" sincronizar amass 2>&1); code=$?
eq "amass nada que escribir: 0" "$code" "0"
printf '%s' "$out" | grep -q 'nada que escribir' && ok "amass nada que escribir: lo dice" || ko "amass nada que escribir: lo dice"

# h8mail conserva secciones y opciones que no gestiona
H9="$TMPD/home9"; mkdir -p "$H9"
printf '[h8mail]\nhibp=vieja-123456\nopcion_ajena=se-queda\n[otra]\nclave=valor-ajeno\n' > "$H9/.h8mail_config.ini"
chmod 600 "$H9/.h8mail_config.ini"
HOME="$H9" KEYS_FILE="$TMPD/reg9.yaml" "$PY" "$KEYS" poner h8mail hibp hibp-nueva-123456 >/dev/null 2>&1
eq "h8mail: actualiza la suya" "$(python3 -c "import configparser;c=configparser.ConfigParser(interpolation=None);c.read('$H9/.h8mail_config.ini');print(c['h8mail']['hibp'])")" "hibp-nueva-123456"
eq "h8mail: conserva opción ajena" "$(python3 -c "import configparser;c=configparser.ConfigParser(interpolation=None);c.read('$H9/.h8mail_config.ini');print(c['h8mail']['opcion_ajena'])")" "se-queda"
eq "h8mail: conserva sección ajena" "$(python3 -c "import configparser;c=configparser.ConfigParser(interpolation=None);c.read('$H9/.h8mail_config.ini');print(c['otra']['clave'])")" "valor-ajeno"

# clave muy corta: avisa pero no bloquea
H10="$TMPD/home10"; mkdir -p "$H10"
out=$(HOME="$H10" KEYS_FILE="$TMPD/reg10.yaml" "$PY" "$KEYS" poner shodan key corta 2>&1)
[[ "$out" == *"muy corta"* ]] && ok "clave corta: avisa" || ko "clave corta: avisa"
out=$(HOME="$H10" KEYS_FILE="$TMPD/reg10.yaml" "$PY" "$KEYS" poner shodan key sk-larga-123456 2>&1)
[[ "$out" == *"muy corta"* ]] && ko "clave larga: no avisa" || ok "clave larga: no avisa"

echo ""; echo "=== guardas ==="
eq "el registro real no cambió" "$(md5sum "$FW/00_Config/credentials/api-keys.yaml" 2>/dev/null | cut -d' ' -f1)" "$MD5_REG_REAL"
eq "el api-keys.yaml real no cambió" "$(md5sum "$REAL_HOME/.theHarvester/api-keys.yaml" 2>/dev/null | cut -d' ' -f1)" "$MD5_HT_REAL"
grep -qF '## Claves de API' "$FW/../docs/MANUAL-GESTOR.md" && ok "manual: apartado de claves" || ko "manual: apartado de claves"
grep -qF 'api-keys.yaml' "$FW/../AGENTS.md" && ok "AGENTS: menciona el registro" || ko "AGENTS: menciona el registro"
[[ -f "$FW/../docs/API-KEYS-2026-11-06.md" ]] && ok "doc del cambio" || ko "doc del cambio"
grep -qF 'api-keys.yaml' "$FW/00_Config/credentials/README.md" && ok "credentials: explica el registro" || ko "credentials: explica el registro"
grep -qF 'K|k) keys_menu' "$FW/cyber_framework.sh" && ok "gestor: opción K cableada" || ko "gestor: opción K cableada"
git -C "$FW/.." check-ignore -q "CyberSecurity-Framework/00_Config/credentials/api-keys.yaml" \
    && ok "el registro está ignorado por git" || ko "el registro está ignorado por git"

echo ""
echo "----------------------------------------"
echo "pasan: $pasan   fallan: $fallan"
[[ "$fallan" -eq 0 ]]
