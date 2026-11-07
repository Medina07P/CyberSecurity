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
# conservación: shodan (vía sincronizar, solo tiene un campo)
rm -rf "$HOME/.shodan"; mkdir -p "$HOME/.shodan"
printf 'shodan-conservada-123456\n' > "$HOME/.shodan/api_key"
py poner shodan key - >/dev/null 2>&1
py sincronizar shodan >/dev/null 2>&1
eq "shodan: conserva valor ajeno" "$(cat "$HOME/.shodan/api_key")" "shodan-conservada-123456"
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
# importar amass round-trip
printf 'datasources:\n  - name: shodan\n    ttl: 4320\n    creds:\n      key: "importada-amass-123456"\n' > "$HOME/.config/amass/datasources.yaml"; chmod 600 "$HOME/.config/amass/datasources.yaml"
py poner amass shodan.key - >/dev/null 2>&1
py importar amass >/dev/null 2>&1
eq "importar amass" "$(python3 -c "import yaml;print(yaml.safe_load(open('$KEYS_FILE'))['amass']['shodan']['key'])")" "importada-amass-123456"
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

echo ""
echo "pasan: $pasan  fallan: $fallan"
[[ "$fallan" -eq 0 ]] && exit 0 || exit 1
