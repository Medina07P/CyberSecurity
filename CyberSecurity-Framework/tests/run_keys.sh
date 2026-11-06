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
py poner theharvester shodan.key sk-propia-123456 >/dev/null 2>&1
eq "~ gana al /etc" "$(python3 -c "import yaml;print(yaml.safe_load(open('$HT'))['apikeys']['shodan']['key'])")" "sk-propia-123456"
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

echo ""
echo "pasan: $pasan  fallan: $fallan"
[[ "$fallan" -eq 0 ]] && exit 0 || exit 1
