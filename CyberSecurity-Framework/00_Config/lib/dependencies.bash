#!/bin/bash
# Datos y comprobaciones de dependencias. Solo lo carga el gestor (tecla D).

_dependencies_self="${BASH_SOURCE[0]:-$0}"
_dependencies_self_dir="${_dependencies_self%/*}"
[[ "$_dependencies_self_dir" != "$_dependencies_self" ]] || _dependencies_self_dir='.'
DEPENDENCIES_LIB_DIR="$(cd "$_dependencies_self_dir" && pwd)"
unset _dependencies_self _dependencies_self_dir
declare -ga DEPENDENCIES_EXTRA_ORDER=(ollama avml nmap-vulners)

declare -gA DEPENDENCIES_MAP=(
    [nmap]=nmap [masscan]=masscan [rustscan]=rustscan [nikto]=nikto
    [nuclei]=nuclei [burpsuite]=burpsuite [python3]=python3
    [hydra]=hydra [sqlmap]=sqlmap [curl]=curl [ffuf]=ffuf [nc]=netcat-traditional
    [iwlist]=wireless-tools [ip]=iproute2
    [ftp]=ftp [ldapsearch]=ldap-utils [rpcclient]=smbclient [smbclient]=smbclient
    [enum4linux]=enum4linux [mysql]=mariadb-client [psql]=postgresql-client
    [whatweb]=whatweb [timeout]=coreutils
    [sudo]=sudo [find]=findutils [ssh]=openssh-client [crontab]=cron
    [getcap]=libcap2-bin [scrot]=scrot [import]=imagemagick
    [gnome-screenshot]=gnome-screenshot [wget]=wget
    [iw]=iw [airodump-ng]=aircrack-ng [aireplay-ng]=aircrack-ng [aircrack-ng]=aircrack-ng
    [hcitool]=bluez [bluetoothctl]=bluez
    [cutycapt]=cutycapt [tcpdump]=tcpdump
    [autopsy]=autopsy [foremost]=foremost [scalpel]=scalpel [wireshark]=wireshark [dd]=coreutils
    [zaproxy]=zaproxy [volatility3]=volatility3
)

declare -gA DEPENDENCIES_NO_APT=(
    [sdptool]='sin paquete apt en este Kali'
    [gatttool]='sin paquete apt en este Kali'
    [avml]='binario de GitHub (Microsoft), no se instala aquí'
    [lime]='módulo de kernel que se compila, no se instala aquí'
    [volatility]='sin paquete apt en Kali (reemplazado por volatility3); solo se documenta'
    [nmap-vulners]='no es un binario: script NSE que se clona a mano a /usr/share/nmap/scripts/'
    [ollama]='se instala con «curl -fsSL https://ollama.com/install.sh | sh», no es un paquete apt'
)

declare -ga DEPENDENCIES_ORDER=(
    '03_Scanners|nmap' '03_Scanners|masscan' '03_Scanners|rustscan' '03_Scanners|nikto'
    '03_Scanners|nuclei' '03_Scanners|burpsuite' '03_Scanners|python3'
    '05_Exploitation|hydra' '05_Exploitation|sqlmap' '05_Exploitation|curl' '05_Exploitation|ffuf'
    '05_Exploitation|nc' '05_Exploitation|iwlist' '05_Exploitation|ip'
    '04_Enumeration|ftp' '04_Enumeration|ldapsearch' '04_Enumeration|rpcclient'
    '04_Enumeration|smbclient' '04_Enumeration|enum4linux' '04_Enumeration|mysql'
    '04_Enumeration|psql' '04_Enumeration|whatweb' '04_Enumeration|timeout'
    '06_PostExploitation|sudo' '06_PostExploitation|find' '06_PostExploitation|ssh'
    '06_PostExploitation|crontab' '06_PostExploitation|getcap' '06_PostExploitation|scrot'
    '06_PostExploitation|import' '06_PostExploitation|gnome-screenshot' '06_PostExploitation|wget'
    '07_Wireless|iw' '07_Wireless|airodump-ng' '07_Wireless|aireplay-ng' '07_Wireless|aircrack-ng'
    '07_Wireless|hcitool' '07_Wireless|bluetoothctl' '07_Wireless|sdptool' '07_Wireless|gatttool'
    '10_Evidence|cutycapt' '10_Evidence|tcpdump'
    '08_Forensics|volatility' '08_Forensics|autopsy' '08_Forensics|foremost' '08_Forensics|scalpel'
    '08_Forensics|wireshark' '08_Forensics|avml' '08_Forensics|lime' '08_Forensics|dd'
    'Dependencias adicionales|zaproxy' 'Dependencias adicionales|volatility3'
    'Dependencias adicionales|nmap-vulners' 'Dependencias adicionales|ollama'
)

dependencies_binary_ok() {
    local binario="$1"
    if [[ "$binario" == 'nmap-vulners' ]]; then
        [[ -f "${NMAP_VULNERS_PATH:-/usr/share/nmap/scripts/vulners.nse}" ]]
        return $?
    fi
    command -v "$binario" >/dev/null 2>&1
}

dependencies_status() {
    local entry grupo binario previo=''
    for entry in "${DEPENDENCIES_ORDER[@]}"; do
        grupo="${entry%%|*}"
        binario="${entry#*|}"
        if [[ "$grupo" != "$previo" ]]; then
            printf '%s:\n' "$grupo"
            previo="$grupo"
        fi
        if dependencies_binary_ok "$binario"; then
            printf '  ✓ %s\n' "$binario"
        elif [[ -v DEPENDENCIES_NO_APT[$binario] ]]; then
            printf '  ✗ %s (%s)\n' "$binario" "${DEPENDENCIES_NO_APT[$binario]}"
        else
            printf '  ✗ %s\n' "$binario"
        fi
    done
}

dependencies_missing_with_package() {
    local entry binario paquete
    local -A vistos=()
    for entry in "${DEPENDENCIES_ORDER[@]}"; do
        binario="${entry#*|}"
        [[ -v DEPENDENCIES_MAP[$binario] ]] || continue
        [[ -v DEPENDENCIES_NO_APT[$binario] ]] && continue
        dependencies_binary_ok "$binario" && continue
        paquete="${DEPENDENCIES_MAP[$binario]}"
        [[ -v vistos[$paquete] ]] && continue
        vistos[$paquete]=1
        printf '%s\n' "$paquete"
    done
}

dependencies_install() {
    local respuesta
    if [[ $# -eq 0 ]]; then
        printf 'No hay nada que instalar.\n' >&2
        return 0
    fi
    printf 'Paquetes a instalar: %s\n' "$*" >&2
    printf "Escribe 'instalar' para continuar (cualquier otra entrada cancela): " >&2
    if ! IFS= read -r respuesta || [[ "$respuesta" != 'instalar' ]]; then
        printf 'Instalación cancelada.\n' >&2
        return 1
    fi
    sudo apt-get install -y "$@"
}

dependencies_resolve_selection() {
    local seleccion="$1"; shift
    local -a faltan=("$@") elegidos=()
    local -A vistos=()
    local idx paquete
    if [[ "$seleccion" == 'todas' ]]; then
        printf '%s\n' "${faltan[@]}"
        return 0
    fi
    for idx in $seleccion; do
        if [[ "$idx" =~ ^[0-9]+$ ]] && (( 10#$idx >= 1 && 10#$idx <= ${#faltan[@]} )); then
            paquete="${faltan[$((10#$idx - 1))]}"
            [[ -v vistos[$paquete] ]] && continue
            vistos[$paquete]=1
            elegidos+=("$paquete")
        else
            return 1
        fi
    done
    printf '%s\n' "${elegidos[@]}"
}

dependencies_extra_missing() {
    local binario
    for binario in "${DEPENDENCIES_EXTRA_ORDER[@]}"; do
        dependencies_binary_ok "$binario" || printf '%s\n' "$binario"
    done
}

dependencies_install_nmap_vulners() {
    dependencies_binary_ok nmap-vulners && { printf 'nmap-vulners ya está instalado.\n' >&2; return 0; }
    printf 'Clona vulnersCom/nmap-vulners de GitHub y copia vulners.nse a /usr/share/nmap/scripts/ con sudo; ejecuta "nmap --script-updatedb" al final.\nEscribe NMAP_VULNERS_SI para continuar (cualquier otra entrada cancela): ' >&2
    local respuesta; IFS= read -r respuesta
    [[ "$respuesta" == 'NMAP_VULNERS_SI' ]] || { printf 'Instalación de nmap-vulners cancelada.\n' >&2; return 1; }
    local tmp; tmp=$(mktemp -d)
    if ! git clone --depth 1 https://github.com/vulnersCom/nmap-vulners.git "$tmp/nmap-vulners"; then
        printf 'No se pudo clonar nmap-vulners.\n' >&2; rm -rf "$tmp"; return 1
    fi
    local destino="${NMAP_VULNERS_PATH:-/usr/share/nmap/scripts/vulners.nse}"
    mkdir -p "${destino%/*}" 2>/dev/null
    if ! sudo install -m 644 "$tmp/nmap-vulners/vulners.nse" "$destino"; then
        printf 'No se pudo copiar vulners.nse a su destino.\n' >&2; rm -rf "$tmp"; return 1
    fi
    [[ -f "$tmp/nmap-vulners/http-vulners-regex.nse" ]] && sudo install -m 644 "$tmp/nmap-vulners/http-vulners-regex.nse" "${destino%/*}" 2>/dev/null
    rm -rf "$tmp"
    sudo nmap --script-updatedb >/dev/null 2>&1
    dependencies_binary_ok nmap-vulners && { printf 'nmap-vulners instalado y verificado.\n' >&2; return 0; }
    printf 'nmap-vulners se copió pero no se detecta en su ruta.\n' >&2
    return 1
}

dependencies_github_token() {
    python3 -c '
import sys, os
sys.path.insert(0, "'"$DEPENDENCIES_LIB_DIR"'")
from pathlib import Path
from osint.credentials import load_credentials
fw = Path("'"$DEPENDENCIES_LIB_DIR"'").resolve().parents[1]
registry = Path(os.environ.get("KEYS_FILE", fw / "00_Config/credentials/api-keys.yaml"))
try:
    print(load_credentials(registry, []).get("github", ""), end="")
except Exception:
    pass
'
}

dependencies_offer_github_token() {
    [[ -n "$(dependencies_github_token)" ]] && return 0
    printf 'No hay un token de GitHub guardado; uno evita el límite de 60 peticiones/hora sin autenticar.\nToken de GitHub (opcional, Enter para omitir; nunca se imprime): ' >&2
    local respuesta; IFS= read -r respuesta
    [[ -n "$respuesta" ]] || return 0
    printf '%s' "$respuesta" | python3 "$DEPENDENCIES_LIB_DIR/../scripts/api_keys.py" poner theharvester github.key --stdin >/dev/null 2>&1
}

dependencies_avml_release() {
    local token json
    token=$(dependencies_github_token)
    if [[ -n "$token" ]]; then
        json=$(curl -fsSL -H "Authorization: Bearer $token" https://api.github.com/repos/microsoft/avml/releases/latest)
    else
        json=$(curl -fsSL https://api.github.com/repos/microsoft/avml/releases/latest)
    fi
    [[ -n "$json" ]] || { printf 'No se pudo consultar la API de releases de GitHub.\n' >&2; return 1; }
    python3 -c '
import json, sys
data = json.loads(sys.stdin.read())
tag = data.get("tag_name", "")
url = next((a.get("browser_download_url", "") for a in data.get("assets", [])
            if a.get("name") == "avml"), "")
if not tag or not url:
    sys.exit(1)
print(tag + "|" + url)
' <<<"$json"
}

DEPENDENCIES_AVML_MAX_BYTES=20971520

dependencies_verify_avml() {
    command -v avml >/dev/null 2>&1 || { printf 'avml no aparece en PATH tras instalarlo.\n' >&2; return 1; }
    local ayuda; ayuda=$(timeout 10 avml --help 2>&1)
    if [[ "${ayuda,,}" == *avml* && "${ayuda,,}" == *usage:* \
          && ( "$ayuda" == *'<FILENAME>'* || "$ayuda" == *'<OUTPUT>'* ) ]]; then
        printf 'avml instalado y verificado.\n' >&2; return 0
    fi
    printf 'avml se instaló pero no respondió como se esperaba a --help.\n' >&2
    return 1
}

dependencies_install_avml() {
    dependencies_binary_ok avml && { printf 'avml ya está instalado.\n' >&2; return 0; }
    printf 'Descarga el binario de avml desde las releases de GitHub (microsoft/avml) a /usr/local/bin/avml con sudo. No hay suma de verificación oficial publicada: la integridad depende de HTTPS y del dominio de GitHub, no de una firma.\nEscribe AVML_SI para continuar (cualquier otra entrada cancela): ' >&2
    local respuesta; IFS= read -r respuesta
    [[ "$respuesta" == 'AVML_SI' ]] || { printf 'Instalación de avml cancelada.\n' >&2; return 1; }
    dependencies_offer_github_token
    local release; release=$(dependencies_avml_release) || { printf 'No se pudo resolver la última versión de avml.\n' >&2; return 1; }
    local tag="${release%%|*}" url="${release#*|}" tmp; tmp=$(mktemp)
    printf 'Descargando avml %s...\n' "$tag" >&2
    if ! curl -fsSL --max-filesize "$DEPENDENCIES_AVML_MAX_BYTES" -o "$tmp" "$url"; then
        printf 'La descarga de avml falló.\n' >&2; rm -f "$tmp"; return 1
    fi
    chmod +x "$tmp"
    if ! sudo install -m 755 "$tmp" /usr/local/bin/avml; then
        printf 'No se pudo instalar avml en /usr/local/bin.\n' >&2; rm -f "$tmp"; return 1
    fi
    rm -f "$tmp"
    dependencies_verify_avml
}

# Resumen de una línea para el menú principal (mismo rol que keys_resumen_line)
dependencies_resumen_line() {
    local -a faltan
    mapfile -t faltan < <(dependencies_missing_with_package)
    if [[ ${#faltan[@]} -eq 0 ]]; then
        printf 'nada pendiente por apt\n'
    else
        printf '%s paquetes por apt\n' "${#faltan[@]}"
    fi
}
