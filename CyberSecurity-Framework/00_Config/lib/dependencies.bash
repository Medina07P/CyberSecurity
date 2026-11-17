#!/bin/bash
# Datos y comprobaciones de dependencias. Solo lo carga el gestor (tecla D).

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
    'Dependencias adicionales|nmap-vulners'
)

dependencies_binary_ok() {
    local binario="$1"
    if [[ "$binario" == 'nmap-vulners' ]]; then
        [[ -f "${NMAP_VULNERS_PATH:-/usr/share/nmap/scripts/nmap-vulners.nse}" ]]
        return $?
    fi
    command -v "$binario" >/dev/null 2>&1
}
