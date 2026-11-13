#!/bin/bash
# Fichas informativas: cargar solo define la función; no consulta el entorno.
# Rutas de referencia relativas a CyberSecurity-Framework salvo docs/ (repo).
module_intro() {
    case "${1-}" in
        # 00_Config/run_all_config.sh; 00_Config/lib/session.bash;
        # 00_Config/scripts/api_keys.py; docs/MANUAL-GESTOR.md.
        00_Config)
            printf '%s\n' \
                'Para qué sirve: Preparar la configuración del proyecto, objetivos y claves.' \
                'Entrada: Datos del proyecto, objetivos y claves según la acción.' \
                'Incluye: Validadores, lista de objetivos, asistente y registro de claves API.' \
                'Precauciones: Registrar un objetivo no equivale a autorización; protege las claves.'
            ;;
        # 01_OSINT/README.md; 00_Config/lib/osint/cli.py (parser y despacho).
        01_OSINT)
            printf '%s\n' \
                'Para qué sirve: Recopilar información pública de dominios y empresas.' \
                'Entrada: Dominio, empresa o archivo local para metadatos, según la acción.' \
                'Incluye: WHOIS, DNS, certificados, correos publicados, perfiles y metadatos.' \
                'Precauciones: También contacta sitios y DNS; respeta alcance y límites de las fuentes.' \
                'Una IP privada de Metasploitable normalmente no necesita OSINT: usa 02 (reconocimiento), 03 (escáneres) y 04 (enumeración).'
            ;;
        # 02_Recon/scripts/{ping_sweep,fingerprint,dns_enum,screenshotter}.sh;
        # 02_Recon/run_all_recon.sh; docs/PATHS-KALI-2026-10-31.md.
        02_Recon)
            printf '%s\n' \
                'Para qué sirve: Hacer reconocimiento inicial de hosts, servicios y tecnologías.' \
                'Entrada: IP o red para descubrimiento, dominio para DNS, host y puerto para capturas; según la acción.' \
                'Incluye: Ping, Nmap, banners, whatweb, consultas DNS y capturas web.' \
                'Precauciones: Genera tráfico al objetivo; requiere autorización, también para intentos AXFR y sondeos activos.'
            ;;
        # 00_Config/lib/scanners_menu.bash; 03_Scanners/README.md.
        03_Scanners)
            printf '%s\n' \
                'Para qué sirve: Realizar escaneo de puertos, servicios y posibles vulnerabilidades.' \
                'Entrada: IPv4 o dominio para red; URL HTTP(S) completa para web, según la acción.' \
                'Incluye: Nmap, Masscan, RustScan, Nikto, Nuclei y Burp manual.' \
                'Precauciones: Requiere autorización; genera tráfico y los perfiles avanzados pueden ser intensivos. Disponibilidad no garantiza funcionamiento.'
            ;;
        # 00_Config/lib/enumeration_menu.bash; 04_Enumeration/README.md.
        04_Enumeration)
            printf '%s\n' \
                'Para qué sirve: Profundizar en servicios concretos mediante enumeración de datos y accesos.' \
                'Entrada: Host/IPv4 y puerto para servicios; URL completa para web/API, según la acción.' \
                'Incluye: SSH, FTP, SMB, LDAP, bases de datos, web, API y fuzzing.' \
                'Precauciones: Requiere autorización; genera tráfico, prueba accesos y algunos métodos pueden modificar datos o bloquear servicios.'
            ;;
        # 00_Config/lib/exploitation_menu.bash; 05_Exploitation/README.md;
        # docs/SQLMAP-Y-FRENOS-2026-10-31.md; docs/RATE-LIMIT-2026-10-31.md.
        05_Exploitation)
            printf '%s\n' \
                'Para qué sirve: Probar explotación controlada de fallos y accesos.' \
                'Entrada: Petición capturada, URL, host/puerto o datos del payload, según la acción.' \
                'Incluye: Pruebas web, sqlmap, accesos SSH/FTP/DB, Kerberos, guías CVE y generadores.' \
                'Precauciones: Exige autorización explícita y evaluar impacto: puede bloquear cuentas, alterar datos o abrir accesos; una guía no demuestra explotación.'
            ;;
        # 00_Config/lib/postexploitation_menu.bash;
        # docs/CIERRE-MANTENIMIENTO-06-2026-11-11.md (alcance y límites).
        06_PostExploitation)
            printf '%s\n' \
                'Para qué sirve: Acceder a acciones posteriores a un acceso autorizado.' \
                'Entrada: Sistema actual, host, credenciales o comando, según la hoja; no todo actúa en la IP de sesión.' \
                'Incluye: Entradas de escalada, credenciales, recolección, persistencia, movimiento lateral y limpieza.' \
                'Precauciones: Exige autorización explícita; impacto potencial sobre datos, accesos y logs. El mantenimiento no certifica integración operacional de todas las hojas.'
            ;;
        # 00_Config/lib/wireless_menu.bash; 07_Wireless/{README,USE}.md.
        07_Wireless)
            printf '%s\n' \
                'Para qué sirve: Consultar mantenimiento inalámbrico, disponibilidad local y guía.' \
                'Entrada: Ningún objetivo para la comprobación; interfaces y otros datos solo al elegir una hoja.' \
                'Incluye: Comprobación sin ejecutar binarios y entradas WiFi/Bluetooth conservadas.' \
                'Precauciones: Entrar no ejecuta herramientas ni una auditoría integrada; disponibilidad no acredita hardware o permisos. Operar radio requiere autorización y revisión específica.'
            ;;
        # 00_Config/lib/forensics_menu.bash; 08_Forensics/USE.md;
        # 08_Forensics/memory/strings_analysis.sh (staging y modo offline).
        08_Forensics)
            printf '%s\n' \
                'Para qué sirve: Analizar fuentes explícitas offline; separar la adquisición local sensible.' \
                'Entrada: Archivos de memoria, logs, PCAP, imágenes o fuentes seleccionadas; no IP de sesión.' \
                'Incluye: Strings, logs, TShark, Volatility, disco, recuperación, timeline y visor.' \
                'Precauciones: Requiere fuentes autorizadas, espacio para copias y permisos adecuados; adquisición y montaje son acciones separadas. No certifica custodia legal ni compatibilidad operacional.'
            ;;
        # 09_Automation/python/{orchestrator,auto_audit,report_generator}.py;
        # 09_Automation/run_all_automation.sh; 09_Automation/workflows/*.yaml.
        09_Automation)
            printf '%s\n' \
                'Para qué sirve: Consultar scripts de automatización presentes, sin prometer un flujo integral validado.' \
                'Entrada: Objetivo y fase para algunos scripts; directorios de resultados para el adaptador de informes.' \
                'Incluye: Scripts Bash/Python/PowerShell y adaptador hacia 11; workflows declarativos no consumidos.' \
                'Precauciones: No se declara integración operacional completa; algunos scripts encadenan acciones activas. Revisar código, alcance y autorización antes de ejecutarlos.'
            ;;
        # 10_Evidence/evidence_manager.sh; 10_Evidence/auto_capture.sh.
        10_Evidence)
            printf '%s\n' \
                'Para qué sirve: Gestionar y capturar evidencia del trabajo autorizado.' \
                'Entrada: Tipo y archivo para añadir evidencia; objetivo para captura automática.' \
                'Incluye: Copias, metadatos, hashes, listado, empaquetado y capturas web/de red.' \
                'Precauciones: Algunas acciones también escanean o capturan tráfico; requieren autorización y permisos. Protege los datos; hashes no equivalen a custodia legal.'
            ;;
        # 11_Reports/report_generator.sh; 09_Automation/python/report_generator.py;
        # docs/MANUAL-GESTOR.md (informes desde scans existentes).
        11_Reports)
            printf '%s\n' \
                'Para qué sirve: Elaborar informes desde resultados existentes.' \
                'Entrada: Directorio de resultados y datos de atribución del informe.' \
                'Incluye: Motor de hallazgos e informes técnicos y de cliente en Markdown/HTML y JSON.' \
                'Precauciones: Generar informes no realiza escaneos nuevos ni demuestra ausencia de vulnerabilidades; revisa cobertura, atribución y datos sensibles.'
            ;;
        # 12_Knowledge_Base/{search_kb,run_all_kb}.sh y sus guías Markdown.
        12_Knowledge_Base)
            printf '%s\n' \
                'Para qué sirve: Buscar y consultar guías locales de referencia.' \
                'Entrada: Término de búsqueda o documento local a consultar.' \
                'Incluye: Cheatsheets, metodologías, CVEs, notas y procedimientos.' \
                'Precauciones: Los ejemplos no se ejecutan al mostrar la ficha; adaptarlos requiere comprobar contexto y autorización.'
            ;;
        # 13_Labs/setup_lab.sh; 13_Labs/main.sh (tools_menu y vpn_menu);
        # 13_Labs/{hackthebox/htb_setup,tryhackme/thm_setup,web_apps/web_setup}.sh.
        13_Labs)
            printf '%s\n' \
                'Para qué sirve: Organizar laboratorios, notas y opciones de práctica.' \
                'Entrada: Tipo/nombre del laboratorio; archivo VPN, IP, URL o diccionario según la acción.' \
                'Incluye: Carpetas HTB/THM/AD/web/cloud, opciones VPN y herramientas rápidas de red/web.' \
                'Precauciones: Algunas acciones modifican sistema/red o escanean; requieren autorización. Crear carpetas no despliega máquinas y no garantiza aislamiento.'
            ;;
    esac
    return 0
}
