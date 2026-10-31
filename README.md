# 🛡️ CyberSecurity Framework - Red Team / Pentesting

<div align="center">

![Version](https://img.shields.io/badge/version-2.0-blue)
![Kali](https://img.shields.io/badge/Kali-Linux-557C94?style=flat&logo=kalilinux&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-4.0+-green)
![Python](https://img.shields.io/badge/Python-3.8+-yellow)
![License](https://img.shields.io/badge/License-MIT-orange)

**Estructura profesional para auditorías de seguridad y pentesting**

[Descripción](#descripción) •
[Estructura](#-estructura-del-framework) •
[Instalación](#-instalación) •
[Uso](#-uso) •
[Flujo de Trabajo](#-flujo-de-trabajo) •
[Contribuir](#-contribuir)

</div>

---

## 📋 Descripción

Este framework proporciona una **estructura organizada y profesional** para realizar auditorías de seguridad, pruebas de penetración (pentesting) y evaluaciones de Red Team. Está diseñado para cubrir todo el ciclo de vida de una auditoría, desde la fase de OSINT hasta la generación de informes.

### 🎯 Objetivos

- **Estandarizar** el proceso de auditoría
- **Organizar** herramientas, scripts y resultados
- **Automatizar** tareas repetitivas
- **Documentar** hallazgos y procedimientos
- **Facilitar** la generación de informes profesionales

### 🔒 Seguridad y Ética

> ⚠️ **ADVERTENCIA LEGAL**
>
> Este framework está diseñado **EXCLUSIVAMENTE** para:
> - Pruebas de penetración con autorización explícita
> - Laboratorios de aprendizaje (HTB, THM, etc.)
> - Entornos controlados y de pruebas
>
> El uso no autorizado de estas herramientas es **ilegal**. El usuario es el único responsable de cumplir con las leyes aplicables.

---

## 📁 Estructura del Framework

```
CyberSecurity-Framework/
│
├── 00_Config/               # Configuración y alcance
│   ├── scope.yaml           # Alcance de la auditoría
│   ├── targets.txt          # Lista de objetivos
│   ├── wordlists/           # Diccionarios personalizados
│   └── credentials/         # Credenciales (cifradas)
│
├── 01_OSINT/                # Recopilación de información
│   ├── domains/             # Información de dominios
│   ├── subdomains/          # Subdominios encontrados
│   ├── emails/              # Emails identificados
│   └── scripts/             # Scripts OSINT
│
├── 02_Recon/                # Reconocimiento activo
│   ├── host_discovery/      # Descubrimiento de hosts
│   ├── dns/                 # Enumeración DNS
│   ├── whois/               # Información WHOIS
│   └── scripts/             # Scripts de reconocimiento
│
├── 03_Scanners/             # Escáneres de vulnerabilidades
│   ├── network_scanners/    # Nmap, Masscan, Rustscan
│   └── web_scanners/        # Nuclei, Nikto, Burp, ZAP
│
├── 04_Enumeration/          # Enumeración de servicios
│   ├── smb/                 # Enumeración SMB
│   ├── ldap/                # Enumeración LDAP
│   ├── web/                 # Enumeración web
│   ├── ssh/ ftp/ api/       # SSH, FTP y APIs
│   └── database/            # MySQL, PostgreSQL, Redis
│
├── 05_Exploitation/         # Explotación controlada
│   ├── web/                 # SQLi, XSS, RCE
│   ├── network/             # SSH, FTP, SMB
│   ├── payloads/            # Reverse shells, webshells
│   └── exploits/            # CVEs y exploits personalizados
│
├── 06_PostExploitation/     # Post-explotación
│   ├── privilege_escalation/ # Escalada de privilegios
│   ├── persistence/         # Mantener acceso
│   ├── credential_access/   # Obtener credenciales
│   ├── lateral_movement/    # Movimiento lateral
│   └── cleanup/             # Limpiar huellas
│
├── 07_Wireless/             # Seguridad inalámbrica
│   ├── wifi/                # Ataques WiFi
│   └── bluetooth/           # Ataques Bluetooth
│
├── 08_Forensics/            # Análisis forense
│   ├── memory/              # Análisis de memoria
│   ├── disk/                # Análisis de discos
│   ├── logs/                # Análisis de logs
│   └── pcaps/               # Análisis de tráfico
│
├── 09_Automation/           # Automatización
│   ├── bash/                # Scripts Bash
│   ├── python/              # Scripts Python
│   ├── powershell/          # Scripts PowerShell
│   └── workflows/           # Flujos de trabajo
│
├── 10_Evidence/             # Evidencias recolectadas
│   ├── screenshots/         # Capturas de pantalla
│   ├── pcaps/               # Capturas de tráfico
│   ├── credentials/         # Credenciales encontradas
│   └── proofs/              # Pruebas de acceso
│
├── 11_Reports/              # Informes y documentación
│   ├── executive/           # Informe ejecutivo
│   ├── technical/           # Informe técnico
│   └── templates/           # Plantillas para informes
│
├── 12_Knowledge_Base/       # Base de conocimiento
│   ├── cheatsheets/         # Hojas de referencia
│   ├── methodologies/       # Metodologías de auditoría
│   ├── cves/                # Documentación de CVEs
│   └── procedures/          # Procedimientos estándar
│
├── 13_Labs/                 # Laboratorios y prácticas
│   ├── hackthebox/          # Máquinas HTB
│   ├── tryhackme/           # Salas THM
│   ├── active_directory/    # Laboratorios AD
│   └── web_apps/            # Aplicaciones web vulnerables
│
├── 00_Config/lib/           # Librería del gestor (parser, sesión, fases)
├── tests/                   # Pruebas del gestor
└── cyber_framework.sh       # Gestor interactivo (punto de entrada)
```

Los resultados **no** se guardan dentro del framework: todos los scripts escriben
en `scans/<herramienta>/`, en la raíz del repositorio. Esa carpeta y los datos de
reconocimiento están en `.gitignore`, porque contienen IPs y hallazgos de cada
sesión.

---

## 📊 Resumen por Fase

| Fase | Directorio | Descripción | Herramientas Clave |
|------|-----------|-------------|-------------------|
| **1. Configuración** | `00_Config` | Definir alcance y objetivos | scope.yaml, targets.txt |
| **2. OSINT** | `01_OSINT` | Recopilación pasiva de información | theHarvester, dnsrecon, whois |
| **3. Reconocimiento** | `02_Recon` | Reconocimiento activo de la red | nmap, ping, dig |
| **4. Escaneo** | `03_Scanners` | Escaneo de vulnerabilidades | nmap, nuclei, nikto |
| **5. Enumeración** | `04_Enumeration` | Enumeración de servicios | enum4linux, smbclient, ldapsearch |
| **6. Explotación** | `05_Exploitation` | Explotación controlada | hydra, sqlmap, metasploit |
| **7. Post-Explotación** | `06_PostExploitation` | Escalada y persistencia | linpeas, mimikatz, bloodhound |
| **8. Wireless** | `07_Wireless` | Auditoría inalámbrica | aircrack-ng, airodump-ng |
| **9. Forense** | `08_Forensics` | Análisis forense | volatility, foremost, tshark |
| **10. Automatización** | `09_Automation` | Scripts y workflows | bash, python, docker |
| **11. Evidencias** | `10_Evidence` | Recolección de evidencias | screenshots, pcaps, logs |
| **12. Reportes** | `11_Reports` | Generación de informes | markdown, html, pdf |
| **13. Conocimiento** | `12_Knowledge_Base` | Base de conocimiento | cheatsheets, cves, procedures |
| **14. Laboratorios** | `13_Labs` | Entornos de práctica | HTB, THM, AD, Web |

---

## 🚀 Instalación

### Requisitos del Sistema

```bash
# Sistema
# Kali Linux 2024+ (recomendado)
# 8GB RAM mínimo
# 50GB espacio en disco

# Dependencias principales
sudo apt update
sudo apt install -y nmap masscan hydra ffuf sqlmap nikto whatweb \
    aircrack-ng wireshark tshark john hashcat \
    python3 python3-pip git tree
```

### Clonar el Framework

```bash
# Clonar el repositorio
git clone https://github.com/Medina07P/CyberSecurity.git

# Entrar al directorio del framework
cd CyberSecurity/CyberSecurity-Framework

# Dar permisos a todos los scripts
find . -name "*.sh" -exec chmod +x {} \;
find . -name "*.py" -exec chmod +x {} \;

# Verificar estructura
tree -a -L 2
```

### Configuración Inicial

```bash
# 1. Configurar alcance (editar el fichero que ya existe)
nano 00_Config/scope.yaml

# 2. Configurar objetivos
nano 00_Config/targets.txt

# 3. Verificar configuración
cd 00_Config && ./scripts/validate_config.sh && cd ..
```

---

## 🎮 Uso

### El gestor interactivo (recomendado)

```bash
cd CyberSecurity-Framework
./cyber_framework.sh
```

Al arrancar te pide el objetivo, o te deja elegirlo de `00_Config/targets.txt`, y
lo recuerda durante toda la sesión: todos los scripts que piden un host lo
reciben como valor por defecto. La cabecera muestra el objetivo actual y qué
fases tienen ya resultados.

| Tecla | Acción |
|---|---|
| `00`–`13` | Entrar en un módulo (también vale `0`–`9`) |
| `T` | Cambiar el objetivo de la sesión |
| `99` | Flujo completo (comprueba el alcance de `scope.yaml` y pide confirmación) |
| `?` | Ayuda, con el orden recomendado de fases |
| `Q` | Salir |

Cada script declara sus datos en su propia línea `Uso:`, así que el gestor
pregunta exactamente los que necesita —también en los que piden dos o más— y
ofrece el valor del `Ejemplo:` como defecto al pulsar Enter.

Las marcas de la lista avisan antes de ejecutar:

- `[intrusiva]` — fuerza bruta, explotación, persistencia o limpieza: pide confirmación aparte
- `[manual]` — usa banderas o subcomandos: escribes la línea de argumentos completa
- `[generador]` — escribe otro script, no escanea nada

Los resultados van siempre a `scans/<herramienta>/` en la raíz del repositorio, se
lance el script desde donde se lance.

### Flujo de Auditoría Completo

```bash
# 1. Configuración
cd 00_Config && ./scripts/validate_config.sh

# 2. OSINT (si es dominio)
cd 01_OSINT/scripts && ./osint_harvester.sh example.com

# 3. Reconocimiento
cd 02_Recon/scripts && ./auto_recon.sh 192.168.1.10

# 4. Escaneo
cd 03_Scanners && ./run_all_scanners.sh 192.168.1.10

# 5. Enumeración
cd 04_Enumeration && ./run_all_enum.sh 192.168.1.10

# 6. Explotación
cd 05_Exploitation && ./run_all_exploits.sh 192.168.1.10

# 7. Post-Explotación
cd 06_PostExploitation && ./run_all_post.sh

# 8. Evidencias
cd 10_Evidence && ./evidence_manager.sh --list

# 9. Reporte
cd 11_Reports && ./report_generator.sh --full

# 10. Ver resultados
cd 11_Reports && tree -a
```

### Automatización con Python

```bash
# Auditoría completa con el orquestador
cd 09_Automation/python
python3 orchestrator.py --target 192.168.1.10 --full

# Generar reporte
python3 report_generator.py --input ../../11_Reports/ --output report.html
```

### Laboratorios

```bash
# Configurar máquina de HackTheBox
cd 13_Labs/hackthebox
./htb_setup.sh "Blue"

# Configurar sala de TryHackMe
cd ../tryhackme
./thm_setup.sh "VulnNet"

# Configurar laboratorio AD
cd ../active_directory
./ad_setup.sh "domain.local"

# Ver todos los laboratorios
cd 13_Labs && ./run_all_labs.sh
```

---

## 📋 Flujo de Trabajo

```
┌─────────────────────────────────────────────────────────────────┐
│                    CICLO DE AUDITORÍA                           │
└─────────────────────────────────────────────────────────────────┘

    ┌─────────────┐
    │   TARGET    │
    └──────┬──────┘
           │
           ▼
    ┌─────────────┐
    │    OSINT    │  ← 01_OSINT/
    └──────┬──────┘
           │
           ▼
    ┌─────────────┐
    │    RECON    │  ← 02_Recon/
    └──────┬──────┘
           │
           ▼
    ┌─────────────┐
    │  SCANNERS   │  ← 03_Scanners/
    └──────┬──────┘
           │
           ▼
    ┌─────────────┐
    │    ENUM     │  ← 04_Enumeration/
    └──────┬──────┘
           │
           ▼
    ┌─────────────┐
    │   EXPLOIT   │  ← 05_Exploitation/
    └──────┬──────┘
           │
           ▼
    ┌─────────────┐
    │    POST     │  ← 06_PostExploitation/
    └──────┬──────┘
           │
           ▼
    ┌─────────────┐
    │  EVIDENCE   │  ← 10_Evidence/
    └──────┬──────┘
           │
           ▼
    ┌─────────────┐
    │   REPORT    │  ← 11_Reports/
    └─────────────┘
```

---

## 🛠️ Herramientas Incluidas

### Escáneres de Red
- **Nmap** - Escaneo de puertos y servicios
- **Masscan** - Escaneo ultrarrápido
- **Rustscan** - Escaneo moderno y rápido

### Escáneres Web
- **Nuclei** - Escaneo de vulnerabilidades basado en templates
- **Nikto** - Escaneo de servidores web
- **OWASP ZAP** - Proxy y escáner web
- **Burp Suite** - Proxy y herramientas de seguridad

### Enumeración
- **enum4linux** - Enumeración SMB
- **ldapsearch** - Enumeración LDAP
- **smbclient** - Cliente SMB
- **gobuster** - Fuzzing de directorios

### Explotación
- **Metasploit** - Framework de explotación
- **Hydra** - Fuerza bruta
- **sqlmap** - SQL Injection
- **John the Ripper** - Crackeo de contraseñas

### Post-Explotación
- **LinPEAS** - Escalada de privilegios en Linux
- **WinPEAS** - Escalada de privilegios en Windows
- **BloodHound** - Análisis de Active Directory
- **Mimikatz** - Extracción de credenciales

### Wireless
- **Aircrack-ng** - Suite de auditoría WiFi
- **Airodump-ng** - Captura de paquetes WiFi

### Forense
- **Volatility** - Análisis de memoria
- **Foremost** - Recuperación de archivos
- **Wireshark/TShark** - Análisis de tráfico

---

## 📚 Base de Conocimiento

El framework incluye una extensa base de conocimiento:

### Cheatsheets (`12_Knowledge_Base/cheatsheets/`)
- `nmap_cheatsheet.md` - Comandos de Nmap
- `linux_priv_esc.md` - Escalada en Linux
- `windows_priv_esc.md` - Escalada en Windows
- `reverse_shells.md` - Payloads de reverse shell
- `sql_injection.md` - Técnicas de SQLi
- `metasploit_cheatsheet.md` - Comandos de Metasploit
- `docker_cheatsheet.md` - Comandos de Docker

### Metodologías (`12_Knowledge_Base/methodologies/`)
- `pentest_methodology.md` - Metodología general
- `web_audit_methodology.md` - Auditoría web (OWASP)
- `network_audit_methodology.md` - Auditoría de red
- `wireless_audit_methodology.md` - Auditoría wireless

### CVEs Documentados (`12_Knowledge_Base/cves/`)
- CVE-2024-6387 (regreSSHion)
- CVE-2021-4034 (Polkit)
- CVE-2021-44228 (Log4Shell)
- CVE-2023-44487 (HTTP/2 Rapid Reset)

---

## 📖 Documentación del proyecto

Además de este README:

| Documento | Contenido |
|---|---|
| `AGENTS.md` | Conocimiento operativo: cómo están hechas las cosas y por qué. Empieza por aquí si vas a tocar el código |
| `docs/CLEANUP-2026-10-30.md` | Sesión de limpieza: 44 ficheros en cuarentena, 8 bugs corregidos, rutas absolutas eliminadas |
| `docs/SCANS-PATHS-2026-10-30.md` | Por qué todos los resultados van a `<repo>/scans/` y cómo verificarlo en Kali |
| `docs/GESTOR-2026-10-30.md` | Diseño del gestor: parser de `Uso:`, sesión del objetivo, estado de fases, decisiones tomadas |
| `docs/superpowers/plans/` | Plan de implementación de la unificación de rutas |

### Pruebas

```bash
cd CyberSecurity-Framework
./tests/run_tests.sh    # librería del gestor (57 comprobaciones)
./tests/run_e2e.sh      # el script recibe el argumento tecleado (11)
./tests/run_smoke.sh    # navegación del menú con entrada simulada
```

No necesitan terminal interactiva ni herramientas de pentesting instaladas: se
alimentan por tubería y usan dobles de `nmap`.

---

## 🤝 Contribuir

Si deseas contribuir a este framework:

- **Reportar bugs** - Abre un issue en GitHub
- **Añadir scripts** - Envía un pull request
- **Mejorar documentación** - Actualiza los README
- **Añadir cheatsheets** - Nuevas hojas de referencia

### Estilo de Código
- **Bash**: Usar `#!/bin/bash` y funciones claras
- **Python**: Seguir PEP 8
- **Documentación**: Markdown con formato limpio
- **Scripts**: Siempre incluir `Uso:` y `Ejemplo:` en la cabecera, con los huecos
  entre `<OBLIGATORIO>` y `[opcional]`. El gestor los lee para pedir los datos.
- **Rutas de salida**: nunca relativas al directorio actual. Se resuelven desde
  el propio script y se escriben bajo `<repo>/scans/<herramienta>/`.
- **Valores de retorno**: una función que devuelve un valor imprime solo el valor
  por stdout; la interfaz va por stderr.
- **Pruebas**: si tocas `00_Config/lib/` o `cyber_framework.sh`, ejecuta
  `tests/run_tests.sh` y `tests/run_e2e.sh`.

---

## 📄 Licencia

Este proyecto está bajo la licencia MIT.

```
MIT License

Copyright (c) 2026 CyberSecurity Framework

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## 📞 Contacto

Para consultas, sugerencias o reportes:

- **Email**: security@framework.local
- **GitHub**: CyberSecurity-Framework
- **Twitter**: @CyberSecFramework

---

<div align="center">

⭐ ¡No olvides darle una estrella al repositorio! ⭐

*"La seguridad no es un producto, es un proceso" - Bruce Schneier*

</div>
