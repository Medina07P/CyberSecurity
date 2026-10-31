# NMAP CHEATSHEET

## Comandos Básicos

| Comando                          | Descripción               |
|----------------------------------|---------------------------|
| `nmap <target>`                  | Escaneo básico            |
| `nmap -p- <target>`              | Todos los puertos         |
| `nmap -p 22,80,443 <target>`     | Puertos específicos       |
| `nmap -sV <target>`              | Versiones de servicios    |
| `nmap -sC <target>`              | Scripts por defecto       |
| `nmap -O <target>`               | Detección de SO           |
| `nmap -A <target>`               | Todos los anteriores      |

## Escaneos Avanzados

| Comando                          | Descripción               |
|----------------------------------|---------------------------|
| `nmap -sS <target>`              | SYN scan (sigiloso)       |
| `nmap -sU -p 53,161 <target>`    | UDP scan                  |
| `nmap -sT <target>`              | TCP connect scan          |
| `nmap -sX <target>`              | XMAS scan                 |

## Scripts NSE

| Comando                              | Descripción         |
|--------------------------------------|---------------------|
| `nmap --script vuln <target>`        | Vulnerabilidades    |
| `nmap --script smb-enum* <target>`   | SMB                 |
| `nmap --script http-enum <target>`   | HTTP                |
| `nmap --script ftp-anon <target>`    | FTP anónimo         |

## Ejemplos Útiles

```bash
# Escaneo rápido
nmap -p- --min-rate 3000 -T4 <target>

# Escaneo detallado
nmap -p 22,80,443 -sV -sC -O <target>

# Escaneo de vulnerabilidades
nmap --script vuln -p 80,443 <target>

# Evasión
nmap -f --mtu 16 --data-length 200 --source-port 53 -sS <target>
```
