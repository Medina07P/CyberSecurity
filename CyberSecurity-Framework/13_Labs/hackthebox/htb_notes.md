# HTB Notes

## Conexión VPN
```bash
sudo openvpn --config ~/htb.ovpn --daemon
ip a | grep tun0
```

## Máquinas Completadas

| Máquina | IP | Dificultad | Estado |
|---------|----|------------|--------|
| -       | -  | -          | -      |

## Comandos Útiles
```bash
# Recon
nmap -sV -sC -p- <IP>

# Shell
nc -lvnp 4444
```
