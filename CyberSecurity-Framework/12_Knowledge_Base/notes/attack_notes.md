# NOTAS DE ATAQUE

- **Fecha:** [YYYY-MM-DD]
- **Objetivo:** [IP/DOMINIO]

## Comandos Ejecutados

```bash
# Reconocimiento
nmap -sV -sC -p- <IP>

# Enumeración
enum4linux <IP>
smbclient -L //<IP>

# Explotación
hydra -l admin -P wordlist.txt ssh://<IP>

# Post-Explotación
whoami
id
uname -a
```

## Hallazgos Clave
- [Hallazgo 1]
- [Hallazgo 2]
- [Hallazgo 3]

## Próximos Pasos
1. Paso 1
2. Paso 2
3. Paso 3
