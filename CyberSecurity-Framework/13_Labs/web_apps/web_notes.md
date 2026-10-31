# Web App Notes

## Herramientas
```bash
# Escaneo
nmap -sV -p 80,443 <IP>
whatweb http://<IP>

# Fuzzing
ffuf -w wordlist.txt -u http://<IP>/FUZZ

# SQLi
sqlmap -u "http://<IP>/page?id=1" --batch
```

## Aplicaciones Vulnerables
- OWASP Juice Shop
- DVWA
- WebGoat
- bWAPP
