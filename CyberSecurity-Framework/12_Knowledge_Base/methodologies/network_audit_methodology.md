# METODOLOGÍA DE AUDITORÍA DE RED

## 1. Fases

### 1.1 Descubrimiento
- Mapeo de red
- Identificación de hosts activos
- Detección de firewalls

### 1.2 Escaneo
- Puertos abiertos
- Servicios expuestos
- Fingerprinting

### 1.3 Enumeración
- Servicios específicos
- Usuarios y grupos
- Compartidos de red

### 1.4 Análisis
- Vulnerabilidades conocidas
- Configuraciones inseguras
- Riesgos identificados

## 2. Servicios Comunes

### SSH (22)
- Versión y métodos
- Enumeración de usuarios
- Fuerza bruta

### SMB (445)
- Shares accesibles
- Null sessions
- Usuarios del dominio

### FTP (21)
- Acceso anónimo
- Archivos sensibles
- Fuerza bruta

### HTTP/HTTPS (80,443)
- Tecnologías web
- Directorios
- Vulnerabilidades

### Bases de Datos
- MySQL (3306)
- PostgreSQL (5432)
- Redis (6379)

## 3. Herramientas

```bash
# Escaneo
nmap -sV -sC -p- <target>
masscan -p1-65535 --rate=1000 <target>

# SMB
enum4linux -a <target>
smbclient -L //<target>

# SSH
hydra -l root -P wordlist.txt ssh://<target>
```
