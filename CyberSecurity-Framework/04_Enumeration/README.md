# 🔍 04_Enumeration - Enumeración de Servicios

Este directorio contiene herramientas y scripts para enumerar servicios específicos.

## 📁 Estructura

| Directorio | Descripción |
|-----------|-------------|
| `smb/` | Enumeración SMB (shares, usuarios, null sessions) |
| `ldap/` | Enumeración LDAP/Active Directory |
| `ftp/` | Enumeración FTP (anónimo, usuarios) |
| `ssh/` | Enumeración SSH (usuarios, versiones) |
| `web/` | Enumeración Web (directorios, tecnologías) |
| `api/` | Enumeración de APIs (endpoints, métodos) |
| `database/` | Enumeración de bases de datos |

## 🚀 Uso Rápido

```bash
# Enumeración SMB (enum_smb.sh es un generador; usar el _advanced)
./smb/enum_smb_advanced.sh 192.168.1.10

# Enumeración Web
./web/enum_web.sh 192.168.1.10 80

# Enumeración SSH
./ssh/enum_ssh.sh 192.168.1.10

# Enumeración LDAP
./ldap/enum_ldap.sh 192.168.1.10

# Enumeración API
./api/enum_api.sh 192.168.1.10 8080