# METODOLOGÍA DE AUDITORÍA WEB (OWASP)

## 1. Fases de Auditoría Web

### 1.1 Reconocimiento
- Identificar tecnologías
- Enumerar subdominios
- Descubrir endpoints

### 1.2 Enumeración
- Directorios y archivos
- Parámetros GET/POST
- APIs y servicios

### 1.3 Pruebas OWASP Top 10

#### A01 - Broken Access Control
- IDOR
- Bypass de autenticación
- Escalada de privilegios

#### A02 - Cryptographic Failures
- SSL/TLS
- Almacenamiento de contraseñas

#### A03 - Injection
- SQL Injection
- NoSQL Injection
- Command Injection

#### A04 - Insecure Design
- Fallos de diseño
- Ausencia de validación

#### A05 - Security Misconfiguration
- Configuración por defecto
- Directorios expuestos

#### A06 - Vulnerable Components
- Versiones obsoletas
- Dependencias vulnerables

#### A07 - Identification Failures
- Autenticación débil
- Sesiones inseguras

#### A08 - Software Integrity
- Actualizaciones inseguras
- Firma de código

#### A09 - Monitoring Failures
- Logs insuficientes
- Alertas no configuradas

#### A10 - Server-Side Request Forgery
- SSRF a servicios internos
- Lectura de archivos locales

## 2. Herramientas

```bash
# Escaneo
nmap -p 80,443 --script http-* <target>
whatweb http://<target>
nikto -h http://<target>

# Fuzzing
ffuf -w wordlist.txt -u http://<target>/FUZZ
gobuster dir -u http://<target> -w wordlist.txt

# Explotación
sqlmap -u "http://<target>/page?id=1" --batch
```
