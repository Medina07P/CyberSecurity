# 🧪 13_Labs - Laboratorios y Prácticas

Este directorio contiene configuraciones y notas para laboratorios de hacking.

## 📁 Estructura

| Directorio          | Descripción                    |
|---------------------|--------------------------------|
| `hackthebox/`       | Máquinas de HackTheBox         |
| `tryhackme/`        | Salas de TryHackMe             |
| `active_directory/` | Laboratorios AD                |
| `web_apps/`         | Aplicaciones web vulnerables   |
| `cloud/`            | Laboratorios en la nube        |

## 🚀 Uso Rápido

```bash
# Configurar HTB
./setup_lab.sh htb "Máquina"

# Configurar THM
./setup_lab.sh thm "Sala"

# Configurar AD
./setup_lab.sh ad "dominio.local"

# Configurar Web
./setup_lab.sh web "app.local"

# Configurar Cloud
./setup_lab.sh cloud "aws-lab"
```

## 📋 Flujo de Trabajo

```
1. Elegir laboratorio → hackthebox/ o tryhackme/
2. Configurar máquina → ./setup_lab.sh <tipo> <nombre>
3. Tomar notas       → notes.md
4. Documentar hallazgos
5. Aprender y practicar
```
