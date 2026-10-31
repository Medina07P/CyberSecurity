# DOCKER CHEATSHEET

## 1. Comandos Básicos

```bash
# Imágenes
docker images
docker pull <imagen>:<tag>
docker build -t <nombre> .

# Contenedores
docker ps
docker ps -a
docker run <imagen>
docker run -d <imagen>              # Detached
docker run -it <imagen> /bin/bash   # Interactivo

# Gestión
docker start <container>
docker stop <container>
docker restart <container>
docker rm <container>
docker rmi <imagen>
```

## 2. Contenedores Temporales

```bash
# Kali Linux
docker run -it kalilinux/kali-rolling /bin/bash

# Ubuntu
docker run -it ubuntu:22.04 /bin/bash

# Metasploit
docker run -it metasploitframework/metasploit-framework

# Nmap
docker run -it --rm instrumentisto/nmap <ip>
```

## 3. Volúmenes

```bash
# Montar volumen
docker run -v /host/path:/container/path <imagen>

# Crear volumen
docker volume create <nombre>
docker run -v <nombre>:/container/path <imagen>

# Inspeccionar volumen
docker volume inspect <nombre>
```

## 4. Redes

```bash
# Crear red
docker network create <nombre>

# Conectar a red
docker run --network <nombre> <imagen>

# Inspeccionar red
docker network inspect <nombre>
```

## 5. Docker Compose

```yaml
version: '3.8'
services:
  web:
    image: nginx
    ports:
      - "80:80"
  db:
    image: postgres
    environment:
      POSTGRES_PASSWORD: password
```

```bash
docker-compose up -d
docker-compose down
docker-compose logs
docker-compose exec <service> /bin/bash
```
