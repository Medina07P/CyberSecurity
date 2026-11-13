# syntax=docker/dockerfile:1
# BuildKit con Dockerfile.dockerignore es obligatorio; ver README.md de Docker.
FROM kalilinux/kali-rolling:latest

LABEL maintainer="kali@security.local"
LABEL description="CTF Toolkit Pro - Docker Image"

# Solo instalación durante build; disponibilidad operacional no validada.
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    nmap \
    masscan \
    hydra \
    ffuf \
    sqlmap \
    nikto \
    whatweb \
    wireshark \
    aircrack-ng \
    netcat-openbsd \
    curl \
    wget \
    git \
    python3 \
    python3-yaml \
    python3-requests \
    python3-bs4 \
    python3-scapy \
    python3-shodan \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --user-group --shell /bin/bash toolkit \
    && chmod 700 /home/toolkit
ENV HOME=/home/toolkit PYTHONDONTWRITEBYTECODE=1
WORKDIR /home/toolkit/CyberSecurity-Framework

# Cada directorio queda filtrado por nombres exactos en Dockerfile.dockerignore.
COPY --chown=toolkit:toolkit 00_Config/ ./00_Config/
COPY --chown=toolkit:toolkit 01_OSINT/ ./01_OSINT/
COPY --chown=toolkit:toolkit 03_Scanners/ ./03_Scanners/
COPY --chown=toolkit:toolkit 04_Enumeration/ ./04_Enumeration/
COPY --chown=toolkit:toolkit 05_Exploitation/ ./05_Exploitation/
COPY --chown=toolkit:toolkit 09_Automation/ ./09_Automation/
COPY --chown=toolkit:toolkit 11_Reports/ ./11_Reports/

USER toolkit
# No inicia gestor, auditoría, red ni instalación al entrar.
ENTRYPOINT ["/bin/bash", "--noprofile", "--norc"]
