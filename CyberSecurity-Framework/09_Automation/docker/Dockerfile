FROM kalilinux/kali-rolling:latest

LABEL maintainer="kali@security.local"
LABEL description="CTF Toolkit Pro - Docker Image"

# Instalar herramientas básicas
RUN apt-get update && apt-get install -y \
    nmap \
    masscan \
    hydra \
    ffuf \
    sqlmap \
    nikto \
    whatweb \
    wireshark \
    aircrack-ng \
    hydra \
    netcat \
    curl \
    wget \
    git \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Instalar herramientas adicionales
RUN pip3 install --upgrade pip && \
    pip3 install shodan \
    requests \
    beautifulsoup4 \
    scapy \
    pyyaml

# Crear directorio de trabajo
WORKDIR /opt/ctf-toolkit

# Copiar archivos del framework
COPY . .

# Configurar alias
RUN echo 'alias ctf="cd /opt/ctf-toolkit"' >> ~/.bashrc

ENTRYPOINT ["/bin/bash"]
