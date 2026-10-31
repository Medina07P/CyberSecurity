# METODOLOGÍA DE AUDITORÍA WIRELESS

## 1. Fases

### 1.1 Descubrimiento
- Identificar redes
- Canal y frecuencia
- BSSID y ESSID

### 1.2 Análisis
- Tipo de encriptación (WEP, WPA, WPA2, WPA3)
- Intensidad de señal
- Dispositivos conectados

### 1.3 Ataques

#### WPA/WPA2
- Captura de handshake
- Fuerza bruta
- Ataque de deautenticación

#### WEP
- IV replay
- ARP poisoning
- Cracking con aircrack

#### WPS
- PIN brute force
- Pixie dust

### 1.4 Post-Explotación
- Acceso a la red
- Análisis de tráfico
- Escaneo de red

## 2. Herramientas

```bash
# Escaneo
airodump-ng wlan0mon
wash -i wlan0mon

# Captura de handshake
airodump-ng -c <CHANNEL> --bssid <BSSID> -w capture wlan0mon

# Deauth
aireplay-ng -0 5 -a <BSSID> wlan0mon

# Cracking
aircrack-ng -w wordlist.txt capture-01.cap
```

## 3. Seguridad
- Usar solo en redes propias
- Obtener autorización
- Documentar procedimientos
