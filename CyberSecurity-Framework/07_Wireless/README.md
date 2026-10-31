# 📡 07_Wireless - Seguridad Inalámbrica

Herramientas para auditoría de redes WiFi y Bluetooth.

## 📁 Estructura

| Directorio | Descripción |
|-----------|-------------|
| `wifi/` | Ataques y escaneo WiFi |
| `bluetooth/` | Escaneo y ataques Bluetooth |
| `captures/` | Capturas de paquetes |
| `scripts/` | Utilidades para wireless |

## 🚀 Uso Rápido

```bash
# Escanear redes WiFi
./wifi/wifi_scan.sh wlan0

# Capturar handshake
./wifi/wifi_handshake.sh wlan0

# Atacar red
./wifi/wifi_deauth.sh wlan0 <BSSID> <CHANNEL>

# Escanear Bluetooth
./bluetooth/bt_scan.sh