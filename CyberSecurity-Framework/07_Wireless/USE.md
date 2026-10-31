# 1. Ver interfaces disponibles
./scripts/interface_manager.sh list

# 2. Escanear redes WiFi
./wifi/wifi_scan.sh wlan0

# 3. Activar modo monitor
./scripts/interface_manager.sh monitor wlan0

# 4. Capturar handshake (necesitas BSSID y canal)
./wifi/wifi_handshake.sh wlan0mon

# 5. Ataque de desautenticación
./wifi/wifi_deauth.sh wlan0mon 00:11:22:33:44:55 6

# 6. Craquear handshake
./wifi/wifi_crack.sh handshake-01.cap

# 7. Escanear Bluetooth
./bluetooth/bt_scan.sh

# 8. Ejecutar todo
./run_all_wireless.sh wlan0
