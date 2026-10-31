# 1. Asegúrate de estar en el directorio correcto (desde la raíz del repo)
cd CyberSecurity-Framework/03_Scanners

# 2. Copia cada script (uno por uno) y ejecuta los comandos de arriba

# 3. Verifica que todos tengan permisos
chmod +x run_all_scanners.sh
chmod +x network_scanners/nmap/*.sh
chmod +x network_scanners/masscan/*.sh
chmod +x network_scanners/rustscan/*.sh
chmod +x web_scanners/nikto/*.sh
chmod +x web_scanners/nuclei/*.sh

# 4. Prueba
./run_all_scanners.sh 192.168.1.10
