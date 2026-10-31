# Ejecutar desde el directorio 10_Evidence
# (evidence_manager.sh y auto_capture.sh crean sus propios directorios)

# Agregar una evidencia
./evidence_manager.sh --add screenshot captura.png "Login page"

# Capturar todo de un target
./run_all_evidence.sh 192.168.1.10
