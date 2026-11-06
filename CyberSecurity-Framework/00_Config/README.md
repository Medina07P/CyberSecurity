# Configuración

## Archivos
- `scope.yaml` - Alcance de la auditoría
- `targets.txt` - Lista de objetivos
- `credentials/` - Credenciales seguras
- `wordlists/` - Diccionarios personalizados
Este directorio contiene todos los archivos de configuración, alcance y objetivos para tus auditorías.

## 📁 Estructura

| Archivo/Directorio | Descripción |
|-------------------|-------------|
| `scope.yaml` | Alcance de la auditoría (IPs, métodos, reglas) |
| `targets.txt` | Lista de objetivos con puertos y servicios |
| `wordlists/` | Diccionarios personalizados para fuzzing y fuerza bruta |
| `credentials/` | Credenciales encontradas (¡MANTENER SEGURO!) |

## 🚀 Uso Rápido

```bash
# Validar configuración
./scripts/validate_config.sh

# Alta guiada de objetivos (pregunta host, puerto, protocolo, descripción y prioridad)
./scripts/config_wizard.sh

# Parsear objetivos
python3 scripts/parse_targets.py
```
