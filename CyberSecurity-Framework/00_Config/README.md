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

## Desde el gestor

| Opción | Qué hace |
|---|---|
| `1. run_all_config.sh` | Cuatro comprobaciones de solo lectura: validar, verificar, resumir objetivos y mostrar estado de claves |
| `2. config_wizard.sh` | Asistente que pregunta los objetivos y pide confirmar antes de escribir targets.txt |
| `3. validate_config.sh` | Comprueba archivos y directorios requeridos; devuelve 1 si falta alguno |
| `4. verify_00_config.sh` | Comprueba estructura y archivos esperados; devuelve 1 si falta alguno |
| `5. api_keys.py` | Abre el mismo menú guiado de claves que `K`; no hace falta escribir subcomandos |
| `6. parse_targets.py` | Muestra el resumen de los objetivos existentes, sin modificarlos |

En el menú de claves, `2` permite elegir herramienta e introducir sus claves;
`3` muestra el estado. `0` vuelve al módulo de configuración si entraste por
`00`, o al menú principal si entraste por `K`. Las claves no se imprimen ni se
pasan como argumentos desde el menú guiado. Ver estado o cancelar no crea el
registro. No uses `sudo` para administrar claves de tu usuario normal.

«Ejecución directa» no es un error: esas herramientas no requieren argumentos
externos. El asistente hace sus propias preguntas; los validadores y el resumen
muestran resultados directamente.

`run_all_config.sh` funciona desde cualquier directorio. No abre asistentes ni
pide, importa o sincroniza claves automáticamente. Continúa tras un paso fallido,
muestra su código y stderr, y termina con **1 y resumen parcial** si falló alguno;
solo anuncia éxito con **0** si pasaron los cuatro. Que falten claves opcionales
aparece en el estado, pero no es por sí solo un error de lectura del registro.

## Desde terminal

```bash
# Validar configuración
./scripts/validate_config.sh

# Alta guiada de objetivos (pregunta host, puerto, protocolo, descripción y prioridad)
./scripts/config_wizard.sh

# Parsear objetivos
python3 scripts/parse_targets.py

# Estado de claves sin modificar configuración (la CLI mantiene subcomandos)
python3 scripts/api_keys.py estado

# Resumen y exportación explícita; errores de lectura/escritura salen con 1
python3 scripts/parse_targets.py --input ../targets.txt --summary
```

En parse_targets, `--input` relativo se resuelve respecto a `scripts/`; las rutas
de salida `--json`/`--csv` son relativas al directorio del llamador. Los archivos
de objetivos se leen/escriben como UTF-8. La CLI de api_keys sin subcomando sigue
mostrando ayuda: el menú del gestor es quien proporciona la interfaz guiada.

Pruebas aisladas: `bash CyberSecurity-Framework/tests/run_config_menu.sh` desde
la raíz. Recorren las seis opciones sin leer ni modificar claves/objetivos reales.
