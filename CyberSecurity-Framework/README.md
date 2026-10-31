# Cybersecurity Framework

Framework de auditoría por fases. La vía de entrada es el gestor interactivo:

```bash
./cyber_framework.sh
```

## Estructura de Directorios

```
CyberSecurity-Framework/
├── cyber_framework.sh  # Gestor interactivo (punto de entrada)
├── 00_Config/          # Configuración, alcance y objetivos
│   └── lib/            # Librería del gestor (parser, sesión, fases, prompts)
├── 01_OSINT/           # Recopilación de información
├── 02_Recon/           # Reconocimiento activo
├── 03_Scanners/        # Escáneres y herramientas
├── 04_Enumeration/     # Enumeración de servicios
├── 05_Exploitation/    # Explotación controlada
├── 06_PostExploitation/# Post-explotación
├── 07_Wireless/        # Seguridad inalámbrica
├── 08_Forensics/       # Forense y análisis
├── 09_Automation/      # Automatización y scripts
├── 10_Evidence/        # Evidencias recolectadas
├── 11_Reports/         # Informes y documentación
├── 12_Knowledge_Base/  # Base de conocimiento
├── 13_Labs/            # Laboratorios y prácticas
└── tests/              # Pruebas del gestor
```

## Ciclo de Operación

```
Target → OSINT → Recon → Scanners → Enumeration →
Exploitation → Post-Exploitation → Evidence → Report
```

El gestor muestra en todo momento en qué fase estás y cuál viene después, y
avisa cuando una fase previa no tiene resultados todavía. No bloquea: alguien que
sepa lo que hace puede saltarse el orden.

## Uso

1. Ejecuta `./cyber_framework.sh`.
2. Define el objetivo con la opción `T` (o elígelo de `00_Config/targets.txt`).
   Queda guardado para toda la sesión.
3. Configura el alcance en `00_Config/scope.yaml` y los objetivos en
   `00_Config/targets.txt`.
4. Recorre los módulos en orden numérico.

Cada script declara los datos que necesita en su propia línea `Uso:`, y el gestor
los pregunta. No hay que recordar banderas.

## Resultados

Todos los scripts escriben en `<repo>/scans/<herramienta>/`, se lancen desde
donde se lancen. Esa carpeta y el resto de datos de sesión están en `.gitignore`:
contienen IPs y hallazgos reales y no se versionan.

## Pruebas

```bash
./tests/run_tests.sh    # librería del gestor
./tests/run_e2e.sh      # un script recibe de verdad el argumento tecleado
./tests/run_smoke.sh    # navegación del menú con entrada simulada
```

No necesitan terminal interactiva ni herramientas de pentesting instaladas.
