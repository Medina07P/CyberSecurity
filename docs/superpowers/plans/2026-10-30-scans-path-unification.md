# Unificación de rutas de resultados — Plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Que los 38 scripts que escriben resultados lo hagan siempre en `<repo>/scans/<herramienta>/`, sin importar el directorio desde el que se lancen.

**Architecture:** Cada script resuelve la raíz del repo desde `${BASH_SOURCE[0]}` contando niveles hasta el padre de `CyberSecurity-Framework/`, y compone `OUTPUT_DIR="$SCANS_DIR/<herramienta>"`. Los tres orquestadores además se `cd` a su propio directorio porque invocan a sus hijos con rutas `./hermano/...`.

**Tech Stack:** Bash 4+, sin dependencias nuevas. Verificación con `bash -n` y un sandbox con stubs de herramientas en `PATH`.

**Spec:** `docs/SCANS-PATHS-2026-10-30.md`

## Global Constraints

- No añadir `set -e`: ningún script del repo lo usa.
- Mantener el estilo: `#!/bin/bash`, bloque de cabecera con `Uso:`/`Ejemplo:`, mensajes en español, `2>/dev/null`.
- Ficheros `.sh` en LF. No introducir `\r`.
- Ninguna ruta absoluta ni dependencia del `cwd`.
- No tocar `00_Config/`, `01_OSINT/`, `06_PostExploitation/`, `07_Wireless/`, `08_Forensics/`, `10_Evidence/`, `11_Reports/`, `13_Labs/`, ni los 7 wrappers generadores.
- No afirmar que se ha ejecutado un escaneo real: aquí no hay nmap/nikto/nuclei.

## Review Focus

- **Script lanzado desde la raíz del repo** (no desde el módulo): es como lo lanza `cyber_framework.sh` y como lo lanza cualquiera por costumbre. Debe escribir en el mismo sitio que lanzado desde el módulo.
- **`mkdir -p` ausente**: `run_all_scanners.sh:31` escribe en `scans/nmap/` sin crear el directorio. Tras el cambio debe crearlo.
- **Subdirectorio anidado**: `nuclei_cves.sh` y `nmap_scripts.sh` escriben en una carpeta hija (`nuclei/cves`, `nmap/scripts`), no en la raíz de su herramienta. No deben colapsarse a `<herramienta>/`.
- **Fichero con nombre que ya existe** en el árbol destino al fusionar `scans/`: `database`, `network`, `ssh`, `web` existen en los dos árboles. No se debe sobrescribir nada.
- **Ejecución desde fuera del repo** (p. ej. `/tmp`): la ruta se resuelve igual y no se crea un `scans/` huérfano en el `cwd`.

---

### Task 1: Fusionar los dos árboles de datos

**Files:**
- Modify: `scans/` (destino), `CyberSecurity-Framework/scans/` (origen, se retira)

**Interfaces:**
- Produces: `<repo>/scans/{database,network,ssh,web}/` con 31 ficheros más los 26 que ya había (57 en total).

- [x] **Step 1: Contar el punto de partida**

Run: `Get-ChildItem -Recurse -File .\scans, .\CyberSecurity-Framework\scans | Measure-Object`
Expected: 54 ficheros (25 + 29).

- [x] **Step 2: Mover sin sobrescribir**

Copiar cada fichero de `CyberSecurity-Framework/scans/<sub>/<f>` a `scans/<sub>/<f>`; si el destino ya existe, abortar y reportar en vez de sobrescribir.

- [x] **Step 3: Verificar y retirar el árbol viejo**

Run: `Get-ChildItem -Recurse -File .\scans | Measure-Object` → 54. Después borrar `CyberSecurity-Framework/scans/` solo si está vacío.
Expected: 54 ficheros en `scans/`, `CyberSecurity-Framework/scans/` inexistente.

> Resultado: 54 ficheros, 0 conflictos, los 29 verificados por SHA-256 antes de retirar el origen.

### Task 2: Scripts hoja a profundidad 3 (8 ficheros)

**Files:**
- Modify: `03_Scanners/network_scanners/{nmap/nmap_smart.sh,nmap/nmap_aggressive.sh,nmap/nmap_scripts.sh,masscan/masscan_scan.sh,rustscan/rustscan_scan.sh}`, `03_Scanners/web_scanners/{nikto/nikto_scan.sh,nuclei/nuclei_scan.sh,nuclei/nuclei_cves.sh}`

**Interfaces:**
- Consumes: nada.
- Produces: `SCANS_DIR` (ruta absoluta a `<repo>/scans`) y `OUTPUT_DIR="$SCANS_DIR/<herramienta>"` en cada fichero.

- [x] **Step 1: Sustituir la línea `OUTPUT_DIR`**

Antes de la línea `OUTPUT_DIR=`, insertar:

```bash
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)/scans"
```

y dejar `OUTPUT_DIR="$SCANS_DIR/<herramienta>"` conservando el sufijo exacto que ya tuviera (`nmap/scripts`, `nuclei/cves`).

- [x] **Step 2: Actualizar el comentario de cabecera** si menciona rutas relativas.

- [x] **Step 3: Verificar sintaxis**

Run: `bash -n <cada fichero>`
Expected: sin salida, código 0.

### Task 3: Scripts hoja a profundidad 2 (27 ficheros)

**Files:**
- Modify: `04_Enumeration/{ssh,ftp,smb,ldap,web,database,api}/*.sh` (12), `05_Exploitation/{web,network,database,wireless,active_directory}/*.sh` (11), `09_Automation/bash/*.sh` (3), `02_Recon/scripts/auto_recon.sh` (1)

**Interfaces:**
- Produces: `SCANS_DIR` y `OUTPUT_DIR` con la misma semántica que en Task 2.

- [x] **Step 1: Aplicar el mismo patrón con `../../..`**

```bash
SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/scans"
```

- [x] **Step 2: `02_Recon/scripts/auto_recon.sh` queda FUERA del alcance**

Al leerlo se vio que hace `cd "$OUTPUT_DIR"` (línea 55) a un bundle propio
`recon_<target>_<ts>/`, y sus `scans/vuln_scan.txt` y `scans/cves_encontrados.txt`
son relativas a ese bundle, no al árbol global. No se toca. Ver
"Correcciones hechas al ejecutar" en el diseño.

- [x] **Step 3: Verificar sintaxis** con `bash -n`.

### Task 4: Los tres orquestadores

**Files:**
- Modify: `03_Scanners/run_all_scanners.sh`, `04_Enumeration/run_all_enum.sh`, `04_Enumeration/show_results.sh`

**Interfaces:**
- Consumes: los hijos de Task 2 y 3, invocados con rutas `./hermano/...`.
- Produces: orquestadores que funcionan desde cualquier `cwd`.

- [x] **Step 1: `cd` al propio directorio** al principio del script, tras la cabecera.

- [x] **Step 2: `SCANS_DIR` a profundidad 1**: `"$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scans"`.

- [x] **Step 3: `run_all_scanners.sh:31`**: la rama de respaldo pasa a `-oN "$SCANS_DIR/nmap/basic_${TARGET}.txt"` y se le añade `mkdir -p "$SCANS_DIR/nmap"`.

- [x] **Step 4: Actualizar los comentarios de cabecera** que dicen "ejecutar desde 04_Enumeration/".

- [x] **Step 5: Verificar sintaxis** con `bash -n`.

### Task 5: Prueba de comportamiento en sandbox

**Files:**
- Create: `%TEMP%\opencode\scans-path-test\` (fuera del repo, efímero)

- [x] **Step 1: Copiar el repo a un directorio temporal** y poner en `PATH` stubs de `nmap`, `nikto`, `nuclei`, `ffuf`, `hydra`, `masscan`, `rustscan` que escriban un fichero y salgan 0.

- [x] **Step 2: Ejecutar cada uno de los 35 scripts hoja desde tres `cwd` distintos** (raíz del repo, directorio del módulo, directorio fuera del repo).

- [x] **Step 3: Assert**: en los tres casos aparece el resultado en `<repo>/scans/<herramienta>/` y no se crea ningún `scans/` nuevo en otro sitio.

- [x] **Step 4: `show_results.sh`** desde un `cwd` ajeno encuentra los datos.

### Task 6: Documentación

**Files:**
- Modify: `AGENTS.md`, `04_Enumeration/README.md`, `docs/CLEANUP-2026-10-30.md`

- [x] **Step 1:** `AGENTS.md`: fijar la convención única y quitar la mención al "segundo repo-root `scans/`".
- [x] **Step 2:** `04_Enumeration/README.md`: dejar de decir `../scans`.
- [x] **Step 3:** marcar el pendiente 1 como cerrado en `docs/CLEANUP-2026-10-30.md` con puntero a este plan.

### Task 7: Ampliar `linux_priv_esc.md`

**Files:**
- Modify: `CyberSecurity-Framework/12_Knowledge_Base/cheatsheets/linux_priv_esc.md`

- [x] **Step 1:** Añadir secciones SUID/SGID (incluido GTFOBins), cron, capabilities, kernels vulnerables, credenciales en ficheros, sudo y grupos, tty escapes y herramientas (linpeas, pspy, linux-exploit-suggester), manteniendo el formato de `windows_priv_esc.md`.

- [x] **Step 2:** Quitar la nota "> Pendiente ampliar...".

- [x] **Step 3:** Verificar que no contiene rutas absolutas ni de `$HOME`.
