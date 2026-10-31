# Unificación de rutas de resultados — 2026-10-30

Diseño aprobado antes de tocar código. Cierra el pendiente 1 de
`CLEANUP-2026-10-30.md` y el 2 (`linux_priv_esc.md`).

## Por qué

Hoy conviven **tres** convenciones y ninguna se autolocaliza, así que el destino
de un resultado depende del directorio desde el que se lanza el script:

| Prefijo | Dónde | Lanzado desde el directorio del módulo acaba en |
|---|---|---|
| `../../scans/` | 8 de `03_Scanners`, 4 de `05_Exploitation`, 3 de `09_Automation` | `<repo>/scans/` |
| `../scans/` | 12 de `04_Enumeration`, 5 de `05_Exploitation` | `CyberSecurity-Framework/scans/` |
| `scans/` a secas | `run_all_scanners.sh:31` | `03_Scanners/scans/nmap/` (una cuarta ubicación, y sin `mkdir`) |

Es el mismo fallo que se corrigió con las rutas `~/` el 30, solo que en relativo.
`05_Exploitation` incluso se contradice entre hermanos: `ssh_bruteforce.sh` usa
`../../scans/network` y `ssh_attack.sh` usa `../scans/network`. Y
`run_all_scanners.sh:31` escribe sin `mkdir -p`.

## Decisión

**Un único árbol, `<repo>/scans/<herramienta>/`, resuelto desde el propio script.**

Cada script calcula su ruta absoluta a partir de `${BASH_SOURCE[0]}` y cuenta
niveles hasta la raíz del repo, que es el padre de `CyberSecurity-Framework/`:

- Scripts a profundidad 3 (`03_Scanners/<cat>/<tool>/x.sh`):
  `SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)/scans"`
- Scripts a profundidad 2 (`04_Enumeration/<sub>/x.sh`, `05_Exploitation/<sub>/x.sh`,
  `09_Automation/bash/x.sh`, `02_Recon/scripts/x.sh`):
  `SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/scans"`
- Scripts a profundidad 1 (`03_Scanners/run_all_scanners.sh`,
  `04_Enumeration/run_all_enum.sh`, `04_Enumeration/show_results.sh`):
  `SCANS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scans"`

Y `OUTPUT_DIR="$SCANS_DIR/<herramienta>"`, que es lo único que cambia en los
scripts hoja: `mkdir -p` y el resto del cuerpo siguen intactos.

Los tres orquestadores (`run_all_scanners.sh`, `run_all_enum.sh`,
`show_results.sh`) además hacen `cd "$(dirname "${BASH_SOURCE[0]}")"` al
empezar, porque invocan a sus hijos con rutas como `./network_scanners/nmap/...`
y hoy solo funcionan si los lanzas desde el directorio del módulo.

## Alternativas descartadas

- **`CyberSecurity-Framework/scans/`**: el framework quedaría autocontenido y
  viajaría a Kali con sus resultados. Se descarta porque mezcla datos con código,
  obliga a vaciar el `scans/` de la raíz (que ya tiene datos) y a tocar
  `AGENTS.md` en sentido contrario a lo que ya documenta.
- **Librería compartida `00_Config/lib/paths.sh`**: evita repetir el cálculo en
  38 scripts y sobrevive a mover ficheros. Se descarta porque para hacer
  `source` hay que resolver primero la ruta del propio `lib`, o sea el mismo
  problema de contar niveles; y porque ningún script del repo importa nada hoy.
  House style: cada script es autónomo.
- **Variable de entorno `SCANS_ROOT` para sobrescribir**: útil, pero nadie la ha
  pedido y añade una rama que hay que documentar. Fuera de alcance.

## Alcance

| Grupo | Ficheros | Cambio |
|---|---|---|
| `03_Scanners/network_scanners/{nmap,masscan,rustscan}` + `web_scanners/{nikto,nuclei}` | 8 | `OUTPUT_DIR` absoluto |
| `03_Scanners/run_all_scanners.sh` | 1 | `cd` + `SCANS_DIR` para el `nmap` de respaldo (con `mkdir -p`) |
| `04_Enumeration/{ssh,ftp,smb,ldap,web,database,api}` | 12 | `OUTPUT_DIR` absoluto |
| `04_Enumeration/run_all_enum.sh`, `show_results.sh` | 2 | `SCANS_DIR` absoluto + `cd` |
| `05_Exploitation/{web,network,database,wireless,active_directory}` | 11 | `OUTPUT_DIR` absoluto |
| `09_Automation/bash/{auto_recon,auto_enum,auto_exploit}.sh` | 3 | `OUTPUT_DIR` absoluto |
| `12_Knowledge_Base/cheatsheets/linux_priv_esc.md` | 1 | ampliar (pendiente 2) |
| `AGENTS.md`, `docs/CLEANUP-2026-10-30.md` | 2 | reflejar la convención única |

Total: **37 scripts** (34 hojas + 3 orquestadores).

No se toca: `00_Config/`, `01_OSINT/`, `06_PostExploitation/`, `07_Wireless/`,
`08_Forensics/`, `10_Evidence/` (escribe en `screenshots/`), `11_Reports`,
`13_Labs`, ni los 7 wrappers generadores.

## Correcciones hechas al ejecutar

Dos cosas que este diseño daba por dentro del alcance y no lo están. Se
verificaron leyendo el código, no se dedujeron:

- **`02_Recon/scripts/auto_recon.sh` queda fuera.** Sus `scans/vuln_scan.txt` y
  `scans/cves_encontrados.txt` no son el árbol global: el script hace
  `cd "$OUTPUT_DIR"` (línea 55) a un bundle propio
  `<framework>/02_Recon/recon_<target>_<ts>/`, creado en la línea 54 con una
  subcarpeta `scans`. Son relativas a ese bundle, que es intencionado. Cambiarlas
  a `$SCANS_DIR` habría sacado los CVEs fuera del informe del reconocimiento.
- **`05_Exploitation/web/reverse_shell_php.sh` quedó fuera en la primera
  pasada y luego se corrigió.** Escribe payloads, no resultados de escaneo, así
  que no entraba en esta unificación. Pero tenía el mismo defecto: su
  `OUTPUT_DIR="../../payloads/web_shells"` resolvía a
  `<repo>/payloads/` si se lanzaba desde `05_Exploitation/` y a
  `CyberSecurity-Framework/payloads/` si se lanzaba desde `05_Exploitation/web/`
  — es decir, a ninguna de las dos ubicaciones que documentan `README.md` y
  `05_Exploitation/README.md`, que sitúan `payloads/` dentro de
  `05_Exploitation/`. Ahí es donde ya existe `web_shells/php_shell.php`.
  Corregido a `"$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/payloads/web_shells"`.

## Correcciones posteriores (misma sesión)

Dos scripts estaban **truncados**: abrían un `heredoc` y no lo cerraban. `bash -n`
devolvía 0 y solo emitía un *warning* por stderr, que es lo que los dejó pasar el
2026-10-30.

| Fichero | Qué faltaba |
|---|---|
| `01_OSINT/scripts/social_media_search.sh` | el `EOF` de cierre, `mkdir -p "$OUTPUT_DIR"` (el redirect fallaba si el directorio no existía) y el mensaje final |
| `05_Exploitation/web/reverse_shell_php.sh` | el `EOF` de cierre y la confirmación; el `.php` generado quedaba sin cerrar |

No hay copia en la cuarentena ni historial en git (en ese momento el framework
estaba untracked),
así que los bytes originales no son recuperables: se completaron en el estilo de
la casa (`echo "✅ ..."`, comprobación de que el fichero se escribió). Verificado
que el PHP generado conserva `$ip`/`$port` literales y expande `LHOST`/`LPORT`.

## Migración de datos

`CyberSecurity-Framework/scans/` tiene **29** ficheros en 4 subdirectorios
(`database`, `network`, `ssh`, `web`). Se mueven a `<repo>/scans/` fusionando;
solo `network/` existe en ambos y no hay colisión de nombres (raíz:
`ssh_brute_*.txt`; framework: `ssh_credentials.txt`, `ssh_hydra_*.txt`,
`ssh_users.txt`). Quedan 54 ficheros (25 + 29). Después se retira el `scans/`
vacío del framework.

## Verificación

Lo que este checkout **sí** puede probar:

1. `bash -n` sobre los 113 `.sh` → 0 fallos.
2. Prueba de comportamiento en sandbox: copia del repo a un directorio temporal,
   `nmap`/`nikto`/`nuclei`/`ffuf` sustituidos por stubs en `PATH` que solo
   escriben un fichero, ejecutar cada script desde **tres** `cwd` distintos
   (raíz, directorio del módulo, `/tmp`) y comprobar que en los tres casos el
   resultado aparece en `<repo>/scans/<herramienta>/` y en ningún otro sitio.
3. `show_results.sh` desde un `cwd` ajeno → encuentra los datos migrados.
4. Comprobar que no queda ninguna referencia `../scans` ni `../../scans` en el
   framework.

Lo que **no** se puede probar aquí: un escaneo real contra un objetivo. Eso
sigue pendiente (punto 3 del traspaso) y no se afirmará como hecho.

## Cómo verificarlo en Kali (pendiente)

Lista para ejecutar en el laboratorio. Cada paso dice qué debe verse.

```bash
# 1. Clonar o copiar el repo y situarse FUERA del framework
cd /ruta/al/repo

# 2. Un script hoja lanzado desde la raíz del repo
bash CyberSecurity-Framework/03_Scanners/network_scanners/nmap/nmap_smart.sh 127.0.0.1
ls -la scans/nmap/                      # smart_ports.* y smart_services.* aquí
test ! -e CyberSecurity-Framework/scans && echo "OK: no hay segundo arbol"

# 3. El mismo script desde su propio directorio
cd CyberSecurity-Framework/03_Scanners/network_scanners/nmap
./nmap_smart.sh 127.0.0.1               # debe escribir en el MISMO scans/nmap/

# 4. Un orquestador desde un directorio cualquiera
cd /tmp
bash /ruta/al/repo/CyberSecurity-Framework/03_Scanners/run_all_scanners.sh 127.0.0.1

# 5. La enumeración y su visor
bash /ruta/al/repo/CyberSecurity-Framework/04_Enumeration/run_all_enum.sh 127.0.0.1
bash /ruta/al/repo/CyberSecurity-Framework/04_Enumeration/show_results.sh

# 6. Payloads en su sitio documentado
bash /ruta/al/repo/CyberSecurity-Framework/05_Exploitation/web/reverse_shell_php.sh 10.10.10.10 4444
ls CyberSecurity-Framework/05_Exploitation/payloads/web_shells/
php -l CyberSecurity-Framework/05_Exploitation/payloads/web_shells/shell_10.10.10.10_4444.php
```

Señales de que algo sigue mal:

- aparece un `scans/` nuevo en el `cwd` desde el que lanzaste;
- `CyberSecurity-Framework/scans/` vuelve a existir;
- `show_results.sh` no encuentra datos que sí están en `scans/`;
- el `.php` generado falla `php -l` o contiene `$ip` vacío.

Recordar que el paso 5 lanza enumeración real contra el objetivo: solo dentro del
alcance de `00_Config/scope.yaml`.
