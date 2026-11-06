# Prueba funcional en Kali y correcciones de rutas — 2026-10-31

Primera sesión en la que el framework se ejecutó de verdad, con las herramientas
instaladas, contra un objetivo vivo. Recoge los nueve fallos reproducidos, la causa
de cada uno, el arreglo y la evidencia. Cierra el pendiente 3 de
`CLEANUP-2026-10-30.md` ("un escaneo real contra un objetivo") y amplía
`SCANS-PATHS-2026-10-30.md`, que solo cubrió los resultados de escaneo: esta
sesión encontró que las salidas **que no son de escaneo** (loot, capturas,
evidencias, informes, correos) seguían dependiendo del `cwd`.

## Entorno

- Kali Linux. Red local `192.168.101.12/24`.
- La salida a internet resultó **parcial**: el DNS resuelve y algunas HTTPS
  responden (`api.github.com` devuelve 200), pero `theHarvester -b all` no
  termina en 90 s porque consulta más de veinte fuentes. Las pruebas de OSINT se
  hicieron con `ejemplo.com` (`example.com`, dominio reservado por la IANA para
  documentación), nunca con un dominio real de terceros.
- `00_Config/scope.yaml` autoriza `192.168.1.0/24` y `10.10.10.0/24`, no la red
  local. Por eso el objetivo de todas las pruebas fue **el propio host**:
  `127.0.0.1` (SSH 22, PostgreSQL 5432), un servidor HTTP propio en `:8080` y
  uno TLS en `:8443`. Ninguna prueba de escaneo salió de la máquina; el OSINT de
  `01` fue contra el dominio reservado `example.com`.
- Se probaron los módulos 00–13, tanto a mano como a través de
  `cyber_framework.sh` (sesión de objetivo, slots, modo manual, marcas de
  generador y estado de fase).

## Fallos confirmados

Cada uno se reprodujo primero, se arregló y se volvió a ejecutar el mismo caso.

| ID | Script | Síntoma observado | Causa raíz |
|---|---|---|---|
| B1 | `03_Scanners/web_scanners/nikto/nikto_scan.sh` | Contra el servidor HTTP de `:8080`, nikto aborta con "Unable to connect". Además el fichero de salida salía como `.txt.txt`. | `-ssl` se pasaba siempre, también en `http://`. Y se daba `-o nombre.txt` junto a `-Format txt`, pero nikto añade la extensión por su cuenta. |
| B2 | `03_Scanners/run_all_scanners.sh` | Detecta `8080` y `8443` abiertos, lo imprime… y luego lanza nikto y nuclei contra `http://TARGET` (puerto 80, cerrado). | `WEB_PORTS` se calculaba y no se usaba: los hijos recibían una URL sin puerto. |
| B3 | `02_Recon/scripts/ping_sweep.sh` | `./ping_sweep.sh 127.0.0.1` barre `127.0.0.1.1..254` (direcciones inexistentes) y termina diciendo "✅ 0 hosts activos encontrados". | Asume siempre un prefijo de tres octetos, y el mensaje de éxito era incondicional. |
| B4 | `04_Enumeration/run_all_enum.sh` | Un `8443` abierto se reporta como cerrado y no se enumera. | `8443` no estaba en la lista de `nmap -sV`, y `port_open` se fiaba de un `.gnmap` no vacío: si el puerto no se había escaneado, no aparecía y se daba por cerrado. |
| B5 | `03_Scanners/network_scanners/masscan/masscan_scan.sh` | Sin root: "No se encontraron puertos abiertos". | masscan necesita sockets raw; el script no comprobaba el uid y el mensaje culpaba al objetivo. |
| B6 | 39 scripts de 01/02/06/07/08/09/10/11 | La salida aparece en el `cwd` desde el que se lanza. Lanzado desde la raíz del repo, deja `loot/`, `emails/`, `analysis/`… fuera de los árboles ignorados; lanzado desde el módulo, en otro sitio. | Rutas relativas (`../loot`, `$(pwd)`, `.`) sin autolocalización. |
| B7 | `08_Forensics/timeline/timeline_creator.sh` | `last: orden no encontrada` al construir la línea de tiempo. | Usa `last` sin comprobar que exista. |
| B8 | `11_Reports/report_generator.sh` sin argumentos | "Opción no reconocida: " (con el valor vacío). | No hay rama para `$# -eq 0`. |
| B9 | `01_OSINT/scripts/osint_harvester.sh` | Al ejecutarlo desaparece la marca `[generador]` del menú y `tests/run_smoke.sh` empieza a fallar. | Se reescribe a sí mismo: su `TARGET_FILE` es su propia ruta, así que la primera ejecución sustituye el envoltorio por el payload. |

En el caso de B9 el fallo es de diseño, no de ejecución: el envoltorio *funciona*,
pero se consume. Se resolvió **materializando el payload**, igual que se hizo el
2026-10-30 con `05_Exploitation/exploits/reverse_shell.py` y
`09_Automation/python/auto_audit.py`, que tenían el mismo patrón. Quedan cuatro
envoltorios, todos con destino fuera del repo (`04_Enumeration/smb/enum_smb.sh`,
`04_Enumeration/web/deepseeenum_web.sh`, `06_PostExploitation/lateral_movement/ps_exec.sh`,
`06_PostExploitation/privilege_escalation/linpeas.sh`).

Aparte, un defecto transversal apareció al arreglar el **esquema** de las URLs:
cinco scripts asumían que solo el 443 es HTTPS, así que contra `:8443` hablaban
HTTP plano y la herramienta fallaba en silencio. Corregido en `enum_web.sh`,
`enum_web_advanced.sh`, `enum_api.sh`, `fingerprint.sh` y `auto_recon.sh`.

## Arreglos

| ID | Cambio |
|---|---|
| B1 | `-ssl` solo si `"$URL" == https://*`. El `-o` se pasa sin extensión (`NIKTO_BASE`) y la comprobación posterior mira `${NIKTO_BASE}.txt`. |
| B2 | Bucle `for WEB_PORT in ${WEB_PORTS//,/ }`; `https` en 443/8443, `http` en el resto; URL `esquema://TARGET:PUERTO` para nikto y nuclei. Un escaneo por puerto. |
| B3 | Acepta IP suelta, `a.b.c.d/24` o prefijo `a.b.c`. Valida el rango (`1-254`). Cuenta los hosts con un contador real y distingue "0 activos" de "encontrados". Salida a `$MODULE_DIR/host_discovery`. |
| B4 | `8443` añadido al descubrimiento. `port_open` solo se fía del `.gnmap` si el puerto **aparece** en él (`/open/`, `/closed/` o `/filtered/`); si no, prueba en vivo con `nmap -p`. |
| B5 | Comprobación de `id -u` con mensaje claro y `exit 1`, sugiriendo `sudo bash ${BASH_SOURCE[0]} …`. |
| B6 | Cada salida se ancla al módulo (ver tabla siguiente). `.gitignore` ampliado. |
| B7 | `command -v last` antes de usarlo; si no está, se escribe una nota en el informe en vez de ensuciar stderr. |
| B8 | `$# -eq 0` → `show_help` y `exit 1`. |
| B9 | Payload materializado: `osint_harvester.sh` pasa a ser el script final (con `OUTPUT_DIR` anclado a `01_OSINT/domains` y `mkdir -p`). `tests/run_smoke.sh` comprueba la marca `[generador]` en `06`, donde sí quedan generadores. |
| Esquema | `https` en `443` y `8443` en los cinco scripts de URL. |

### B6: dónde escribe ahora cada módulo

Patrón: `MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"` y
`OUTPUT_DIR="$MODULE_DIR/<dir>"`. Los orquestadores que invocan a sus hermanos
con rutas relativas (`run_all_evidence.sh`, `run_all_reports.sh`,
`report_generator.sh`, `evidence_manager.sh`) hacen además `cd` a su propio
directorio antes de usarlas.

| Módulo | Ficheros | Destino |
|---|---|---|
| `01_OSINT/scripts` | 5 | `01_OSINT/{domains,emails,metadata,social_media,subdomains}` |
| `02_Recon/scripts` | 4 | `02_Recon/{dns,fingerprinting,host_discovery,screenshots}` |
| `06_PostExploitation` | 10 | `06_PostExploitation/{loot/*,persistence}` |
| `07_Wireless` | 6 | `07_Wireless/captures/{logs,handshakes}` |
| `08_Forensics` | 8 | `08_Forensics/analysis/*`, `08_Forensics/recovered`, `captures/memory` |
| `09_Automation/python/auto_audit.py` | 1 | `<repo>/scans/audits/audit_<target>_<ts>/` |
| `10_Evidence` | 3 | `10_Evidence/{screenshots,pcaps,logs,proofs,findings,credentials}` |
| `11_Reports` | 2 | `11_Reports/{executive,technical,final_report}` |

Total: **39 scripts**. `osint_harvester.sh` era un generador que se reescribía a
sí mismo; el arreglo de ruta está en el script ya materializado (ver B9).

`.gitignore` incorpora lo que faltaba para que una ejecución desde la raíz del
repo no deje datos sin ignorar: `06_PostExploitation/loot/`,
`06_PostExploitation/persistence/`, `07_Wireless/captures/` y
`01_OSINT/emails/*.html`.

## Incidencia durante el arreglo: el parser de `Uso:`

La primera versión de la línea de `ping_sweep.sh` fue:

```bash
#  Uso: ./ping_sweep.sh <IP|RED> [rango]
```

`tests/run_tests.sh` empezó a fallar. `00_Config/lib/params.bash` parte cada slot
por `|` con el contrato `posicion|nombre|obligatorio|tipo`; el `|` del nombre se
leyó como separador y el campo "obligatorio" acabó conteniendo `RED> [rango]`.
La línea correcta es `Uso: ./ping_sweep.sh <red> [rango]`, con las alternativas
documentadas en un comentario y en el bloque de error. Queda escrito en
`AGENTS.md` porque afecta a cualquier script nuevo.

## Verificación

Ejecutado en este checkout tras los cambios:

| Comprobación | Resultado |
|---|---|
| `tests/run_tests.sh` | 61 pasan, 0 fallan |
| `tests/run_e2e.sh` | 11 pasan, 0 fallan |
| `tests/run_smoke.sh` | 0 fallos |
| `bash -n` sobre 116 `.sh` (capturando stderr) | 0 fallos |
| `python3 -m py_compile` sobre 6 `.py` | 0 fallos |
| `git status` | solo fuentes y docs; ninguna salida de prueba sin ignorar |

Además, caso por caso, se repitió la reproducción original:

- nikto contra `:8080` completa el escaneo y deja un único `.txt`.
- `run_all_scanners.sh` con stubs en `PATH` invoca nikto y nuclei con
  `http://…:8080` y `https://…:8443` (comprobado con stubs que registran argv).
- `ping_sweep.sh 127.0.0.1` comprueba un host, no 254.
- `run_all_enum.sh` enumera el 8443 abierto.
- `masscan_scan.sh` como usuario normal sale con código 1 y el mensaje de root.
- Los 39 scripts de B6: comprobación estática de que los 39 tienen ancla
  (`MODULE_DIR=` o `cd "$(dirname …)"`) y de que no queda ninguna asignación de
  salida relativa (`OUTPUT_DIR|OUT_DIR|EVIDENCE_DIR|REPORT_DIR="..|.|nombre"`)
  ni redirección `> ../`. Prueba de comportamiento desde `/tmp` con los doce que
  se pueden lanzar sin efectos: los cinco de `01_OSINT`, `file_collector`,
  `screenshot_collector`, `cron_check`, `suid_check`, `capabilities_check`,
  `history_parser` y `log_analyzer`. Ninguno dejó nada en `/tmp`; los que
  llegaron a escribir lo hicieron en el directorio de su módulo
  (`email_harvester` no llegó a escribir: se cortó en `theHarvester`, ver
  pendientes). Los de `persistence`, WiFi, Bluetooth,
  forense de disco y memoria no se ejecutaron: instalan persistencia o exigen
  imágenes y hardware que esta máquina no tiene.
- `timeline_creator.sh` termina sin error con y sin `last`.
- `report_generator.sh` sin argumentos muestra la ayuda.

Lo que **no** se ha probado y no se afirma: un escaneo contra un objetivo remoto
del alcance (el laboratorio no lo tenía), ni nada que dependa de hardware WiFi o
Bluetooth (esta máquina no tiene adaptador).

## Pendientes y notas de diseño

- **Herramientas ausentes**: `rustscan`, `volatility3`, `foremost` y el script
  `nmap-vulners` no están instalados, así que sus scripts no se pudieron probar
  más allá del mensaje de "no instalado". `masscan` requiere root por diseño.
- **`08_Forensics/run_all_forensics.sh` lee `../captures/pcap/*.pcap` y nada
  genera esos ficheros.** No se tocó: haría falta una captura externa
  (`tcpdump`) o un script que las produzca. Queda como incoherencia conocida.
- **Los informes generados pisan ficheros versionados**:
  `11_Reports/executive/executive_summary.md` y
  `11_Reports/technical/technical_report.md` están en git y `--all` los
  reescribe con la fecha del día. Se restauraron a mano tras la prueba. La
  decisión pendiente es sacarlos del índice (como el resto de salidas) o
  convertirlos en plantillas.
- **`01_OSINT/scripts/email_harvester.sh` puede tardar minutos**:
  `theHarvester -b all` consulta más de veinte fuentes y no tiene `timeout`
  (las fuentes sueltas sí terminan: `-b crtsh` en 7 s). No se acotó porque un
  `timeout` corta la recolección a medias y cambia el resultado; si molesta,
  cambiar `-b all` por las fuentes que interesen.
- **Ampliar el alcance para probar en red**: `scope.yaml` no cubre
  `192.168.101.0/24`. Cualquier prueba de red real exige autorización explícita
  previa; los orquestadores (`run_all_*`, opción `99`) encadenan fuerza bruta,
  persistencia y limpieza contra todos los objetivos configurados.
