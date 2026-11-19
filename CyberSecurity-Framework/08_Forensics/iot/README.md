# 08 · IoT y soporte portátil

Cuatro hojas para el ciclo de vida de un USB/SD o de un árbol ya recuperado:
adquirir, triar, consultar reputación de hashes y esterilizar. **Ninguna se
ejecuta sola**: no forman parte de `run_all_forensics.sh` ni de `99`, no
adquieren hardware por entrar al módulo y todas piden su token literal.

| Hoja | Uso | Token / privilegio |
|---|---|---|
| `iot_acquire.sh` | `./iot_acquire.sh <DEVICE> [OUTPUT_DIR] [--size-mib N]` | `ADQUIRIR_SOPORTE`; root ya disponible |
| `iot_triage.sh` | `./iot_triage.sh <DIR> [--investigator NOMBRE] [--exiftool] [--exiftool-limit N]` | ninguno; offline |
| `iot_vt_lookup.sh` | `./iot_vt_lookup.sh <RUN_DIR> [--limit N] [--delay S] [--api-base URL]` | `CONSULTAR_VIRUSTOTAL` + `VT_API_KEY` |
| `iot_sterilize.sh` | `./iot_sterilize.sh <DEVICE> --size-mib N [--wipe zeros\|urandom\|both] [--passes 1-7] [--filesystem none\|vfat]` | `ESTERILIZAR_SOPORTE`; root ya disponible |

## Reglas comunes

- **Sin escalada automática.** Si no eres root, la hoja usa `sudo -n`: o ya
  hay credenciales en caché o falla con rc2. Nunca pide contraseña ni ejecuta
  `sudo` interactivo. Esto replica el contrato de `memory/memory_dump.sh`.
- **Soporte desmontado.** `device-guard` rechaza cualquier partición del
  dispositivo que esté montada, además de `loop`, `ram`, `zram`, `dm-*`,
  `md*`, `sr*` y `nbd*` (son dispositivos virtuales o de solo lectura). Los
  enlaces simbólicos se rechazan en toda la ruta: usa el nodo real
  (`/dev/sdb`), no `/dev/disk/by-id/…`.
- **Tamaño exacto para escribir.** La adquisición acepta `--size-mib`
  opcional (solo comprueba coherencia); la esterilización lo exige y no escribe
  un byte sin él, porque un `dd` a ciegas sobre el dispositivo equivocado es
  irreversible.
- **Sin IP de sesión.** La identidad forense es el dispositivo o el árbol que
  pasas; `08` nunca toma el objetivo de `00_Config/.session`.
- **Rutas privadas.** Los runs viven en `analysis/runs/run-<32hex>/` con modos
  `700/600`; los productos de recuperación en `recovered/run-<32hex>/`
  (`FORENSICS_RECOVERED_ROOT`). Ambas raíces son configurables por entorno y
  están ignoradas por git.

## Adquisición (`iot_acquire.sh`)

```bash
bash 08_Forensics/iot/iot_acquire.sh /dev/sdb
bash 08_Forensics/iot/iot_acquire.sh /dev/sdb --size-mib 14901
```

`forensics_begin acquisition physical` + `observe_device` + `dd
if=<dev> of=<raíz>/image.dd bs=1M conv=noerror,sync`. Además de la imagen
publica `image.json` con `bytes`, `sha256`, `device_bytes`, `dd_rc` y
`completitud_soporte: no_verificada`.

Estados que importan:

- `dd` con `conv=noerror,sync` **rellena** los bloques ilegibles. Que termine
  con rc0 no demuestra lectura íntegra: sin tamaño observado, o con un tamaño
  distinto del dispositivo, el producto queda `PARCIAL`.
- Si el paso `dd_image` no llega a ejecutarse (captura estructural fallida), la
  hoja sale antes de hashear y el run queda bloqueado: no hay imagen «usable».
- Un SHA-256 que no se puede calcular deja el producto en `FALLIDO`; la imagen
  se conserva para inspección manual, nunca se borra.
- La imagen **no se monta**. El carving automático siguiente es
  `disk/file_carving.sh <image.dd>` (Foremost/Scalpel o ddrescue con
  `--physical`).

## PhotoRec: guiado, no por lotes

En esta máquina PhotoRec 7.2 con `/cmd` abre la TUI y puede salir con rc0 sin
recuperar nada. Se probaron varias invocaciones (`/cmd`, `/d`, `/q`, listas de
tipos) y ninguna es automatizable de forma fiable, así que:

- **no** hay paso `photorec` en esta carpeta ni en `run_all_forensics.sh`;
- si lo usas, hazlo a mano sobre la imagen adquirida y no interpretes «rc0 sin
  archivos» como «no había nada que recuperar»;
- el carving repetible y revisable es `disk/file_carving.sh`.

## Triaje (`iot_triage.sh`)

Copia el árbol completo al `work/` del run, verifica la copia (SHA-256 por
archivo) y analiza **la copia**, nunca el original. El original no se toca y
sus permisos no se usan como prueba.

- Familia por **firma** (magic bytes) y, si no hay firma conocida, por
  extensión (`firma: EXTENSION`). Con `--exiftool` añade metadatos de los
  primeros `--exiftool-limit` archivos; sin exiftool instalado la hoja sale con
  rc2 antes de crear run, y si falla en un archivo se omite ese campo sin
  abortar el triaje.
- Duplicados exactos marcados por SHA-256 (`duplicado_de`), no por nombre.
- Informes privados `report.json` y `report.md` en `analysis/` del run.
- Árbol vacío ⇒ `NO_EVALUABLE` y rc1: es un resultado, no un éxito.
- Symlinks o nodos especiales en el árbol ⇒ rechazo antes de generar informe
  (`FALLIDO`, `dependents_blocked`): evita leer fuera del árbol o bloquearse
  con un FIFO.
- Un hash o una firma **no** demuestran autoría, intención ni malware.

## VirusTotal v3 (`iot_vt_lookup.sh`)

```bash
export VT_API_KEY='...'        # variable de entorno, jamás argv ni fichero
bash 08_Forensics/iot/iot_vt_lookup.sh 08_Forensics/analysis/runs/run-<id>
```

- Solo se envían **hashes SHA-256** a `GET /api/v3/files/<hash>` con cabecera
  `x-apikey`. Nunca se sube el archivo ni el contenido del informe.
- Destino admitido: `https://…virustotal.com` o loopback explícito (pruebas).
  HTTP en claro fuera de loopback y `--delay < 15` contra la API pública se
  rechazan antes de crear run.
- `--limit N` (por defecto 4) acota la tanda; `--limit 0` la desactiva.
- `404` ⇒ `NO_CONOCIDO` (no es «limpio»). `401/403/429` o error de red
  detienen la tanda sin inventar veredictos; el run queda `PARCIAL` o
  `FALLIDO` según el caso.
- El run es `lookup network` y guarda `vt.json`/`vt.md` con
  `origen.run` + `report_sha256` del informe consultado, para que se sepa
  exactamente qué hashes se enviaron. No copia el informe ajeno ni lo
  convierte en evidencia del run.
- Compartir hashes con un tercero es una salida de datos: confirma que puedes
  hacerlo antes de lanzarlo.

## Esterilización (`iot_sterilize.sh`)

**Destructiva e irreversible.** Pensada para devolver un soporte tras el
análisis, no para ocultar evidencia.

```bash
bash 08_Forensics/iot/iot_sterilize.sh /dev/sdb --size-mib 14901
bash 08_Forensics/iot/iot_sterilize.sh /dev/sdb --size-mib 14901 \
    --wipe both --passes 2 --filesystem vfat
```

- `--wipe zeros` escribe ceros y **verifica** inicio/fin a cero;
  `--wipe urandom` escribe aleatorio y **no** se verifica (no hay forma barata
  de comprobarlo). `both` alterna ambos por pasada.
- `--passes 1-7` repite el ciclo; no se aceptan más pasadas por accidente.
- `--filesystem vfat` ejecuta `mkfs.vfat -I -F 32` y comprueba la firma FAT del
  sector de arranque. `--filesystem none` deja el soporte sin formatear.
- **No crea un run** ni artefactos forenses. Escribe un recibo privado y un
  log en `analysis/sterilizations/` (`sterilize-<dev>-<UTC>.json/.log`), fuera
  del almacén de runs, con el estado `COMPLETADO`/`PARCIAL`/`CANCELADO` y el rc
  de cada fase.
- `SIGINT`/`SIGTERM` dejan constancia (`CANCELADO`) y no formatean: el soporte
  queda en un estado intermedio que el recibo declara.
- No certifica un borrado seguro normativo (NIST 800-88 / DoD): solo acredita
  qué se ejecutó y qué se pudo verificar.

## Dependencias

`requirements.sh --check` informa también de `photorec`, `exiftool`,
`sha256sum` y `mkfs.vfat`. Sigue haciendo solo `command -v`: presencia en PATH
no acredita versión, permisos ni compatibilidad. `--install` conserva su lista
histórica; esos cuatro son opcionales y no se instalan desde el gestor.

## Pruebas

`tests/test_forensics_iot.py` (dentro de `tests/run_forensics.sh`) usa árboles
sintéticos, un proveedor VirusTotal v3 en loopback y `dd`/`sudo`/`exiftool`/
`sha256sum` como stubs de PATH cerrado, sin root. Acredita contratos de token,
rechazo de entrada, triaje real de la copia y formato de las consultas —
**no** lectura de hardware, borrado real ni veredictos reales de VirusTotal.
