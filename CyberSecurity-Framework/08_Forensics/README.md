# 08_Forensics — fuentes explícitas, resultados privados

El menú `08` separa comprobación local, análisis offline, adquisición local,
disco/recuperación, flujo, visor e IoT/soporte portátil. Entrar, cancelar o EOF
no ejecuta herramientas. No utiliza la IP de sesión como identidad forense.
[Uso y límites](USE.md).

## Diez entradas originales conservadas

| Entrada | Métodos / cobertura |
|---|---|
| `requirements.sh` | Disponibilidad; instalación solo explícita y confirmada |
| `run_all_forensics.sh` | Flujo por fuentes elegidas; recorrido local explícito |
| `memory/memory_dump.sh` | AVML, wrapper LiME preparado, dd histórico acotado |
| `memory/volatility_analysis.sh` | Windows v2/v3: identificación, procesos, árboles, conexiones, DLL, historial |
| `memory/strings_analysis.sh` | Strings, patrones sensibles, URLs, correos |
| `disk/disk_forensics.sh` | Metadata/particiones/filesystem; listado de copia montada explícito; Autopsy manual |
| `disk/file_carving.sh` | Foremost, Scalpel, ddrescue |
| `logs/log_analyzer.sh` | Conteos, niveles, errores, autenticación, SSH, IPs |
| `pcaps/pcap_analyzer.sh` | Capinfos/TShark: protocolos, conversaciones TCP/UDP, DNS, HTTP, indicadores, archivos |
| `timeline/timeline_creator.sh` | Journal JSONL, auth/syslog, dpkg, wtmp, árbol offline; fuentes locales históricas explícitas |

`show_results.sh` añade consulta de resúmenes sin sustituir esas entradas.
El listado `11` conserva acceso a las diez y al visor, sin descubrir scripts en
resultados. Las confirmaciones directas siguen siendo obligatorias.

## IoT / soporte portátil (opción `12`)

Cuatro hojas nuevas en `iot/`, fuera de la lista original y sin ejecución
implícita. Ninguna se invoca desde `run_all_forensics.sh`.

| Hoja | Función |
|---|---|
| `iot/iot_acquire.sh` | Imagen `image.dd` de un dispositivo de bloque + SHA-256 + `image.json` |
| `iot/iot_triage.sh` | Inventario/hash/familia de un árbol recuperado, con `report.json`/`report.md` privados |
| `iot/iot_vt_lookup.sh` | Consulta VirusTotal v3 **solo con hashes** de un triaje finalizado |
| `iot/iot_sterilize.sh` | Borrado destructivo del soporte y recibo privado fuera de los runs |

Reglas propias: adquisición y esterilización exigen root ya disponible (sin
`sudo` interactivo ni escalada automática), soporte desmontado y un token
literal distinto por acción (`ADQUIRIR_SOPORTE`, `ESTERILIZAR_SOPORTE`);
VirusTotal exige `VT_API_KEY` exportada en el entorno y un token
`CONSULTAR_VIRUSTOTAL`, y solo envía hashes por HTTPS (o loopback explícito en
pruebas). La esterilización no crea un run ni es evidencia forense: su recibo
vive en `analysis/sterilizations/`. PhotoRec 7.2 no se automatiza (su `/cmd`
abre la TUI y puede salir 0 sin recuperar nada); tras adquirir, el carving
automático es `disk/file_carving.sh` y PhotoRec queda como uso guiado.

## Inicio seguro (desde el directorio del módulo)

```bash
bash requirements.sh --check
bash memory/strings_analysis.sh '/ruta/trabajo/archivo autorizado'
bash pcaps/pcap_analyzer.sh '/ruta/trabajo/captura elegida.pcap'
bash show_results.sh --run '/ruta/analysis/runs/run-ID/run.json'
bash iot/iot_triage.sh '/ruta/recuperados'
```

Adquisición y esterilización no se muestran aquí: son acciones destructivas o
privilegiadas, documentadas en [USE](USE.md), y exigen token propio.

Los ejemplos de análisis requieren archivos seleccionados por el operador.
No son un smoke test sobre evidencia real. Cada analizador copia y verifica su
propia entrada completa: prever espacio/tiempo y posible cambio de atime.
No se monta ni adquiere automáticamente; no se instalan dependencias al entrar.

Resultados nuevos: `analysis/runs/`, `recovered/` y
`../captures/memory/`, por run privado (directorios700/archivos600).
Resultados antiguos no se migran ni borran. Salidas externas requieren protección
y exclusión git propias. COMPLETADO no significa ausencia de intrusión ni RAM
íntegra. Fixtures/stubs no prueban compatibilidad operacional o custodia legal.

Verificación desde la raíz del framework:
`bash tests/run_forensics.sh` (solo copias/config/evidencia sintéticas) y
`python3 tests/verify_forensics.py RUN_JSON` (lector estricto, solo lectura).
La revisión de tarea/global y el cierre se coordinan por separado; estado en
`../../docs/FORENSE-INTEGRAL-2026-11-11.md`.
