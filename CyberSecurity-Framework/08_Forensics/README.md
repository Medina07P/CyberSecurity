# 08_Forensics — fuentes explícitas, resultados privados

El menú `08` separa comprobación local, análisis offline, adquisición local,
disco/recuperación, flujo y visor. Entrar, cancelar o EOF no ejecuta herramientas.
No utiliza la IP de sesión como identidad forense. [Uso y límites](USE.md).

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

## Inicio seguro (desde el directorio del módulo)

```bash
bash requirements.sh --check
bash memory/strings_analysis.sh '/ruta/trabajo/archivo autorizado'
bash pcaps/pcap_analyzer.sh '/ruta/trabajo/captura elegida.pcap'
bash show_results.sh --run '/ruta/analysis/runs/run-ID/run.json'
```

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
