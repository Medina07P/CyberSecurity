# 📊 11_Reports - Informes de Auditoría

Este directorio contiene el motor de informes que genera reportes profesionales
a partir de **evidencias ya existentes** en `<repo>/scans/` y los árboles de
los módulos anteriores. No ejecuta herramientas, adquisiciones ni empaquetados.
Guía detallada: [USE.md](USE.md).

## 📁 Estructura

| Directorio / Fichero | Descripción |
|---------------------|-------------|
| `generated/`        | Historial privado por objetivo y generación (git-ignored) |
| `lib/`              | Motor Python: parsers, renderizado, modelo |
| `templates/`        | Plantillas de referencia |
| `report_engine.py`  | CLI del motor de informes |
| `report_generator.sh` | Envoltorio Bash del motor |
| `run_all_reports.sh`  | Orquestador de la fase 11 |
| `executive/`        | (Legacy) Informes ejecutivos antiguos |
| `technical/`        | (Legacy) Informes técnicos antiguos |
| `final_report/`     | (Legacy) Informe final antiguo |
| `evidence/`         | Evidencias empaquetadas |

## 🚀 Uso Rápido

```bash
# Generar ambos informes (por defecto)
./report_generator.sh

# Generar solo informe técnico
./report_generator.sh tecnico

# Generar solo informe de cliente
./report_generator.sh cliente

# Con objetivo y datos del cliente
./report_generator.sh ambos --objetivo 192.168.1.10 --cliente ACME --auditor Ana
```

## 📊 Tipos de informe

| Tipo | Fichero | Dirigido a |
|------|---------|-----------|
| `tecnico` | `informe_tecnico.md` / `.html` | Equipo técnico: evidencia, CVEs, payloads |
| `cliente` | `informe_cliente.md` / `.html` | Dirección: impacto, riesgo, plan 30/60/90 |
| `ambos`   | Los dos anteriores + `findings.json` | Entrega completa |

## ⚡ Acción R en el gestor

Desde el menú principal del gestor (`cyber_framework.sh`), la tecla **R**
abre un submenu de informe rápido:

1. Informe técnico
2. Informe de cliente
3. Ambos informes
0. Volver

Si no hay perfil de cliente/auditor guardado, los pide una vez y los
almacena en `11_Reports/.report_profile` para siguientes ejecuciones.

## 🔧 Motor Python

```bash
python3 report_engine.py --objetivo 127.0.0.1 --tipo ambos
python3 report_engine.py --objetivo example.invalid --scans ./scans --salida ./out --cliente ACME --json
# Seleccione un findings.json existente de la ruta indicada en el recibo:
python3 report_engine.py --desde-json /trabajo/run-seleccionado/findings.json --tipo cliente --salida ./out --json
```

Variables de entorno útiles:
- `REPORT_SCANS_DIR`: directorio de resultados (por defecto `<repo>/scans/`)
- `REPORT_OUT_DIR`: raíz de historial (equivale a `--salida`)
- `REPORT_PROFILE`: ruta al perfil de cliente/auditor
- `SESSION_FILE`: archivo de objetivo de sesión (sin fallback si se especifica)
- `REPORT_FRAMEWORK_ROOT`: raíz adicional de evidencias de módulos (equivale a `--fuentes`)

## Evidencia, contexto y límites

| Fuentes | Tratamiento |
|---|---|
| Nmap/Nuclei/Nikto/ffuf y fuentes web/SSH/API/DB soportadas de 03–05 | Lectores específicos con referencia a archivo/línea; confianza según evidencia |
| Manifiestos de 05/06 | Identidad y último intento; metadata y sidecars coherentes, nunca cuerpos privados |
| OSINT 01 (`resultados.json`) | Contexto: conteos de fuentes/estados/registros, no vulnerabilidades |
| Recon 02 (árboles propios) | Referencias de presencia, sin leer cuerpos ni afirmar finalización |
| Wireless 07 | Cobertura no soportada; no interpreta capturas |
| Forense 08 | Referencias de metadata sin asignar el objetivo de sesión; no verifica análisis/integridad |
| Evidencias 10 | Inventario metadata-only; etiquetas explícitas, no inferencia desde descripciones ni lectura de artefactos |
| `masscan/masscan_*.json` | Array completo: IP y puertos TCP/UDP abiertos → observaciones info; no interpreta banners |
| `rustscan/rustscan_*.txt` | Líneas `Open HOST:PORT` o `HOST -> [PORT,PORT]` → observaciones TCP info |
| audits de 09 y formatos desconocidos en scans | Cobertura no soportada; no se ocultan como fuentes evaluadas |
| 00 / 09 | Configuración/orquestación no constituyen hallazgos por sí mismas |

`cobertura` en `findings.json` y en los informes técnicos distingue `evaluada`,
`contexto`, `no_evaluable` y `no_soportada`. La existencia de una evidencia,
SHA guardado o etiqueta no prueba integridad, autenticidad ni vulnerabilidad.
El informe cliente resume limitaciones sin rutas privadas.

Las referencias CVE de Nmap/Nikto quedan como candidatos: una mención no
demuestra explotación. Las firmas Nuclei informativas son observaciones.
Los archivos nuevos se publican con modo600 y directorios nuevos700; se rechazan
enlaces de salida. La publicación es atómica por archivo, no una transacción del
conjunto: tras un error de E/S puede quedar una generación parcial sin recibo.

## Historial automático y compatibilidad

Cada generación crea exclusivamente
`generated/<slug>/runs/run-<UTC>-<uuid>/`, con documentos del tipo solicitado,
`findings.json` y `run.json`. Para agregación explícita `--todos`, la raíz
normal es `generated/_todos/`, no la del host de sesión.

**Cambio de contrato:** `--salida DIR` y `REPORT_OUT_DIR=DIR` son la raíz;
el resultado está en `DIR/runs/<id>/`, nunca en los nombres fijos de DIR.
El recibo stdout `--json` indica `run_id`, `salida` efectiva y `archivos`
de esa ejecución, incluido `run.json`. El gestor usa esas rutas.

No se borran ni migran informes antiguos, no se sobrescriben al generar y no se
crea un enlace `latest`. Dos invocaciones simultáneas reservan runs diferentes.
Rerender desde JSON genera otro run sin alterar la entrada. La fecha nueva es
de generación, no de una nueva adquisición de evidencia.

`run.json` distingue `ESCRIBIENDO`, `COMPLETADO`/rc0 y `NO_EVALUABLE`/rc3.
La fase11 reconoce runs finales con recibo válido y documentos regulares, además
de presencia legacy. Un run incompleto no equivale a informe publicado.
La comprobación es de estructura/presencia, sin hashes ni lectura de documentos;
COMPLETADO no certifica auditoría completa, integridad ni autenticidad.

Para Masscan/RustScan, cobertura evaluada solo significa registros entendidos:
**finalización y actualidad no acreditadas**. RustScan conserva salidas previas
tras fallos; Masscan puede dejar JSON parcial. Vacío/truncado no se declara
«sin puertos» ni convierte por sí solo la generación en rc0. No se resuelve DNS
para asociar IPs a dominios. Puertos equivalentes se unen con Nmap conservando
sus IDs y datos de servicio; TCP y UDP permanecen separados.

Sin objetivo ni sesión el motor falla: **solo `--todos` agrega objetivos**.
`--all` del wrapper selecciona ambos tipos de informe, NO todos los objetivos.
Un JSON de otro objetivo se rechaza; `--desde-json` usa su identidad almacenada
si no se pasa objetivo explícito. No revalida las evidencias originales.

Con `--scans`/`REPORT_SCANS_DIR` externos, los demás módulos no se recorren
implícitamente: añada `--fuentes /ruta/CyberSecurity-Framework` si corresponde.
Los árboles externos de 08/10 no se descubren por sus overrides operacionales;
el lector usa el layout de la raíz seleccionada.

Códigos: 0 informes escritos con alguna fuente evaluable; 1 uso/entrada/E/S;
3 informes limitados escritos sin fuente evaluable. Cero hallazgos no significa
ausencia de vulnerabilidades. El recibo `--json` incluye `archivos` escritos en
esta ejecución, también con rc3; un fallo no presenta informes históricos.

Pruebas seguras: `bash CyberSecurity-Framework/tests/run_reports_evidence.sh`
desde la raíz. Solo fuentes permitidas, PATH cerrado y datos/config sintéticos;
no acreditan compatibilidad con todas las herramientas reales.
