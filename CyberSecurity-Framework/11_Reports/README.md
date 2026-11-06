# 📊 11_Reports - Informes de Auditoría

Este directorio contiene el motor de informes que genera reportes profesionales
a partir de los resultados de escaneo almacenados en `<repo>/scans/`.

## 📁 Estructura

| Directorio / Fichero | Descripción |
|---------------------|-------------|
| `generated/`        | Informes generados (git-ignored, uno por objetivo) |
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
python3 report_engine.py --scans ./scans --salida ./out --cliente ACME
python3 report_engine.py --desde-json generated/127.0.0.1/findings.json --tipo cliente
```

Variables de entorno útiles:
- `REPORT_SCANS_DIR`: directorio de resultados (por defecto `<repo>/scans/`)
- `REPORT_OUT_DIR`: directorio de salida
- `REPORT_PROFILE`: ruta al perfil de cliente/auditor
