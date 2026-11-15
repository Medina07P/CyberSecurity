# 11_Reports — informes desde evidencias existentes

## Estado de entrega

Implementación local del alcance aprobado, sin commit, integración ni push.
Trabajo conservado en el worktree nativo:

`/home/kali/.local/share/opencode/worktree/f6569d/reports-evidence-fixes`

HEAD separado administrado por el harness; los cambios están sin commit.
El checkout original y sus cambios locales de scope/targets no se usaron para
implementar ni probar estas correcciones. No se adquirieron evidencias reales.

Guía de uso: `CyberSecurity-Framework/11_Reports/USE.md`.
Plan: `docs/superpowers/plans/2026-11-13-reportes-evidencias-correcciones.md`.
Ledger/logs: `.superpowers/sdd/2026-11-13-reportes-evidencias-correcciones/`.

## Correcciones

- Objetivo obligatorio por flag/sesión; agregar objetivos exige `--todos`.
  `SESSION_FILE` aísla la lectura; JSON de otra identidad o con tipos inválidos
  se rechaza antes de escribir. Rerender sin flag usa identidad del registro.
- El wrapper consume solo el primer selector de tipo; valores de opciones
  llamados `cliente`, `tecnico` o `ambos` no se pierden.
- 05 valida metadata/sidecars, finalización, estados/códigos e identidad completa
  antes de publicar. Conserva puertos y URL en selección; ordena instantes con
  zona horaria. Un intento fallido o identidad ambigua no revive éxitos antiguos.
- EJECUTADO es observación, no diferencial inventado; reflexión XSS candidata.
  Un acceso operacional con credenciales no basta para declarar vulnerabilidad.
- Referencias CVE de Nmap/Nikto candidatas; Nuclei informativo observación.
  Dedupe conserva el texto y severidad de la prueba de mayor confianza.
- `cobertura` registra fuente, módulo, objetivo, estado y límites. Se mantiene
  compatible con JSON anterior que no tenga ese campo.
- OSINT integra estados/conteos como contexto; recon registra presencia sin leer
  cuerpos ni afirmar finalización. Wireless/fuentes no soportadas quedan visibles.
  Forense no hereda el host de sesión. 10 usa inventario metadata-only, sin abrir
  artefactos ni inferir vulnerabilidades de etiquetas/descripciones.
- Fase11 no empaqueta automáticamente ni ejecuta módulos previos. El motor
  devuelve en `--json` los archivos realmente escritos, incluso con rc3; el
  gestor respeta tipo/salida y no abre históricos tras fallos. EOF durante el
  perfil cancela sin guardar ni generar.
- Nuevos archivos600/directorios700; preflight rechaza enlaces de salida y
  publicación por reemplazo atómico de cada archivo, sin truncar enlaces ajenos.
  Se rechazan enlaces/archivos especiales en fuentes y dependencias pareadas.

## Verificación sintética

Última suite dedicada:

`bash CyberSecurity-Framework/tests/run_reports_evidence.sh`

**144 tests / rc0 / GUARD OK**: 78 motor existente, 11 postexplotación,
53 contratos nuevos y 2 guardas del runner. Allowlist de fuentes, HOME/config/
sesión sintéticos y PATH cerrado. Logs RED y GREEN de cada grupo conservados;
`final-suite.log` acredita el último estado. Sintaxis: 23 AST Python y 4 Bash
sin stderr; `git diff --check` rc0.

Regresiones en archivo git temporal con configuración/HOME sintéticos:

`/tmp/opencode/reports-final-regressions-u8cvnglw/`

| Suite | Resultado |
|---|---|
| `run_reports.sh` | rc0 |
| `run_enumeration.sh` | rc0 |
| `run_evidence.sh` | rc0 |
| `run_smoke.sh` | rc0 |
| `run_e2e.sh` | rc0 |

La última corrección del EOF de perfil se verifica además en la suite dedicada
final; no altera los flujos completos de perfil usados por estas regresiones.

## Gate global no verde

`run_tests.sh`, en `/tmp/opencode/reports-regressions-am04kmwl/`, no terminó
en180s. Registró estos cuatro fallos antes del corte:

1. `118 scripts .sh en el framework` (observó122).
2. `45 scripts con 2+ huecos (incluido perfil Smart)` (observó51).
3. `sqli: no detectó la diferencia real` (obtuvo0).
4. `sqli: hallazgos por objetivo, sin arrastrar los ajenos` (esperaba90, obtuvo0).

También imprimió dos errores `rm` al intentar borrar directorios del fixture
http_inject. Se conservan logs y copia; los tres servidores http_target propios
que quedaron huérfanos tras el timeout se identificaron por argv completo y se
detuvieron con TERM. No se atribuye causa al timeout ni se declara esta suite
completa verde. Estos pendientes ajenos al módulo11 no se corrigen de forma
encubierta ni se extiende el alcance a explotación.

## Decisiones y costes

1. El alcance nuevo aprobado sustituye defaults históricos de todos implícito,
   CVE confirmado por mención y paquete automático. Coste: cambio intencional de
   comportamiento; automatizaciones deben seleccionar alcance/paquete explícitos.
2. Revisión propia, sin subagentes; sin commit ni integración automática.
   Coste: no hay revisión independiente ni código integrado en develop.
3. Estados operacionales no equivalen a vulnerabilidades. Coste: resultados
   anteriormente elevados pasan a observación/candidato y requieren revisión.
4. Dedupe prioriza confianza sobre gravedad candidata. Coste: una referencia
   candidata de mayor severidad no eleva la cabecera del confirmado.
5. Scans externos no autorizan recorrer otros módulos implícitamente; requieren
   `--fuentes`/`REPORT_FRAMEWORK_ROOT`. Coste: selección adicional explícita.
6. Publicación atómica por archivo, no transacción global ni protección frente
   a escritor hostil del mismo UID. Coste: fallo tardío puede dejar generación
   parcial sin recibo; revisar/repetir. No se ajustan permisos de padres existentes.

No quedan menores diferidos nuevos identificados en la revisión de este alcance.
La cobertura es deliberadamente limitada, no compatibilidad operacional universal,
autenticidad, verificación integral de hashes ni custodia legal.

Conservar worktree, logs y cambios sin commit. La integración requiere decisión
expresa del usuario; no eliminar este workspace como parte de una limpieza.
