# Task 8 — Docker estático

Estado: DONE, implementación y self-review local; sin revisión independiente ni
validación operacional. Base recibida `96b2bfd`, Tasks 1–7 no reimplementadas.

## Cambios acotados

- `FW/09_Automation/docker/Dockerfile`: Kali rolling; paquetes previos sin Hydra
  duplicado, `netcat-openbsd`, Python y dependencias apt en lugar de instalación
  global Python; home privado, grupo/usuario toolkit, COPY con propietario y
  shell Bash sin perfiles/rc ni acciones automáticas.
- `FW/09_Automation/docker/docker-compose.yml`: contexto framework `../..` y
  Dockerfile explícito; sin mounts/socket/hostnet/cap_add/root. `cap_drop: ALL`,
  `no-new-privileges:true`; shell interactiva, sin command/entrypoint override.
- `FW/09_Automation/docker/Dockerfile.dockerignore`: deny-all, ancestros exactos
  reabiertos y descendientes inmediatamente denegados; excepciones de archivos
  por nombre exacto, no globs permisivos de extensiones.
- `FW/09_Automation/docker/README.md`: BuildKit con filtro específico obligatorio,
  prohibición de builder antiguo sin filtro, datos en capa efímera, límites.
- `FW/tests/test_automation_docker.py`: YAML seguro, checks estáticos y árbol
  sintético de candidatos bajo `/tmp/opencode` mediante AutomationFixture.

## Allowlist

Manifest autoritativo completo, versionado en este commit:
`FW/09_Automation/docker/Dockerfile.dockerignore` (68 nombres exactos).
Inventario contrastado con **rutas** de `git ls-files`, sin abrir datos/config ni
hashear contenido: 67 fuentes ya versionadas + README Docker nuevo en este commit.
Se reutilizó la lista explícita de fuentes de `tests/automation_fixture.py` como
semilla, quitando gestor, puente de menú, tests y metadatos Docker.

Incluye paquete `00_Config/lib/automation`, librerías necesarias OSINT/escáneres/
enumeración/SQLmap/informes y `dangerous.txt`; seis hojas fijas (validación,
OSINT, Nmap, Nikto, SSH, SMB) más SQLmap; entradas Python/Bash/PowerShell de 09,
sus dos workflows, README 09/Docker y motor 11 con parsers. La lista exacta en
el filtro evita reproducir un inventario privado o depender de extensiones.
No incluye configuración local ni versionada de alcance/objetivos, wordlists,
claves, `.session`, perfil de informes, report.json/html, scans, loot, analysis,
logs, bytecode ni fuentes bajo directorios de datos. Dockerfile/ignore se envían
como metadatos de build por Docker, pero no están permitidos para COPY a la imagen.

## TDD y verificación (comandos, output, rc)

Todos los unittest desde `FW/tests/` con `PYTHONDONTWRITEBYTECODE=1`.
No se ejecutó Docker ni herramientas de auditoría del checkout.

1. RED, antes de implementación:
   `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest test_automation_docker -v`
   → `Ran 4 tests`, `FAILED (failures=3)`, **rc=1**.
   Fallos esperados: volumen/socket heredado; falta filtro específico; pip global.
   El test de semántica del matcher ya pasaba.
2. Primera ejecución tras implementación: mismo comando → 1 fallo, **rc=1**.
   Detectó un error en el matcher de prueba: `/dir/**` no debe excluir el propio
   `/dir` (requiere separador/descendiente). Se corrigió y se añadieron aserciones
   literales para esa semántica; no se relajó el filtro de producto.
3. GREEN: mismo comando → los cuatro métodos `ok`, `Ran 4 tests`, `OK`, **rc=0**.
   Métodos: `test_compose_minimum_privileges`, `test_context_allowlist`,
   `test_nonroot_and_dependencies`, `test_matcher_parent_and_recursive_semantics`.
   Incluye señuelos `.py/.sh/.yaml/.log/.pyc` en loot/scans/credentials/analysis,
   logs y bytecode, y hermanos privados en **cada** ancestro reabierto; ningún
   candidato privado admitido y conjunto aceptado igual a excepciones exactas.
4. Regresión nueva aislada (no legacy):
   `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s . -p 'test_automation_*.py' -v`
   → `Ran 104 tests`, `OK`, **rc=0**. Avisos esperados de report_input histórico
   en pruebas de informes sintéticos; no fallos ni skips. Solo stubs/copias y
   fixtures sintéticos; no instalaciones/red/herramientas reales.
5. Desde raíz, comprobación Python estática mediante heredoc con
   `PYTHONDONTWRITEBYTECODE=1 python3 -`: `yaml.safe_load` de Compose y los dos
   workflows; `ast.parse` del nuevo test; nombres exactos del ignore contrastados
   con `git ls-files -- CyberSecurity-Framework` (excepción README nuevo).
   Output: tres `safe_load OK`, `AST OK ... (no bytecode)`,
   `Allowlist OK: 68 exact names; 67 existing tracked sources + 1 new documentation source`,
   **rc=0**. No datos/config sensibles abiertos ni hasheados.
6. `git diff --check` → sin output, **rc=0**; diff revisado solo de fuentes Task8.

## Self-review y límites

- Rutas Compose/Dockerfile/ignore coherentes; COPY por directorios bajo el filtro,
  con propietario toolkit, sin COPY global ni mount que oculte el código.
- El matcher es una comprobación estática del subconjunto de patrones usado,
  incluida semántica de ancestros y `**`; no sustituye una prueba de BuildKit.
- Bash inerte; sin apt/instalación en runtime; usuario no root y home 700. El
  directorio framework está bajo el home para permitir scans junto al framework.
- Default bridge **permite red**; no se afirma aislamiento de red. Sin elevación
  implícita para raw sockets/captura/hardware. No se promete todos los backends.
- No build/up/config, comandos Docker, instalaciones, red, datos reales, hashes,
  legacy suites/99, push, subagentes ni revisores. Sin cambios a otros módulos.
- No se afirma sandbox de seguridad, compatibilidad operacional, disponibilidad
  real de paquetes de Kali rolling, reproducibilidad o rama completa verde.
- Datos nuevos en capa del contenedor: exportar deliberadamente antes de borrarlo;
  no hay persistencia predeterminada ni acceso implícito al host.

`FW` = `CyberSecurity-Framework`. Commit acotado solicitado:
`fix: remove implicit Docker host access and private build inputs`.
