# Task 7 — PowerShell explícito

Estado: DONE. Base `d0bb395`; solo Task7. Sin push ni subagentes/revisores.

## Entrega y self-review

- `auto_enum.ps1` exige destino padre existente y `-Execute`. Sin ejecutar,
  imprime plan/uso sin consultar fuentes ni crear salidas; execute sin destino
  devuelve 2. Destino inválido/no Windows devuelve 2; fallo de ejecución o
  escritura devuelve 1; éxito devuelve 0.
- Conserva Get-ComputerInfo, Get-LocalUser, Get-Process ordenado por CPU/top20,
  netstat -ano y Get-ScheduledTask, con los cinco nombres originales.
- Rutas absolutas locales, rechazo de UNC/providers/ADS/`..`, validación de
  directorio y de todos los ancestros contra ReparsePoint antes de crear run
  GUID y antes de recolectar/publicar. Join-Path, LiteralPath y NoClobber.
- Cada cmdlet de colección usa ErrorAction Stop. Captura LASTEXITCODE de
  netstat. Resumen JSON con id/file/state/raw_exit/reason, salida visible de
  errores y rc global; cmdlets sin exit nativo usan raw_exit null. Primer fallo
  corta las fuentes posteriores, marcadas skipped.
- Publicación mediante `.partial` y File.Move sin overwrite: no hay archivo
  final vacío válido por fallo de fuente/escritura. El cleanup no elimina un
  archivo final preexistente. Si falla guardar resumen, stdout informa rc1 y
  no se publica summary.json exitoso; puede quedar summary.json.partial.
- Allowlist del fixture ampliada solo para el contrato PowerShell. No se
  implementaron Tasks1–6 ni se modificaron sus contratos de producto.

## TDD y verificación

Comandos desde `CyberSecurity-Framework/tests`, salvo git desde raíz:

1. `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest test_automation_powershell -v`
   RED inicial: rc1, cuatro fallos. Tres aserciones estáticas detectaron la
   falta del contrato; el dinámico falló porque aún faltaba su fixture
   (pwsh rc64), no se ejecutó el recolector original.
2. Mismo comando tras implementación: primer intento rc1 por enlace incorrecto
   del argumento `-ano` en el mock; corregido el mock, rc0, 4 tests OK.
3. Se amplió el contrato para comprobar archivos/ancestros enlazados y
   preservación de un archivo ajeno ante fallo de fuente. RED rc1: el cleanup
   anterior eliminaba el archivo final ajeno. Corregido con staging y cleanup
   limitado a `.partial`; GREEN rc0, 4 tests OK (último run: 1.460s).
4. `PYTHONDONTWRITEBYTECODE=1 python3 -c "import ast; from pathlib import Path; paths = ['test_automation_powershell.py', 'automation_fixture.py']; [(ast.parse(Path(p).read_text(), filename=p), print(p + ': AST OK')) for p in paths]"`
   rc0; ambas fuentes Python: AST OK.
5. `git diff --check`: rc0, sin salida.

`pwsh` encontrado únicamente por PATH. No corresponde SKIP dinámico en este
entorno; unittest registra SKIP explícito si pwsh no existe. El test dinámico
parsea AST del producto y del fixture, ejecuta solo copias allowlist bajo
`/tmp/opencode/automation-*` y devuelve `MOCK CONTRACT OK; AST OK`.
Las cinco fuentes y Out-File están mockeadas antes de cualquier invocación;
no se ejecuta netstat ni un cmdlet real de recolección. Se prueban éxito,
fallo de cada fuente, netstat rc7, escritura parcial, escritura del resumen,
ausencia de flags, padre ausente/archivo, enlaces de destino/ancestro y
rechazo de plataforma real no Windows. En Linux, una segunda copia sustituye
solo los guards de plataforma/prefijo de unidad para usar directorios
sintéticos con espacios; el producto no ofrece bypass. También se invoca la
copia sin esas sustituciones para comprobar el rechazo no Windows.

## Límites y concerns

- No se certifica compatibilidad Windows/PowerShell operacional: se ejecutó
  pwsh en Linux con mocks, no junctions ni cmdlets Windows reales.
- Se exige padre controlado por el operador. La validación y revalidación de
  rutas no son aislamiento por handles ni protegen contra un atacante capaz
  de sustituir ancestros durante las ventanas entre comprobación y uso.
  No presentar el script como sandbox ni usar padres compartidos no fiables.
- Un fallo que impida retirar `.partial` se avisa; jamás se etiqueta como
  resultado final exitoso. Una terminación externa puede dejar staging.
- No config/evidencias reales abiertas, copiadas o hasheadas; no red,
  instalaciones, Docker, auditorías, suite legacy ni flujo99. Solo las pruebas
  nuevas de Task7; no se declara toda la rama verde.
