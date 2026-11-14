# Diseño — lectores de puertos e historial automático de informes

Fecha: 2026-11-13. Estado: **implementado localmente; verificación dedicada175/rc0/GUARD OK el2026-11-14; sin integración**.
El usuario eligió el enfoque1: historial automático, no una bandera opcional.
Documento y plan aprobados tras elegir el enfoque1; entrega y límites en `docs/INFORMES-PUERTOS-HISTORIAL-2026-11-13.md`.

## Intención

Ampliar 11_Reports para utilizar los resultados existentes de Masscan/RustScan
como observaciones trazables y conservar cada generación de informes por separado.
No repetir escaneos, elevar puertos a vulnerabilidades ni perder entregas previas.

Base de trabajo: las correcciones anteriores están sin commit en el worktree
`/home/kali/.local/share/opencode/worktree/f6569d/reports-evidence-fixes`.
Su entrega está en `docs/INFORMES-EVIDENCIAS-2026-11-13.md`. No descartarlas,
reimplementarlas, integrarlas ni cambiar de base silenciosamente.

## Enfoques considerados

1. **Historial automático (elegido):** cada generación tiene directorio exclusivo;
   tanto salidas por defecto como personalizadas se interpretan como raíces de
   historial. Evita sobrescrituras por defecto; cambia rutas que algunas
   automatizaciones pueden haber asumido.
2. **Historial opt-in:** añadir bandera y conservar salidas fijas por defecto.
   Menor impacto de compatibilidad, pero permite sobrescrituras accidentales.
   No elegido por el usuario.

Se conserva Python estándar y los lectores deterministas; sin nuevas dependencias.
Propuesta de tamaño: ampliación acotada de parsers y publicación/integración,
con pruebas y documentación; no reescritura del módulo.

## Objetivos y no objetivos

- Leer únicamente formatos admitidos de Masscan JSON y RustScan texto existente.
- Atribuir por registros, conservar protocolo/puerto y referencias de evidencia.
- Unir observaciones equivalentes a Nmap sin duplicar puertos.
- Guardar cada generación, incluidas las limitadas con rc3 y los rerenders,
  sin modificar informes anteriores ni sus fuentes.
- Mostrar/abrir únicamente los archivos de la generación recién publicada.
- Mantener distinción entre observación, candidato, confirmado y cobertura.

Fuera: ejecutar escáneres, cambiar productores de03, completar la auditoría
operacional de09, PDF, IA, interfaz de revisión de hallazgos, comparación
automática entre auditorías, borrado/retención, migración de informes anteriores,
un navegador nuevo de históricos o firmas/custodia legal. Los directorios
separados permiten consulta y comparación manual sin implementar esas funciones.

## Restricciones y evidencia de productores

- Masscan escribe `scans/masscan/masscan_<slug>.json` mediante `-oJ`; un fallo
  puede dejar un archivo parcial. No existe recibo estructurado de finalización.
- RustScan se invoca con `-g`, sin derivar a Nmap; publica stdout como
  `scans/rustscan/rustscan_<slug>.txt` solo tras rc0. Un fallo conserva el
  resultado anterior; el archivo por sí solo no identifica el último intento.
- El fixture versionado de03 publica `Open example.invalid:8080`. Se admitirán
  también líneas estructuradas de modo greppable `HOST -> [PORT,PORT]`, con
  fixtures literales separados. No se afirma compatibilidad universal con
  versiones reales de RustScan por probar únicamente esos formatos.
- El lector NO usa mtime ni el nombre para inventar fecha, finalización o éxito
  actual; tampoco interpreta `errores.log` compartido como recibo por objetivo.
- No red, resolución DNS, instalaciones, sudo ni ejecución de herramientas.
- No lectura de datos/configuración reales durante pruebas. Conservar los
  cambios anteriores y los pendientes globales. Sin subagentes, commits,
  integración ni push automáticos, según el flujo acordado.

## Lectores y confianza

### Masscan

Aceptar array JSON completo. Cada registro admitido tiene `ip` como IP literal
válida y `ports` como lista de objetos con `port` entero1–65535 (no booleano),
`proto` igual a `tcp` o `udp` y `status` igual a `open` para aportar observación.
Un puerto con otro estado válido no se presenta como abierto. No convertir
campos `banner`, `service`, nombres libres o referencias CVE en hallazgos.
Los registros mal tipados se anotan como no evaluables, sin inferir valores.

Cada puerto abierto aporta host/puerto/protocolo, severidad info, confianza
observación y referencia al archivo y al registro/puerto identificado, sin
incorporar cuerpos o banners. Los registros de otros hosts quedan fuera del
informe solicitado, aunque el nombre del archivo sugiera ese objetivo.
Un dominio de sesión no se equipara a una IP mediante DNS implícito.

JSON truncado no se recupera con regex: fuente no evaluable, sin hallazgos.
Array vacío válido no acredita un escaneo completado ni un host limpio:
sin recibo de finalización, queda no evaluable y no activa por sí solo rc0.

### RustScan

Admitir exactamente líneas completas:

- `Open HOST:PORT`, puerto TCP.
- `HOST -> [PORT,PORT]`, espacios opcionales alrededor de separadores; TCP.

Validar IP/host y puertos, admitir IPv6 solo con sintaxis de host/puerto
inequívoca (`[IPv6]:PORT` para Open). No usar fragmentos de banners ni cadenas
`open` aisladas. Secuencias ANSI SGR de color pueden retirarse antes de reconocer
la estructura; otras secuencias de control se rechazan, no se interpretan.
Deduplicar puertos de líneas repetidas.

Una línea desconocida no produce observación: queda como limitación sin copiar
su texto libre al informe cliente. Un archivo mezclado puede aportar registros
válidos del objetivo y limitaciones; no se afirma evaluación completa.
Archivo vacío o `HOST -> []` sin recibo no acredita «sin puertos abiertos».

### Cobertura común

Observaciones válidas pueden marcar la lectura estructurada como evaluable,
pero el motivo de cobertura declara siempre **finalización y actualidad no
acreditadas**. Fuente inválida/vacía queda no evaluable. Los resultados previos
de RustScan no se anuncian como último intento correcto.

El contenido manda sobre basename. Si no se puede atribuir una fuente dañada,
se informa como limitación sin inventarle objetivo. No incluir detalles de
otros registros/hosts en el informe de un único objetivo.

Se reutilizan las claves actuales de puertos de Nmap
`nmap.open_port:<protocolo>:<host>:<puerto>` para los nuevos lectores. Aunque
el prefijo sea histórico, evita cambiar IDs ya publicados. Si Nmap aporta
servicio/producto, conservar su ficha y unir referencias de ambos lectores;
si no existe Nmap, la ficha identifica honestamente Masscan o RustScan.
Protocolos y puertos distintos nunca se fusionan. No unir esto con hallazgos CVE.

## Historial automático

### Layout y compatibilidad

Ruta normal:

`11_Reports/generated/<slug>/runs/run-<UTC>-<uuid>/`

Para `--todos`, la raíz normal es `11_Reports/generated/_todos/`, independiente
de una posible sesión de host. `_todos` no se usa como objetivo de red.

`--salida DIR` y `REPORT_OUT_DIR=DIR` seleccionan **la raíz**; la ejecución se
guarda en `DIR/runs/run-<UTC>-<uuid>/`. No se añade otro slug dentro del destino
personalizado. Explicar este cambio en ayuda y documentación; no ofrecer modo
de sobrescritura ni simular que las rutas fijas siguen actualizándose.

Los informes antiguos directamente bajo `<slug>/` o un destino personalizado
se conservan byte a byte. Sin renombrarlos, copiarles una fecha inventada,
migrarlos ni crear enlaces `latest`. Los árboles de salida siguen ignorados
por git; destinos externos requieren protección/exclusión propias.

### Reserva, publicación y estados

1. Validar argumentos, estructura/identidad del JSON de entrada y rutas antes de
   reservar una ejecución. Un error de uso no crea un run.
2. Crear padres nuevos700 y reservar run exclusivo700 mediante operación que
   falle si ya existe. UUID más UTC sirve para identificar, no probar orden de
   las evidencias. En concurrencia nunca reutilizar un directorio existente.
3. Escribir `run.json`600 con versión1, identidad del run, UTC de generación,
   objetivo/modo, tipo de informe, entrada `scans` o `json`, estado
   `ESCRIBIENDO` y rc aún no final. No guardar credenciales ni argv completo.
4. Publicar únicamente los documentos del tipo solicitado y `findings.json`,
   con la protección de enlaces y publicación privada por archivo del bloque
   anterior. No copiar artefactos originales al directorio del informe.
5. Publicar `run.json` final atómicamente al terminar todo: estado `COMPLETADO`
   con rc0, o `NO_EVALUABLE` con rc3. Guardar nombres relativos de archivos,
   sin rutas fuera del run. COMPLETADO significa generación completada, no
   auditoría completada ni integridad de las fuentes.
6. Solo después emitir recibo stdout `--json`, incluyendo ruta efectiva e ID
   de ejecución y lista de archivos escritos. El gestor abre solo sus HTML.

Una falla de E/S devuelve1 sin recibo de éxito ni apertura de históricos.
Conservar el run propio incompleto y estado `ESCRIBIENDO` si no se pudo cerrar;
no borrar archivos ajenos ni confundir ese directorio con entrega publicada.
Es publicación por archivo con marcador de finalización, no transacción de
directorio ni defensa frente a escritor hostil del mismo UID.

### Rerender y lectura de estado

`--desde-json` genera otro run exclusivo; nunca altera el registro elegido ni
los informes que lo acompañan. Conserva el contenido revisado y la atribución,
actualiza la fecha de generación y registra en `run.json` que la entrada fue
JSON. No afirma haber revalidado las fuentes originales. `run.json` del informe
no debe ser confundido con manifiestos de explotación/forense.

El contrato público del recibo sigue identificando `archivos`; añadir `run_id`
y `salida` efectiva no autoriza al gestor a adivinar rutas. Incluir `run.json`
en esa lista. rc3 conserva sus documentos limitados y recibo, rc1 no.
La fase11 reconoce el nuevo layout y solo considera publicado un run con
recibo final estructuralmente válido y archivos regulares existentes; sigue
reconociendo informes legacy como presencia, nunca como autenticidad.

## Pruebas y revisión

Ampliar el runner allowlist existente, sin copiar árboles de resultados reales.
TDD para cada comportamiento nuevo y regresiones pertinentes en copia sintética.

- Masscan TCP/UDP, tipos inválidos/booleanos, IP ajena, duplicados, JSON truncado,
  vacío y nombre engañoso; no elevar banners/CVE.
- RustScan ambos formatos, color SGR, controles no admitidos, IPv6 explícita,
  líneas mixtas, duplicados, vacío y host distinto.
- Dos lectores y Nmap para un puerto: una observación, evidencia combinada;
  servicio Nmap conservado, IDs anteriores estables.
- Dos generaciones idénticas y generaciones concurrentes: runs separados,
  anteriores intactos; directorios700/archivos600.
- Salidas por defecto/personalizadas, --todos y tipos técnico/cliente/ambos;
  receipt con ruta real, apertura solo del HTML recién generado.
- Rerender crea run nuevo sin alterar entrada, ni releer scans ni fuentes.
- Enlaces, colisiones, error de entrada, fallo de escritura inyectado y run
  incompleto: sin sobrescribir previos ni emitir éxito; fase no lo da por publicado.
- Compatibilidad de JSON anterior y presencia legacy; actualizar intencionalmente
  pruebas que esperaban nombres fijos, no ocultar fallos de las suites antiguas.

Persisten los cuatro fallos observados/timeout de `run_tests.sh` del bloque
anterior; no declararlos resueltos por esta ampliación ni rama global verde.

## Decisiones propuestas y revisión del diseño

Elegido por usuario: historial automático. Elecciones técnicas propuestas por
el asistente: formatos estrictos, clave de puerto heredada, marcador `run.json`,
no `latest`, raíz `_todos`, reserva exclusiva, sin navegación/comparación nueva.
El constructor puede escoger módulos auxiliares, nombres de tests y detalles
internos de parsing/reserva, manteniendo estos contratos y sin dependencias.

Revisión del constructor realizada por el propio autor, respetando «sin
subagentes». Se resolvieron en este documento: significado de --salida, informes
vacíos/rc3, evidencia conservada por RustScan, concurrencia y runs incompletos.
No quedan preguntas bloqueantes identificadas antes de planificar. Esta revisión
no es independiente y no sustituye la aprobación del usuario.
