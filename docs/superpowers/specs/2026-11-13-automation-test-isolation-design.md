# Aislador exclusivo de pruebas de 09

Estado: APROBADO por el usuario para preparar el plan. Fecha: 2026-11-13.

## Intención y acuerdos

Cerrar I1 de Task9 sin limitar la auditoría operacional. El usuario eligió separar
pruebas de desarrollo de ejecución operacional y exige no borrar nada ni retirar
funcionalidades. El usuario aprobó después el documento con «Si, aprobado».
Se prepara el plan; no se ha autorizado por ello ninguna auditoría, instalación,
consulta real ni ejecución fuera de la barrera revisada.

El incidente de Nmap de Task9 y sus evidencias permanecen registrados. No se
reinterpreta la sesión como exclusivamente sintética. Tasks1–8 no se repiten;
Task9 y revisión global permanecen pendientes.

## Enfoques

1. Audit hook de Python: diagnóstico local útil, insuficiente para hijos/nietos;
   descartado como barrera principal.
2. Aislar el framework completo: complicaría auditorías que requieren Internet,
   datos reales y herramientas instaladas; descartado como política operacional.
3. Aislador exclusivo de pruebas, elegido: barrera Linux heredada por toda la
   descendencia, sin red externa ni configuración real, runtime mínimo explícito.
   Exige preparar el runtime y puede bloquearse si el host no lo soporta.

## Objetivos, límites y conservación

- Mantener intactas las entradas y capacidades operacionales de 09 y otros módulos.
- Las auditorías podrán usar Internet, datos y credenciales reales cuando el
  operador tenga autorización específica y se respeten sus permisos actuales.
  Este diseño no autoriza ninguna auditoría ni amplía el alcance de una existente.
- El aislamiento pertenece a `tests/`, no se activa al entrar al gestor ni se
  aplica automáticamente a herramientas operacionales.
- No borrar logs, evidencias, archivos ni workspaces, tampoco los de prueba.
  Directorios nuevos únicos por ejecución; limpieza diferida a decisión expresa
  del usuario. Se desactiva la limpieza automática de las fixtures afectadas.
- No instalaciones, sudo, Docker build/up, VM ni nuevas dependencias descargadas.
- Sin bypass `--unsafe`, entorno que desactive protección ni fallback al host.
- No garantía contra vulnerabilidades del kernel o intérpretes; el objetivo es
  contener errores ordinarios de pruebas y procesos hijos, no malware hostil.

## Arquitectura propuesta por el autor

### Frontera host / sandbox

Un lanzador nuevo de pruebas usa Bubblewrap existente en Linux, sin privilegios
añadidos, con namespaces de usuario, montaje, PID, IPC y red. Si faltan bwrap,
permisos de namespaces o una dependencia requerida: diagnóstico BLOCKED/rc2 y
ningún test arranca. La presencia del ejecutable no acredita aislamiento.

Antes de cualquier ejecución, una revisión estática independiente debe aprobar
el lanzador, manifiesto runtime, validación y probes. No se ejecutan probes durante
el diseño. Tras aprobar diseño/plan y revisión estática, se permiten únicamente
probes sintéticos dentro de la barrera; las suites arrancan solo si todos pasan.

El host prepara una copia por allowlist de fuentes/test/docs necesarios, sin
importarlos ni ejecutar comandos del framework. Nunca copia scope/targets/sesión,
claves, outputs, `.git`, HOME o configuraciones reales. Selección de fuente por
nombre exacto, sin enlaces; árbol fuente de entrada solo lectura en sandbox.
Los tests y backends se importan/ejecutan exclusivamente dentro del sandbox.

### Runtime mínimo

Manifiesto versionado de rutas exactas de intérpretes Python/Bash y utilidades
ordinarias requeridas por fixtures, con sus librerías compartidas, biblioteca
estándar y PyYAML si aplica. No montar `/`, `/usr`, `/etc`, `/home`, `/tmp`,
`/run`, `/proc` del host ni directorios bin completos. Cada archivo runtime
se valida como fuente regular esperada y se proyecta solo lectura en una raíz
nueva. Bibliotecas/directorios de runtime solo cuando el manifiesto demuestre
que no exponen binarios de auditoría, configuración privada o extensiones ajenas.
No usar `ldd` sobre archivos arbitrarios; descubrimiento de dependencias mediante
lectura estática de ELF/metadatos de runtime conocido, sin ejecutar el archivo.

El plan fijará rutas y utilidades exactas leyendo las fuentes de tests. Añadir
una dependencia exige cambio explícito del manifiesto y revisión; no hay copia
recursiva general de dependencias del host. Python sin user-site ni sitecustomize
del host; entorno limpio, sin PYTHONPATH/LD_PRELOAD/BASH_ENV/proxies heredados.

PowerShell dinámico será opcional: solo si existe manifiesto runtime separado,
revisado y cerrado. Mientras no exista se conserva su prueba y capacidad, pero
el caso dinámico queda SKIP explícito; sus contratos estáticos sí se verifican.
No incorporar automáticamente `/opt` ni el PATH del host para hacerlo pasar.

### Sistema de archivos, red y procesos

HOME/config/targets/wordlists nuevos y sintéticos dentro de un árbol de trabajo
privado 700, persistido en un directorio único bajo `/tmp/opencode`. En el sandbox
ese árbol puede verse como `/tmp/opencode` para conservar contratos de fixtures,
sin exponer su padre ni hermanos del host. Archivos nuevos 600, umask077.

`/proc` nuevo del namespace PID, dispositivos mínimos privados y sin sockets,
descriptores, agentes SSH, D-Bus o Docker del host. Cerrar descriptores heredados
no indispensables antes de iniciar. Sin capabilities, escalada o submontajes.
Namespace de red nuevo sin uplink, rutas ni resolv.conf real; bloqueo de sockets
IP mediante política de syscalls revisada si las capacidades de namespace no
bastan para el contrato sin red. No activar loopback ni permitir red externa en
este perfil; casos que requieran servidor local se marcan pendientes, no verdes.

Hijos y nietos permanecen bajo la misma raíz/red y namespace PID, con ciclo de
vida supervisado y muerte conjunta al terminar el lanzador. Límites de tiempo y
procesos evitan pruebas colgadas; señales nunca se dirigen a procesos del host.
Pruebas de grupos y pidfds se realizan únicamente sobre descendientes sintéticos.

PATH dentro de sandbox contiene utilidades permitidas y dobles de herramientas;
Nmap/Hydra/SQLmap/curl/etc reales no se incluyen. Invocar su nombre por error
termina en doble explícito o ausencia, nunca en un backend del host.

### Evidencia y ausencia de borrados

Directorio nuevo por ejecución con fuentes copiadas, manifiesto efectivo, logs,
resultado de probes y resultados de suites. No se incluye contenido real del host.
No borrar fixtures al terminar: adaptar `AutomationFixture.close()` y harnesses
que usen TemporaryDirectory/atexit cleanup para preservar sus árboles. Al salir
se desmonta la vista efímera y se terminan sus procesos; no se borra el árbol
persistente que contiene los resultados. Advertir crecimiento de disco; si no hay
espacio, fallar sin reutilizar, truncar ni borrar ejecuciones anteriores.

El bloqueo actual de `run_automation.sh` solo se reemplaza después de aprobación
estática y pruebas de frontera. No cambiar sus suites a SKIP general ni eliminarlas
para conseguir verde. Probes/suites fallidos conservan logs y rc no cero.

## Verificación propuesta (aún no ejecutada)

1. Revisión estática: mounts, fd/env, manifest, deny de backends y no fallback.
2. Probes hijo/nieto con archivos canary exclusivamente sintéticos: lectura visible
   del permitido y rechazo del canary externo al sandbox, sin usar datos reales.
3. Doble con nombre de herramienta y marcador de respaldo fuera del sandbox:
   comprobar que no es accesible desde hijos/nietos. Nunca invocar backend real.
4. Probes de red sin destinos reales: constatar política de syscalls y namespace
   aislado mediante metadatos y operaciones locales denegadas. Ningún paquete
   hacia Internet o una IP documental como prueba de bloqueo.
5. Casos ausencia de bwrap, dependencia, permiso, fuente con symlink y manifests
   inválidos: falla antes del primer test, sin fallback.
6. Cancelación/timeout: reap de procesos propios y evidencia persistente. Comprobar
   que no existe ruta de limpieza que elimine fixtures/logs o archivos previos.
7. Solo tras esos gates, suite09 completa y carreras sintéticas; regresiones
   compatibles dentro de la misma barrera. Informar SKIP/bloqueados y los rc
   observados, sin reutilizar conteos históricos como prueba de las fuentes nuevas.

Cerrar I1 exige revisión independiente de implementación y evidencia de contención
de descendientes, no solo tests de un hook local. Después se retoma Task9, sus
pendientes y revisión global del módulo sin repetir Tasks1–8.

## Archivos previstos y decisiones pendientes al plan

Archivos nuevos del aislador/manifiesto/probes bajo `CyberSecurity-Framework/tests/`;
adaptación del runner, fixture, tests de aislamiento y documentación de pruebas.
No cambios al ejecutor operacional, red de auditorías, hojas ni permisos existentes.
Ledger del aislador separado del ledger09, con enlace entre ambos; no reescribir
históricos ni quitar el registro del incidente.

El plan concretará el manifiesto y versiones mínimas, montaje efímero, límites,
API del lanzador y política de syscalls. Si el runtime disponible no permite este
contrato sin instalaciones, se declara BLOCKED y se consulta antes de cambiarlo.

## Seguimiento

- [x] Usuario elige aislador exclusivo de pruebas, preservando operación autorizada.
- [x] Redacción basada en fixture/runner/guard actuales, sin ejecución.
- [x] Revisión independiente de diseño.
- [x] Aprobación del documento por usuario.
- [x] Invocar writing-plans; preparar plan sin implementar producto.

Builder check sesión `ses_e299e727effeh3EF2ziFJszxnX`: `nothing important left`.
Revisión solo de diseño, no evidencia de sandbox implementado o verificado.
