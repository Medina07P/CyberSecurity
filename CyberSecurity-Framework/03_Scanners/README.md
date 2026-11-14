# 03 · Escáneres: menú guiado

Desde el gestor, pulsa **03** (también `3`). Primero revisa las herramientas;
no uses `run_all_scanners.sh` como prueba de instalación.

| Opción | Qué hace |
|---|---|
| **1 · Comprobar herramientas** | Comprueba disponibilidad local, sin red, instalaciones ni actualizaciones. |
| **2 · Puertos y servicios básicos** | Nmap sobre los 100 puertos TCP más comunes, detección ligera de servicios; sin NSE, Masscan ni detección de SO. |
| **3 · Analizar una URL** | Elige Nikto o Nuclei, introduce URL completa y confirma el análisis activo. |
| **4 · Burp manual** | Abre el lanzador, pide puerto de proxy y explica la captura. Community no escanea ni guarda proyectos. |
| **5 · Avanzado** | Conserva los diez scripts originales, incluidos todos los puertos, NSE, Masscan y RustScan. Los perfiles intensivos piden confirmación adicional. |
| **6 · Control Burp** | 1 estado local, 2 verificar un GET explícito, 3 parar instancia propia acreditada, 0 volver. No abre GUI al entrar. |
| **0** | Vuelve al menú principal. |

El objetivo de sesión aparece en pantalla y se propone para el escaneo básico.
Sin sesión no se usa una IP de ejemplo. `0` o `!` cancela la pregunta de objetivo;
EOF o responder «no» a la confirmación no ejecuta herramientas.

Para web escribe el esquema correcto, el puerto y la ruta, por ejemplo
`https://example.com:9443/ruta`. No se deduce HTTP o HTTPS del objetivo de sesión.
No se aceptan credenciales en la URL: utiliza Burp para una sesión autenticada.

## Requisitos

- Bash y Python 3 para validar entradas localmente.
- Los modos de red aceptan IPv4 o dominio; IPv6 literal se rechaza antes de
  invocar herramientas porque estos perfiles/informes no implementan IPv6.
- Solo necesita estar instalada la herramienta elegida; la comprobación no las ejecuta.
- Masscan necesita **root**. El menú no eleva privilegios ni ejecuta `sudo`.
- Nmap básico usa TCP connect sin root; Smart completo incluye detección de SO
  y otros perfiles avanzados pueden necesitar privilegios.
- RustScan no requiere root por defecto; guarda stdout y usa modo greppable,
  sin derivación automática a Nmap.
- Burp requiere entorno gráfico e interacción manual.
- Nuclei necesita plantillas locales disponibles. Los scripts limitan a HTTP,
  desactivan comprobaciones de actualización e Interactsh, usan máximo
  10 peticiones/s y concurrencia 2. No prueban protocolos no HTTP ni hallazgos OOB.

## Uso directo (solo con autorización)

Las rutas se resuelven desde el propio script: no es obligatorio cambiar de cwd.
Ejemplos desde `CyberSecurity-Framework/`:

```bash
# Inicio acotado; también se puede elegir desde 03 → 2
bash 03_Scanners/network_scanners/nmap/nmap_smart.sh 192.0.2.1 basico

# Análisis activo de una URL explícita
bash 03_Scanners/web_scanners/nikto/nikto_scan.sh https://example.com:9443/ruta
bash 03_Scanners/web_scanners/nuclei/nuclei_cves.sh https://example.com critical,high

# Avanzado: solo si se autoriza la intensidad y el alcance
bash 03_Scanners/network_scanners/nmap/nmap_scripts.sh 192.0.2.1 80,443
```

Smart sin perfil sigue siendo **completo**, no básico: todos los puertos,
servicios y NSE `vuln`. No lo confundas con `03 → 2`.

`run_all_scanners.sh <host>` sigue siendo avanzado: Smart completo, Masscan
opcional solo para IPv4 explícita con root, descubrimiento 80/443/8080/8443
y Nikto/Nuclei por puerto. El esquema por puerto es una **heurística**, no
detección de TLS. Para una URL conocida usa la opción web del menú.

## Burp: apertura, estado, tráfico y parada separados

**03.4** conserva la apertura GUI y guía manual de navegador/CA/Repeater/exportación.
Abrir no envía el antiguo curl al objetivo de sesión ni autoriza una verificación.
Burp puede generar tráfico propio de la aplicación; no se promete una GUI sin red.
Community no escanea ni guarda proyectos; la asistencia GUI opcional requiere su
propio consentimiento TTY (`INICIAR GUI`) y puede fallar: sigue disponible el flujo manual.

**03.6 → 1** consulta estado sin conectar ni crear artefactos. Puerto ocupado no
acredita dueño Burp ni captura. Si no puede observar informa `NO_DETERMINADO`.
**03.6 → 2** pide URL HTTP(S) completa, puerto proxy explícito y permiso propio
para enviar un GET vía `127.0.0.1:N`. No propone la sesión como URL/permiso.
`0`/`!`, no o EOF cancelan; un sí a abrir no autoriza tráfico posterior.
El código HTTP observado no certifica origen ni captura. La query puede contener
secretos y la URL aparece en argv del proceso y argumentos del gestor: no es
almacenamiento secreto. Evita secretos en la URL de esta comprobación GET.
**03.6 → 3** pide ID propio y consentimiento para TERM y posible KILL;
**parar tiene efectos**, no es una consulta. La hoja verifica identidad y usa
pidfd, sin señales por nombre/grupo ni adopción de PID legacy.

CLI pública (ejemplos, no instrucciones de validación automática):

```bash
bash 03_Scanners/web_scanners/burpsuite/burp_launcher.sh [puerto]
bash 03_Scanners/web_scanners/burpsuite/burp_launcher.sh --estado [--instance ID]
bash 03_Scanners/web_scanners/burpsuite/burp_launcher.sh --verificar https://example.test/ruta --proxy-port 8080 --execute --confirm-network
bash 03_Scanners/web_scanners/burpsuite/burp_launcher.sh --parar --instance ID --execute
```

Los corchetes indican argumentos opcionales, no literales. Verificar en TTY
puede sustituir `--confirm-network` por la frase exacta `ENVIAR GET`, pero nunca
omite `--execute`. Curl recibe **`--disable` primero**, GET, max-time5, sin
redirects/reintentos/`-k` ni expansión de URL. Solo la solicitud explícita.
ID tiene forma `burp-` seguida de32hex minúsculas. CLI sin ID al parar solo acepta
una instancia nueva inequívoca; el menú exige ID. Falta de recibo/pidfd o identidad
incongruente bloquea. No se garantiza controlar descendientes/daemonización.

Migración: el curl automático desaparece; `--parar` antiguo sin `--execute`
ya no actúa. Cada apertura crea config/log/recibo privados nuevos bajo
`<repo>/scans/burp/instances/<ID>/`; conserva todas las instancias y rutas legacy,
sin migrar, borrar o adoptar sus PIDs. `BURP_LAUNCHER_ESPERA` antiguo ya no se usa.
Community puede ignorar el puerto: revisar Settings → Proxy → Proxy settings y
`--estado`, sin confundir listener con captura. Ni `run_all_scanners` ni99
adquieren acciones Burp.

## Resultados y fallos

Los resultados van a **`<repo>/scans/<herramienta>/`**, nunca al cwd.
Los nombres incluyen el objetivo; Masscan produce JSON; Nuclei/CVEs producen
texto estándar `.txt` compatible con el motor de informes.

- Código **0**: la herramienta terminó; no demuestra que el objetivo sea seguro.
- Código **1**: entrada inválida, dependencia ausente o fallo. Resultado **NO DETERMINADO**.
- El orquestador cuenta ejecutadas, fallidas y omitidas; devuelve 1 si falla
  una tarea requerida. Las omisiones no son resultados limpios.
- `errores.log` conserva el historial en secciones fechadas. Puede incluir
  avisos informativos: stderr por sí solo no implica fallo. El mensaje de
  cada ejecución identifica su diagnóstico, sin listar logs antiguos ajenos.
- Smart no reutiliza puertos de una ejecución anterior si el descubrimiento falla.
- Nikto exige evidencia nueva de un host evaluado y sin terminación por errores:
  un código de proceso 0 por sí solo no basta. Rechaza comas literales porque
  Nikto las interpreta como separadores de objetivos; usa `%2C` si corresponde.
- RustScan publica stdout solo después de éxito: un fallo no trunca el archivo anterior.
- Los archivos finales siguen siendo por objetivo, no un historial completo de
  escaneos: una ejecución correcta posterior puede reemplazarlos. Conserva la
  evidencia relevante antes de repetir; los logs sí se acumulan.
- Limitación pendiente: URLs muy largas pueden superar el límite de nombre de
  archivo del sistema. Se informa fallo; todavía no hay nombres abreviados con hash.

## Verificación sin escanear

Desde la raíz del repo:

```bash
bash CyberSecurity-Framework/tests/run_scanners_menu.sh
```

La suite copia solo fuentes a un temporal, crea objetivos sintéticos y usa
herramientas simuladas en PATH cerrado. Las suites antiguas se ejecutan solo
en un clon limpio: algunas borran salidas compartidas.

Para este bloque de consentimiento, los equivalentes Burp y menús están en los
nueve IDs cerrados de `test_cross_consent.py`, no en el runner legacy.
Las enmiendas Task4 están **NOT RUN**: revisión estática independiente y permiso
exacto del controlador antes de `automation_sandbox_launch.py --cross-consent`;
`--suite` requiere autorización separada. No ejecutar el comando anterior como
atajo al gate ni interpretar esta guía como autorización de ejecución.

La autorización real debe existir en el alcance del proyecto. Registrar un
objetivo de sesión **no concede autorización**.
