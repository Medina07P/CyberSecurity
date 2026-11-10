# 04 · Enumeración guiada — todas las capacidades conservadas

En el gestor pulsa **04**. Nada se ejecuta al entrar; primero puedes comprobar
herramientas localmente. El menú muestra el objetivo de sesión y permite elegir:

| Opción | Operaciones |
|---|---|
| 1 | Comprobar disponibilidad local, sin ejecutar herramientas ni enviar tráfico |
| 2 · SSH | Versión, métodos de autenticación, usuarios y algoritmos |
| 3 · FTP | Banner, acceso anónimo, listado y todos los NSE `ftp-*` originales |
| 4 · SMB | Null session, usuarios RPC, enum4linux, shares y NSE |
| 5 · LDAP | RootDSE, namingContexts y usuarios; LDAPS en 636/3269 |
| 6 · Bases de datos | MySQL root sin contraseña; PostgreSQL postgres/postgres, versión y bases; Redis INFO y KEYS * |
| 7 · Web | Headers, whatweb, robots, sitemap y ffuf; o siete puertos y archivos sensibles |
| 8 · API | Doce endpoints, GET/POST/PUT/DELETE/PATCH/OPTIONS/HEAD y Swagger/OpenAPI |
| 9 | Flujo completo original por servicios abiertos |
| 10 | Ver resultados del objetivo, sin tráfico de red |
| 11 | Lista íntegra de los 16 scripts, incluidos auxiliares FTP/LDAP y ambos generadores |
| 0 | Volver |

**No se ha eliminado ninguna capacidad.** El resumen y la confirmación del
gestor explican lo que se ejecutará. POST/PUT/DELETE/PATCH pueden modificar o
borrar datos; `ftp-*` incluye pruebas intrusivas; `KEYS *` puede bloquear Redis.
La autorización del alcance sigue siendo imprescindible: fijar el objetivo no
la concede. El menú no ejecuta sudo ni instala dependencias.

`0` o `!` cancela la pregunta de objetivo/puerto. EOF o una confirmación
negativa no inicia operaciones. Sin sesión no se toma una IP de ejemplo.

## CLI y generadores

Se mantienen las invocaciones históricas host/puerto. Para web/API se añade
esquema opcional y `--url` explícita (el menú usa URL completa):

```bash
bash 04_Enumeration/ssh/enum_ssh.sh 192.0.2.1 2222
bash 04_Enumeration/web/enum_web.sh 192.0.2.1 8443 https
bash 04_Enumeration/web/enum_web.sh --url https://example.com:9443/base
bash 04_Enumeration/api/enum_api.sh --url https://example.com:9443/base
bash 04_Enumeration/show_results.sh example.com
```

La CLI directa constituye una invocación explícita: no introduce preguntas
interactivas nuevas; las confirmaciones adicionales están en el gestor.
Las rutas no dependen del cwd. En modo histórico, deducir HTTPS de 443/8443
es una **heurística**, no detección de TLS. La URL explícita conserva ruta y query.

Los dos generadores siguen disponibles y **sobrescriben código**, no escanean:

- `web/deepseeenum_web.sh` regenera `web/enum_web.sh` con el mismo contenido.
- `smb/enum_smb.sh` se reemplaza por su payload SMB, conservando enum4linux,
  RPC, shares y las pruebas de ADMIN$, IPC$, C$, public, share, documents y
  backup. Su prefijo opcional se usa dentro de `scans/smb/`, no en el cwd.

## Evidencias y estados

Resultados en `<repo>/scans/<servicio>/`, identificados por host y puerto.
Web/API incluye hash de esquema/ruta/query; los nombres largos se acotan sin
cambiar la URL de red. Cada resultado nuevo lleva `.meta.json`; el último
intento queda en `.attempt.json`. No modifiques esos registros para atribuir
evidencia a otro objetivo.

- `CONFIRMADO`: evidencia de acceso/consulta, no una vulnerabilidad inferida de texto cualquiera.
- `DENEGADO`: rechazo explícito del servicio, distinto de un fallo de transporte.
- `EJECUTADO`, `CERRADO`, `FILTRADO`, `OMITIDO` y `NO_DETERMINADO` evitan confundir
  una herramienta ausente o una conexión fallida con un resultado limpio.
- Un fallo conserva los bytes anteriores, pero el último intento no los
  presenta como una ejecución correcta nueva. Los logs se acumulan con fecha.
- Los informes reconocen nuevas evidencias SSH/MySQL/API y mantienen formatos
  históricos; archivos antiguos sin host no se asignan por la sesión actual.

Los clientes MySQL/Postgres ignoran credenciales/configuración heredadas para
probar exactamente la identidad indicada. PostgreSQL usa detección de servicio
Nmap para el banner: el antiguo `pg-banner` no existe en Nmap estándar. La
enumeración SSH de usuarios conserva su ejecución si existe el NSE requerido;
si falta, anuncia `NO_DETERMINADO`, no finge que se ejecutó.

## Límites operativos

- `ENUM_TIMEOUT`: 60 s por servicio del flujo completo, configurable como entero positivo.
- `ENUM_STEP_TIMEOUT`: 30 s por operación de servicios; HTTP conecta en 5 s y
  limita cada intento a 15 s. LDAP limita consultas de usuarios a 500 entradas/15 s
  y debe revisarse cualquier respuesta truncada.
- Las sondas HTTP comparan baseline; una respuesta SPA/catch-all no demuestra
  endpoints, archivos ni métodos. Un 2xx de método se informa solo como observación,
  no como prueba de modificación exitosa.
- HTTP 429/503: un reintento respetando Retry-After; si persiste o supera el
  presupuesto de espera, se corta sin puntuar. ffuf se detiene al observar el
  freno en su stream y no publica hallazgos parciales; no puede retirar
  peticiones que ya estaban en vuelo. No se reinicia automáticamente su diccionario.
- Se mantiene el diccionario `/usr/share/wordlists/dirb/common.txt` de ffuf y
  sus 20 hilos. Debe existir localmente; no se descarga.
- Los modos de red actuales no anuncian soporte IPv6 completo.

## Pruebas sin herramientas reales

Desde la raíz del repo:

```bash
bash CyberSecurity-Framework/tests/run_enumeration.sh
```

Usa fuentes copiadas, configuración sintética y PATH cerrado. No ejecuta
escáneres ni generadores sobre el checkout real. Las suites antiguas requieren
clon limpio porque algunas borran resultados compartidos.
