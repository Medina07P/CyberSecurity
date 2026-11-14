# Gestor: todas las opciones y entradas (00–13)

Inventario por lectura de fuentes, 2026-11-13; reconciliación acotada09/10/11
2026-11-14 (Phase A contratos/docs; historia Phase B previa: ficha09 implementada,
GREEN NOT RUN entonces; observación posterior del controlador sobre82663d7 abajo). No se ejecutaron
menús ni herramientas reales para redactarlo. Rutas relativas a
`CyberSecurity-Framework/`. Una entrada presente **no** equivale a capacidad
integrada operacional, resultado válido, autorización ni instalación comprobada.
Las bibliotecas `lib/` y fixtures/tests no son herramientas del menú.
El contrato de cobertura usa ahora el inventario exacto
`CyberSecurity-Framework/tests/automation_sandbox_sources.json`, no git dentro
del sandbox. Conserva todas las hojas/namespaces y mutaciones existentes; al
añadir una opción/hoja deben revisarse fuentes, manifiesto y su fila explicada.
La [infraestructura de verificación](AUTOMATION-TEST-ISOLATION-2026-11-13.md)
no añade opciones operacionales al gestor ni sustituye esa explicación.

## Reglas comunes

El gestor propone el objetivo de sesión para hojas que admiten host; muestra
`Uso:` y solicita campos o argumentos manuales. Los números de listas genéricas
se calculan ordenando fuentes: identificar una herramienta por ruta, no por
número permanente. `0` vuelve sin lanzar una hoja; `R` **dentro de la lista**
recarga fuentes, no genera informes. Elegir una hoja sí puede ejecutar tráfico,
leer/escribir datos o modificar el host. `[intrusiva]` añade confirmación,
`[manual]` pide argumentos y `[generador]` escribe otro script. Cancelar antes
del lanzamiento no ejecuta; no se promete rollback de una hoja ya iniciada.
Los `run_all` heredados no tienen el contrato conservador de 09 y sus mensajes
de éxito no prueban cobertura. Nunca usar `99` como smoke test.

En el principal se acepta un dígito como alias de00–09; `?` admite también
`??`, help/HELP y H/h; Q/q admite salir/exit. Entrada vacía solo redisplay.

## Menú principal

| Opción | Finalidad | Entrada | Efectos y límites |
|---|---|---|---|
| `00` | Configuración y claves | selección de hoja | lista genérica; valida o edita datos locales según hoja, no autoriza una auditoría |
| `01` | OSINT por fuentes | dominio/empresa/archivo | lista genérica; consultas externas y resultados con cobertura; DNS activo solo opt-in |
| `02` | Reconocimiento | host/red/dominio | lista genérica; puede ampliar a /24, AXFR y escaneo completo en auto_recon; revisar hoja |
| `03` | Escáneres | opción guiada y host/URL | menú específico; disponibilidad sin red al elegir1, escaneo solo explícito |
| `04` | Enumeración de servicios | opción y host/puerto/URL | menú específico; incluye accesos anónimos, credenciales de prueba, métodos HTTP y fuzzing |
| `05` | Explotación | opción y petición/host/URL | menú específico; son sondas activas o guías según hoja; no todo es exploit funcional |
| `06` | Post-explotación | opción y datos locales/remotos | mantenimiento del menú, no integración operacional completa; puede cambiar el host actual |
| `07` | Wireless y radio | opción de mantenimiento | entrar no transmite ni modifica interfaces; lista original conserva hojas peligrosas |
| `08` | Forense | fuente explícita, nunca IP de sesión | análisis offline por copias; local/adquisición/instalación solo explícitos; sin custodia legal certificada |
| `09` | Automatización | target explícito y plan | menú sin heredar sesión; preview primero, ejecución y permisos nuevos; [USE](../CyberSecurity-Framework/09_Automation/USE.md) |
| `10` | Evidencia | selección explícita, archivos y etiqueta opcional | menú específico0–9; no adopta sesión; importación/captura/exportación separadas, no custodia legal |
| `11` | Informes | tipo/objetivo/input | lista genérica; motor11 lee existentes e históricos atribuibles; cada generación conserva runs/id y recibo propio |
| `12` | Base de conocimiento | término de búsqueda | lista genérica; lectura local, no auditoría ni explotación |
| `13` | Laboratorios | menú Labs/nombre/ruta | abre main.sh; plantillas locales y acciones rápidas/VPN/borrado, no despliegue automático de infraestructura |
| `99` | Flujo heredado completo | objetivo de sesión y confirmación | encadena00/01/02/03/04/05/06/10/11, incluye fuerza bruta/persistencia/limpieza; no incluye09 ni prueba éxito por fase; no ejecutar como validación |
| `R` | Informe rápido | 1 técnico,2 cliente,3 ambos,0 volver; perfil/nombres | genera desde datos existentes; ofrece abrir HTML; no inicia escáner ni acredita actualidad |
| `T` | Cambiar objetivo | número de targets o0/manual; IP/dominio | guarda .session y registra scope.yaml/targets.txt con backups; scope es registro best-effort, no barrera de autorización |
| `K` | Registro de API keys | subopción y herramienta/campo | puede leer/escribir HOME y registro; secretos nunca deben publicarse; Enter conserva y '-' borra |
| `?` | Ayuda | sin parámetros adicionales | muestra módulos, orden sugerido, marcas y rutas; no ejecuta auditoría |
| `Q` | Salir | sin parámetros adicionales | termina gestor; no equivale a limpiar ni revertir operaciones previas |
| `principal.vacio` | Redisplay principal | Enter sin texto | no despacha hoja ni concede permisos; vuelve a mostrar menú |

### R, T, K y selección genérica

| Opción | Finalidad | Entrada | Efectos y límites |
|---|---|---|---|
| `R.1` | Informe técnico | objetivo y perfil auditor/cliente solicitado | motor11 genera técnico, puede leer históricos; no prueba fases ejecutadas |
| `R.2` | Informe de cliente | objetivo y nombres de perfil | motor11 genera cliente, no escanea ni confirma ausencia de fallos |
| `R.3` | Ambos informes | mismo input implícito scans del wrapper | produce técnico/cliente; rc3 significa sin evidencia evaluable |
| `R.0` | Volver | ninguna adicional | cancela generación; no borra informes existentes |
| `R.abrir` | Abrir HTML generado | confirmación s/N | usa visor del sistema; archivo presente no demuestra resultado evaluable |
| `T.numero` | Elegir target existente | índice mostrado dinámicamente | registra objetivo seleccionado, no constituye autorización escrita |
| `T.0` | Escribir target | IPv4/dominio validado | persiste sesión/scope/targets; fallo de registro avisa sin cancelar sesión |
| `K.1` | Pedir claves faltantes | valores de campos por herramienta | actualiza registro y destinos soportados; Enter conserva, '-' elimina |
| `K.2` | Pedir una herramienta | índice entre theHarvester/Shodan/h8mail/amass/recon-ng/SpiderFoot y campos | escribe claves seleccionadas;0 en selector vuelve, sin conceder permisos de red |
| `K.3` | Estado detallado | sin campos secretos | muestra presencia/longitud/divergencia, nunca valor; estado no prueba API válida |
| `K.4` | Sincronizar | seleccionar4 y registro local; sin confirmación adicional | inicia directamente escritura/sincronización del registro y destinos; preserva no vacío solo externo, BD ausente no se inventa |
| `K.5` | Importar claves externas | archivos de herramientas locales | lee destinos soportados al registro, no publica ni valida cuotas |
| `K.0` | Volver | ninguna adicional | no cambia claves; retorna al menú o00 según origen |
| `K.herramienta.numero` | Elegir herramienta en K.2/K.5 | índice dinámico mostrado | selecciona herramienta para pedir/importar; la selección no valida API ni autoriza red |
| `K.herramienta.0` | Cancelar selector de herramienta | 0, vacío o EOF | vuelve sin pedir/importar claves; no borra el registro existente |
| `lista.numero` | Ejecutar hoja por ruta | slots o argumentos manuales | efectos de tablas siguientes; run_all pide confirmación adicional; números no estables |
| `lista.0` | Volver | ninguna adicional | sin ejecución nueva ni borrado de resultados |
| `lista.R` | Recargar listado | ninguna adicional | redescubre fuentes, no genera informe ni ejecuta herramientas |

## Submenús específicos

Las filas de agrupación describen el despacho **real**, no solo el texto de UI.
Por ejemplo05.2 anuncia varias herramientas pero abre http_inject; las demás
siguen disponibles en la lista completa. Ver entradas para sus límites.

| Opción | Finalidad | Entrada | Efectos y límites |
|---|---|---|---|
| `03.1` | Comprobar dependencias | sin objetivo ni URL | command-v/entorno gráfico, sin binarios, instalación ni red; presencia no funcionamiento |
| `03.2` | Puertos básicos | IP/dominio | Nmap100TCP versión ligera sin NSE; no cubre todos los puertos |
| `03.3` | Elegir analizador web | URL explícita y subopción | no deduce HTTPS por puerto; ambas hojas generan tráfico activo |
| `03.web.1` | Nikto | URL explícita validada | evalúa servidor, necesita salida completa; rc0 solo no basta |
| `03.web.2` | Nuclei | URL explícita validada | HTTP medium/high/critical,10peticiones/s, sin Interactsh/update; no confirma automáticamente explotabilidad |
| `03.web.0` | Cancelar web | ninguna adicional | no lanza Nikto/Nuclei; conserva históricos |
| `03.4` | Burp manual | puerto proxy opcional | abre GUI y explica Repeater; Community no escanea ni guarda proyectos |
| `03.5` | Lista avanzada original | elegir ruta y argumentos | incluye full/NSE/Masscan/RustScan; no es perfil básico seguro |
| `03.0` | Volver | ninguna adicional | sin escaneo ni instalación nueva |
| `04.1` | Disponibilidad local | ninguna adicional | no ejecuta binarios/red; NSE se contrasta al usarlo |
| `04.2` | SSH | host y puerto22 default | versión/auth/usuarios/algoritmos; no solo banner |
| `04.3` | FTP | host y puerto21 default | banner/acceso anónimo/listado/NSE; acceso no es solo descubrimiento |
| `04.4` | SMB avanzado | host explícito | null session/RPC/usuarios/shares/enum4linux, activo |
| `04.5` | LDAP | host y puerto389 default | RootDSE/base/usuarios, puede leer información sensible |
| `04.6` | Selección BD | host y subopción | las hojas incluyen accesos/consultas, no solo versiones |
| `04.bd.1` | MySQL | host/puerto3306 | banner y prueba root sin password; requiere autorización de acceso |
| `04.bd.2` | PostgreSQL | host/puerto5432 | prueba postgres/postgres, versión/listado BD; ignora PGHOSTADDR heredado |
| `04.bd.3` | Redis | host/puerto6379 | INFO y KEYS *, puede bloquear bases grandes |
| `04.bd.0` | Cancelar BD | ninguna adicional | sin conexiones nuevas ni limpieza de resultados |
| `04.7` | Selección web | host/URL explícita y tipo | completa o avanzada, no se retira fuzzing |
| `04.web.1` | Web completa | URL/esquema/puerto | headers/tecnologías/robots/sitemap/ffuf, baseline contra catch-all |
| `04.web.2` | Web avanzada | host explícito | revisa siete puertos y archivos sensibles; mayor volumen que completa |
| `04.web.0` | Cancelar web | ninguna adicional | sin peticiones nuevas ni eliminación histórica |
| `04.8` | API | URL explícita | endpoints/Swagger y GET/POST/PUT/DELETE/PATCH/OPTIONS/HEAD; puede modificar recursos |
| `04.9` | Flujo original | target explícito | accesos/NSE/fuzzing/credenciales; no smoke test |
| `04.10` | Visor por objetivo | objetivo elegido | solo evidencia local con sidecars válidos; último intento fallido no revive éxito histórico |
| `04.11` | Lista16 entradas | ruta/slots/manual | incluye auxiliares y generadores; cada hoja conserva efectos propios |
| `04.0` | Volver | ninguna adicional | no abre conexiones nuevas |
| `05.1` | Disponibilidad | sin objetivo ni petición | local sin tráfico/instalación; no compatibilidad operacional |
| `05.2` | Petición capturada | archivo .req | despacha http_inject; rate_limit/sqlmap están en lista completa, no ejecutados solo por elegir2 |
| `05.3` | Sondas web URL | URL explícita | encadena xss/sql_injection/web_attack con confirmaciones; payloads activos |
| `05.4` | SSH/FTP | host y puerto22 default | ssh_attack+Hydra SSH+FTP (22 se transforma a21 para FTP); puede bloquear cuentas |
| `05.5` | Bases de datos | host explícito | llama MySQL/PostgreSQL/Redis, con pruebas de acceso activas |
| `05.6` | Kerberos | DC y dominio | Nmap88 y kinit para cinco usuarios con password vacío/cache privado; no compromiso demostrado |
| `05.7` | CVE | host/puerto22 default | despacha cve_2024_6387, sonda de versión, no exploit probado; otras CVE por lista |
| `05.8` | Payload | LHOST y puerto4444 default | despacha generador PHP, no ejecuta reverse_shell.py automáticamente |
| `05.9` | WiFi | interfaz explícita | llama wifi_attack: sudo iwlist scan y guarda redes/errores; no deauth ni cracking automático |
| `05.10` | Plantilla | objetivo de sesión o loopback default | despacha template.sh, es ejemplo no exploit funcional; Python por lista |
| `05.11` | Flujos completos | objetivo de sesión obligatorio | ejecuta run_all_attacks y run_all_exploits; intrusivo, no validación casual |
| `05.12` | Visor evidencia | objetivo opcional | lectura local, no convierte NO DETERMINADO en resultado limpio |
| `05.13` | Lista completa | ruta y slots/manual | conserva todas las hojas y guías sin prometer integración operacional |
| `05.0` | Volver | ninguna adicional | no inicia nuevas sondas ni revierte las previas |
| `06.1` | Disponibilidad | ninguna adicional | command-v sin ejecutar herramientas; no instala ni cambia permisos |
| `06.2` | Escalada de privilegios | sin subselector adicional | encadena SUID/SGID/capabilities/cron/linpeas locales; generador linpeas puede escribir fuera repo |
| `06.3` | Credenciales locales | sin subselector adicional | encadena linux_creds e historiales; datos sensibles, no usar host personal como fixture |
| `06.4` | Recolección loot | sin subselector adicional | encadena archivos/capturas locales; puede copiar información privada |
| `06.5` | Persistencia | subopción explícita | modifica host actual, no remoto por target de sesión |
| `06.persist.1` | SSH backdoor | puerto opcional | crea/configura acceso persistente según hoja; requiere permiso específico |
| `06.persist.2` | Cron | comando literal requerido | registra ejecución periódica; no rollback automático |
| `06.persist.0` | Cancelar persistencia | ninguna adicional | no crea persistencia nueva |
| `06.6` | Movimiento lateral | tipo, host, usuario/puertos | túneles o generador PSExec, no equivalente a recolección local |
| `06.lateral.1` | SSH jump | host/user/port | conexión SSH hacia destino; depende credenciales y autorización |
| `06.lateral.2` | Port forward | host/local_port/remote_port/user | túnel/listener; puede exponer acceso local, no ejecutado al entrar |
| `06.lateral.3` | PSExec | IP/dominio/usuario/password/comando | generador escribe wrapper; argumentos sensibles ocultos en UI, no garantía sobre procesos externos |
| `06.lateral.0` | Cancelar lateral | ninguna adicional | no crea túnel nuevo ni elimina existente |
| `06.7` | Limpieza | confirmaciones de hoja | trunca/borra logs locales; destructivo, no higiene de tests |
| `06.8` | Flujo completo post | target explícito | combina acciones locales sensibles; mantenimiento del menú no lo vuelve integración operacional |
| `06.9` | Lista completa | ruta y argumentos | todas las hojas/generadores originales, sin autorización implícita |
| `06.11` | Alias lista completa | ruta y argumentos | alias heredado de9 no anunciado; mismas hojas y confirmaciones |
| `06.12` | Alias lista completa | ruta y argumentos | alias heredado de9 no anunciado; no visor adicional |
| `06.13` | Alias lista completa | ruta y argumentos | alias heredado de9 no anunciado; no nueva capacidad |
| `06.10` | Resultados | filtro objetivo opcional | visor local con metadata; no adquisición ni cambio de privilegios |
| `06.0` | Volver | ninguna adicional | no inicia nueva acción local |
| `07.1` | Disponibilidad | ninguna adicional | solo command-v; no ejecuta radio, sudo ni herramientas |
| `07.2` | Guía mantenimiento | ninguna adicional | explica límites; no lee capturas ni certifica handshakes |
| `07.11` | Diez entradas | ruta/manual | preserva fuentes, hojas no operacionalmente integradas ni probadas |
| `07.0` | Volver | ninguna adicional | sin transmisión ni cambios de interfaz |
| `08.1` | Dependencias | ninguna adicional | requirements --check, sin instalación ni sondeo de versión |
| `08.2` | Strings offline | archivo explícito | copia verificada, extrae indicadores; no incidente probado |
| `08.3` | Log offline | archivo explícito | patrones/conteos privados, no diagnóstico de intrusión |
| `08.4` | PCAP offline | captura explícita | capinfos/tshark sobre copia, sin captura en vivo ni red |
| `08.5` | Volatility | memoria Windows, backend/perfil/símbolos locales | offline, sin descargas; tablas no prueban ausencia de intrusión |
| `08.6` | Disco/recuperación | subopción y archivo | metadata por defecto, soporte físico nunca implícito |
| `08.disk.1` | Metadata disco | imagen y opciones | no monta por defecto; mount-copy solo copia explícita |
| `08.disk.2` | Recuperación | archivo y output opcional | Foremost/Scalpel/ddrescue sobre copias; no modifica original |
| `08.7` | Timeline offline | tipo/ruta y year/timezone opcionales | fechas no resueltas no se inventan; sin fuente NO_EVALUABLE |
| `08.timeline.journal` | Journal exportado | archivo JSONL offline | normaliza eventos seleccionados; no lee journal del host implícitamente |
| `08.timeline.auth` | Auth log | archivo offline explícito | extrae eventos de autenticación, años ambiguos quedan sin resolver |
| `08.timeline.syslog` | Syslog | archivo offline explícito | extrae eventos, no demuestra causalidad |
| `08.timeline.dpkg` | Dpkg | archivo offline explícito | registra operaciones de paquetes; no prueba integridad de paquetes |
| `08.timeline.wtmp` | Wtmp | archivo offline explícito | interpreta sesiones de esa copia, no certifica identidad humana |
| `08.timeline.tree` | Árbol de archivos | directorio offline explícito | metadata de copia por fuente, no cronología exhaustiva del sistema |
| `08.8` | Local sensible | subopción explícita | adquisición/host/install/físico solo con confirmaciones nuevas |
| `08.local.1` | RAM local | método auto/avml/lime/dd y padre opcional | ADQUIRIR_MEMORIA; privilegios, dd muestra1GiB siempre parcial |
| `08.local.2` | Timeline host | permiso LOCAL_SI | lee fragmentos históricos locales; no instantánea forense completa |
| `08.local.3` | Flujo local | permiso explícito local | fuentes del host, no reutiliza IP de sesión ni adquiere implícitamente por entrar |
| `08.local.4` | Instalar dependencias | INSTALAR_DEPENDENCIAS literal | apt y paquetes históricos; no instala AVML/LiME ni carga módulos por sí mismo |
| `08.local.5` | Metadata física | dispositivo y permiso | lectura física explícita, sin montaje/hash exhaustivo |
| `08.local.6` | Recuperación física | dispositivo y RECUPERAR_FISICO | ddrescue exclusivamente; daños físicos requieren especialista |
| `08.requirements.1` | Comprobar desde lista | ninguna adicional | disponibilidad solamente, no binarios ni instalación |
| `08.requirements.2` | Instalar desde lista | confirmación directa | modifica paquetes locales; no usar para pruebas del framework |
| `08.9` | Flujo offline | memory/log/pcap/disk/timeline-auth seleccionados | solo fuentes elegidas; cancelación espera cleanup de hoja, no inicia siguiente |
| `08.10` | Visor metadata | filtros run/input/operation opcionales | no relee originales ni cuerpos; cleanup no revalida análisis corrupto |
| `08.11` | Diez originales y visor | ruta allowlist | no descubre scripts recuperados como herramientas; mantiene confirmaciones |
| `08.0` | Volver | 0, ! o EOF | sin análisis ni adquisición nueva |
| `09.1` | Disponibilidad | ninguna adicional | catálogo/PATH, no ejecuta backends ni certifica versiones |
| `09.2` | Guía | ninguna adicional | planes/permisos/límites sin leer config/evidencias |
| `09.3` | Quick | target explícito | preview ping+scan_basic; ejecución requiere EJECUTAR/destino/scanner |
| `09.4` | Full conservador | target explícito | quick+versionesBD, no credenciales/NSE; mismos permisos nuevos |
| `09.5` | Acción avanzada | ID catálogo y campos obligatorios/opcionales | preview y confirmaciones por acción; todas las acciones explicadas en USE |
| `09.6` | Workflow | ruta YAML y target default explícito | valida/preview; no shell ni ejecución por leer YAML |
| `09.11` | Árbol original | ninguna adicional | lista rutas Bash/Python/PS/YAML/Docker/README; no ejecuta por extensión |
| `09.0` | Volver | 0 o EOF | no conserva permisos ni hereda objetivo de sesión |

### 00: asistente y CLI de claves; 10: comandos de evidencia

| Opción | Finalidad | Entrada | Efectos y límites |
|---|---|---|---|
| `00.wizard.1` | Añadir objetivos | host/puerto/protocolo/desc/prioridad | compone lote y confirma antes de escribir targets; no toca scope |
| `00.wizard.2` | Lista nueva | mismo lote y confirmación final | reemplaza targets con .bak; no retira autorizaciones de scope |
| `00.wizard.0` | Salir del asistente | 0 o EOF | sin escritura del lote pendiente |
| `00.wizard.confirmar` | Duplicados/línea/otro/guardar | s/n; host vacío termina lote | duplicado se omite salvo opt-in; prioridad C/A/M/B; guardar requiere confirmación final |
| `00.keys.estado` | Estado API keys | herramienta opcional, json/faltan | solo presencia/longitud/divergencias; no imprime valores |
| `00.keys.poner` | Editar campo | herramienta/campo/valor o --stdin; '-' borra | escribe registro y sincroniza según contrato; no pasar secretos en historial público |
| `00.keys.pedir` | Entrada interactiva | herramienta/campo opcional | pide campos, Enter mantiene y '-' borra; no valida API remota |
| `00.keys.sincronizar` | Aplicar registro | herramienta opcional | conserva valor externo no vacío ausente del registro; no crea BD ficticia |
| `00.keys.importar` | Importación local | herramienta explícita | lee claves ya instaladas al registro; no escanea red |
| `10.0` | Volver | 0, ! o EOF | cancela sin ejecutar hojas ni adoptar objetivo de sesión |
| `10.1` | Disponibilidad local | ninguna adicional | command -v de python3/cutycapt/tcpdump/nmap; no ejecuta ni acredita funcionamiento |
| `10.2` | Importar | tipo y archivo; descripción/etiqueta opcionales | copia privada con SHA-256; no captura ni valida semánticamente el contenido |
| `10.3` | Listar | ninguna adicional | inventario local y problemas de metadata; no recalcula hashes ni prueba integridad |
| `10.4` | Verificar | ninguna adicional | lee contenido y contrasta hashes; vacío/parcial retorna fallo; MD5 legacy no acredita autenticidad |
| `10.5` | Empaquetar | nombre opcional y confirmación de exportación | verifica antes de exportar datos/metadata/manifiesto a11_Reports/evidence; confidencial SIN CIFRAR, sin sobrescribir |
| `10.6` | Captura seleccionada | web/tráfico/scan/contexto local explícitos | solicita selecciones y autorización nueva para red; no adquiere por entrar, sin sudo automático |
| `10.7` | Flujo offline | ninguna adicional | run_all_evidence --offline lista/verifica; no captura ni empaqueta |
| `10.8` | Guía local | ninguna adicional | imprime orientación a USE y límites; presencia no significa integridad ni custodia legal |
| `10.9` | Tres entradas originales | selección guiada posterior | conserva wrappers de importar/capturar/flujo; lista no ejecuta, confirmaciones no se eluden |
| `10.add` | Añadir evidencia | --add TIPO ARCHIVO [DESCRIPCION] | copia privada de screenshot/pcap/credential/finding/proof con metadata SHA-256; tipo no valida contenido, no custodia legal |
| `10.target` | Etiquetar importación | --target ETIQUETA solo con --add | etiqueta explícita opcional, una vez; no adopta sesión ni modifica scope/targets ni atribuye vulnerabilidades |
| `10.verify` | Verificar hashes | --verify como única operación | contrasta SHA-256 nuevo/MD5 legacy; vacío/problemas rc1; MD5 coincidente no demuestra autenticidad |
| `10.list` | Listar evidencia | --list como única operación | inventario sin recalcular hashes; vacío rc0, problemas rc1; listado no validación |
| `10.package` | Empaquetar | --package [NOMBRE] como única operación | verifica antes de exportar datos/metadata/manifiesto a11_Reports/evidence; confidencial SIN CIFRAR; CLI requiere decisión explícita del operador |
| `10.help` | Ayuda | --help o -h sin operación | muestra ayuda manage sin adquisición; no admite combinar con una operación |

### 13: menú Labs y todos sus submenús

Fuentes `13_Labs/main.sh`, `setup_lab.sh` y scripts por categoría. Al entrar,
consulta interfaces/VPN y cuenta directorios locales; eso no conecta VPN ni
demuestra una máquina disponible. Los nombres/rutas heredados no se presentan
como resistentes a traversal ni sustitución concurrente; evitar nombres ajenos
y no usar sus borrados para higiene de tests.

| Opción | Finalidad | Entrada | Efectos y límites |
|---|---|---|---|
| `13.1` | HTB | subopción de máquina | abre gestión de carpetas/notas, no arranca VM |
| `13.2` | THM | subopción de sala | gestión local de notas, no registra ni inicia sala remota |
| `13.3` | Active Directory | dominio y subopción | crea plantillas de trabajo, no despliega controlador |
| `13.4` | Web Apps | aplicación y subopción | plantillas/notas, no instala aplicación vulnerable |
| `13.5` | Cloud | laboratorio y subopción | carpetas/guías, no crea recursos cloud |
| `13.6` | Herramientas rápidas | tipo de herramienta | acciones directas sin contrato de permisos09; pueden contactar red |
| `13.7` | Listar todos | ninguna adicional | run_all_labs imprime directorios, no auditoría ni setup masivo |
| `13.8` | VPN | subopción y .ovpn | puede crear conexiones OpenVPN privilegiadas |
| `13.9` | Eliminar laboratorio | categoría/nombre y s/N | borrado recursivo irreversible de árbol elegido; no usar con nombres no confiables |
| `13.10` | Ayuda Labs | ninguna adicional | muestra comandos/tipos/estructura, no instala herramientas |
| `13.11` | Salir Labs | ninguna adicional | termina main.sh y vuelve al gestor, no desconecta VPN automáticamente |
| `13.htb.1` | Nueva máquina | nombre explícito | htb_setup crea recon/exploits/loot/notes; no VM ni conexión automática |
| `13.htb.2` | Listar máquinas | ninguna adicional | lista carpetas locales, no estado de HTB |
| `13.htb.3` | Notas de máquina | nombre explícito | abre EDITOR/nano, puede modificar notas |
| `13.htb.4` | Notas generales HTB | ninguna adicional | abre archivo local si existe, no consulta plataforma |
| `13.htb.5` | Volver Labs | ninguna adicional | sin nueva acción de setup ni borrado |
| `13.thm.1` | Nueva sala | nombre explícito | thm_setup crea estructura/guías; no inicia instancia |
| `13.thm.2` | Listar salas | ninguna adicional | solo directorios locales, no estado remoto |
| `13.thm.3` | Notas de sala | nombre explícito | editor local con posibilidad de escritura |
| `13.thm.4` | Notas generales THM | ninguna adicional | archivo local si existe, sin consulta remota |
| `13.thm.5` | Volver Labs | ninguna adicional | sin acciones nuevas de plataforma |
| `13.ad.1` | Nuevo dominio | nombre explícito | crea estructura/plantillas AD; no DC ni usuarios reales |
| `13.ad.2` | Listar dominios | ninguna adicional | muestra carpetas locales, no enumeración AD |
| `13.ad.3` | Notas de dominio | nombre explícito | abre README con editor, no conecta dominio |
| `13.ad.4` | Notas ataques AD | ninguna adicional | edita guía local; no ejecuta técnicas descritas |
| `13.ad.5` | Volver Labs | ninguna adicional | no inicia despliegue ni auditoría |
| `13.web.1` | Nueva aplicación | nombre explícito | crea carpetas/guías; no servidor vulnerable |
| `13.web.2` | Listar aplicaciones | ninguna adicional | directorios locales solamente |
| `13.web.3` | Notas aplicación | nombre explícito | editor sobre README local; puede escribir |
| `13.web.4` | Notas generales Web | ninguna adicional | lectura/edición de guía, no solicitudes HTTP |
| `13.web.5` | Volver Labs | ninguna adicional | no crea ni elimina aplicación |
| `13.cloud.1` | Nuevo lab cloud | nombre explícito | estructura/notas, no Terraform ni recursos remotos |
| `13.cloud.2` | Listar labs cloud | ninguna adicional | solo carpetas locales, no inventario cloud real |
| `13.cloud.3` | Notas lab cloud | nombre explícito | editor local, no accede cuentas cloud |
| `13.cloud.4` | Notas generales Cloud | ninguna adicional | guía local si existe; no CLI de proveedor |
| `13.cloud.5` | Volver Labs | ninguna adicional | sin nuevas operaciones cloud |
| `13.tools.1` | Nmap llamado rápido | IP explícita | realmente -sV -sC -p-; completo/NSE, no básico100 |
| `13.tools.2` | WhatWeb | URL explícita | tráfico HTTP directo, no evaluación de vulnerabilidad |
| `13.tools.3` | ffuf | URL con FUZZ y wordlist | fuzzing directo, sin garantías baseline compartidas de04 |
| `13.tools.4` | Gobuster | URL y wordlist | enumeración dir activa; no disponibilidad local solamente |
| `13.tools.5` | Generador shell | tipo/LHOST/LPORT | imprime texto, no lanza conexión ni listener |
| `13.shell.1` | Texto Bash | LHOST/LPORT | imprime receta Bash, no la ejecuta |
| `13.shell.2` | Texto Python | LHOST/LPORT | imprime receta socket/subprocess, no la ejecuta |
| `13.shell.3` | Texto Netcat | LHOST/LPORT | imprime receta nc, disponibilidad -e no probada |
| `13.shell.4` | Texto PHP | LHOST/LPORT | imprime receta PHP, no crea conexión |
| `13.shell.5` | Volver anunciado | selección5 | implementación aún pide host/puerto y cae en inválida antes de tools; no prometer retorno temprano |
| `13.tools.6` | Listener Netcat | puerto explícito | abre socket nc -lvnp; exposición de red local, Ctrl+C detiene |
| `13.tools.7` | Hash de contraseña | texto introducido | muestra MD5/SHA1/SHA256; no almacenamiento seguro de passwords ni auditoría |
| `13.tools.8` | Notas rápidas | texto hasta Ctrl+D | escribe notes_timestamp.txt local; puede contener secretos |
| `13.tools.9` | Volver Labs | ninguna adicional | sin herramientas nuevas, no cierra conexiones previas |
| `13.vpn.1` | HTB VPN | ruta .ovpn existente | sudo openvpn daemon; mensaje no prueba conectividad |
| `13.vpn.2` | THM VPN | ruta .ovpn existente | sudo openvpn daemon; no se ha probado aquí |
| `13.vpn.3` | Desconectar todas | selección explícita | sudo pkill openvpn afecta conexiones ajenas también |
| `13.vpn.4` | Estado VPN | ninguna adicional | ip a busca tun; presencia no autorización ni conectividad real |
| `13.vpn.5` | Volver Labs | ninguna adicional | no desconecta VPN activa |
| `13.delete.1` | Borrar HTB | nombre y s/N | rm recursivo de hackthebox/machines/nombre, irreversible |
| `13.delete.2` | Borrar THM | nombre y s/N | rm recursivo de tryhackme/rooms/nombre, irreversible |
| `13.delete.3` | Borrar AD | nombre y s/N | rm recursivo de active_directory/machines/nombre, irreversible |
| `13.delete.4` | Borrar Web | nombre y s/N | rm recursivo de web_apps/machines/nombre, irreversible |
| `13.delete.5` | Borrar Cloud | nombre y s/N | rm recursivo de cloud/machines/nombre, irreversible |
| `13.delete.6` | Volver Labs | ninguna adicional | sin borrado nuevo ni recuperación de lo eliminado |

## Todas las entradas originales de herramientas

Cada fila identifica una fuente, su entrada, propósito/efectos y límites. Los
archivos declarativos de09 se explican además en su matriz USE; no son hojas
ejecutadas por el descubrimiento genérico. Salidas de escaneo suelen ir a
`<repo>/scans/<herramienta>`; las de módulo (OSINT, loot, capturas, forense,
evidencia e informes) quedan en sus árboles ignorados. Leer guía del módulo
antes de operar: no se ha verificado aquí compatibilidad operacional.

| Ruta de fuente | Entrada | Finalidad y efectos | Límites/condiciones |
|---|---|---|---|
| `00_Config/run_all_config.sh` | sin argumentos | valida/verifica/resume targets/estado claves, cuatro lecturas | no wizard ni sincronización; falla si falla un paso |
| `00_Config/scripts/api_keys.py` | estado/poner/pedir/sincronizar/importar | registro único y seis destinos de herramientas; por gestor abre K | secretos locales; divergencias conservadas, no valida APIs |
| `00_Config/scripts/config_wizard.sh` | asistente local | lote de objetivos y copia .bak al reemplazar | escribe targets, no scope; confirma antes de escribir |
| `00_Config/scripts/parse_targets.py` | input/output/summary según CLI | lee formato pipe y genera resumen/exportación | error devuelve1, no validación de autorización |
| `00_Config/scripts/validate_config.sh` | sin argumentos | comprueba estructura/config y cuenta wordlists | lee datos locales, no red ni autorización legal |
| `00_Config/scripts/verify_00_config.sh` | sin argumentos | verifica archivos/estructura00 | falta archivo devuelve1, presencia no configuración válida operacional |
| `01_OSINT/run_all_osint.sh` | dominio, archivo/empresa opcionales | coordina cinco fuentes y cobertura | metadatos solo archivo explícito; sin DNS activo implícito |
| `01_OSINT/scripts/email_harvester.sh` | dominio, salida opcional | reúne emails mediante fuentes configuradas, con evidencia | APIs opcionales/limitadas; no confundir patrones con emails verificados |
| `01_OSINT/scripts/metadata_extractor.sh` | archivo, salida opcional | extrae metadata local a run OSINT | no descarga archivos ni acredita autor humano |
| `01_OSINT/scripts/osint_harvester.sh` | dominio, salida opcional | WHOIS/DNS/fuentes web con cobertura | theHarvester CLI omitido, optionales visibles; sin AXFR implícito |
| `01_OSINT/scripts/social_media_search.sh` | empresa, salida/dominio opcionales | busca referencias sociales con fuentes/evidencia | no crea hallazgos desde URLs construidas; identidad no confirmada |
| `01_OSINT/scripts/subdomain_finder.sh` | dominio, salida/diccionario/resolver opcionales | fuentes pasivas y DNS acotado solo con diccionario | DNS_SI explícito; no AXFR ni credenciales |
| `02_Recon/run_all_recon.sh` | target opcional | recorre hojas con target o tres primeras entradas targets | heredado, argumentos no ajustados a cada hoja y éxito no acredita cobertura |
| `02_Recon/scripts/auto_recon.sh` | IP o dominio | IP amplía a /24; dominio DNS/AXFR; Nmap completo/NSE/SO y capturas | activo/intensivo, no perfil conservador09 ni éxito fiable por mensaje |
| `02_Recon/scripts/dns_enum.sh` | dominio explícito | dig ANY/AXFR/subdominios/reverse, guarda DNS | incluye intento transferencia zona; errores pueden ocultarse |
| `02_Recon/scripts/fingerprint.sh` | IP explícita | Nmap SO/versiones, WhatWeb cuatro puertos y banners nc | mezcla acciones; no usado como simple versions backend09 |
| `02_Recon/scripts/ping_sweep.sh` | IP/prefijo/red24, rango opcional | ping/reverse y guarda hosts vivos | IP suelta no amplía; filtrado ICMP no prueba host apagado |
| `02_Recon/scripts/screenshotter.sh` | host y puerto | cutycapt/wkhtmltoimage o captura ventana local | fallback manual no prueba página remota; esquema inferido por puerto |
| `03_Scanners/run_all_scanners.sh` | target explícito | coordina escáneres, contabiliza omitidas/fallidas | no perfil básico; tráfico intensivo y requisitos propios |
| `03_Scanners/network_scanners/masscan/masscan_scan.sh` | red, puertos opcionales | barrido TCP rápido y JSON | requiere root, no sudo implícito del menú ni autorización por target |
| `03_Scanners/network_scanners/nmap/nmap_aggressive.sh` | host explícito | Nmap agresivo, resultados por target | alto volumen/privilegios según opciones; no smoke test |
| `03_Scanners/network_scanners/nmap/nmap_scripts.sh` | host, puertos opcionales | ejecuta NSE y guarda resultados | scripts activos, presencia de textoCVE no explotación confirmada |
| `03_Scanners/network_scanners/nmap/nmap_smart.sh` | host, perfil opcional | basico100TCP sin NSE; default completo inteligente | completo sigue default CLI, IPv6 literal no soportado |
| `03_Scanners/network_scanners/rustscan/rustscan_scan.sh` | host explícito | puertos rápidos con publicación stdout tras éxito | binario puede faltar; no confundir rc fallido con cero puertos |
| `03_Scanners/web_scanners/burpsuite/burp_launcher.sh` | puerto opcional | lanza Burp y guía captura manual con puerto real | Community sin escaneo/proyectos guardados; requiere GUI |
| `03_Scanners/web_scanners/nikto/nikto_scan.sh` | URL explícita | escanea servidor y publica evidencia de evaluación completa | comas literales rechazadas; rc0 solo no basta |
| `03_Scanners/web_scanners/nuclei/nuclei_cves.sh` | URL, severidad opcional | plantillas CVE HTTP contra URL | activo, coincidencia no explotabilidad; revisar cobertura |
| `03_Scanners/web_scanners/nuclei/nuclei_scan.sh` | URL explícita | plantillas HTTP10peticiones/s, texto para informes | sin Interactsh/update; no todas vulnerabilidades ni protocolos |
| `04_Enumeration/run_all_enum.sh` | target explícito | flujo de servicios con timeouts y puertos | incluye accesos/NSE/fuzzing/credenciales; no simple fingerprint |
| `04_Enumeration/show_results.sh` | objetivo opcional | visor local de resultados por host/puerto/hashURL | sidecars inválidos o intentos fallidos no reviven evidencia histórica |
| `04_Enumeration/api/enum_api.sh` | host, puerto/esquema o URL | endpoints/Swagger y métodos HTTP incluidos mutadores | POST/PUT/DELETE/PATCH pueden alterar recursos; HEAD usa --head |
| `04_Enumeration/database/enum_mysql.sh` | host, puerto opcional | banner y root sin password | prueba de acceso explícita, no solo versión |
| `04_Enumeration/database/enum_postgres.sh` | host, puerto opcional | banner/login postgres/postgres/versión/bases | credenciales de prueba, PGHOSTADDR heredado ignorado |
| `04_Enumeration/database/enum_redis.sh` | host, puerto opcional | INFO y KEYS * | puede bloquear BD grande; no receta versions09 |
| `04_Enumeration/ftp/enum_ftp.sh` | host, puerto opcional | banner/anónimo/listado/NSEftp | acceso activo y lectura directorios, no pasivo |
| `04_Enumeration/ftp/ftp_anonymous.sh` | host explícito | prueba login FTP anónimo y listado | acceso sin contraseña sigue requiriendo autorización |
| `04_Enumeration/ldap/enum_ldap.sh` | host, puerto opcional | RootDSE/domino/usuarios por LDAP | información sensible; depende permisos/directory |
| `04_Enumeration/ldap/ldap_anonymous.sh` | host explícito | consulta LDAP anónima | anónimo no equivale a uso autorizado |
| `04_Enumeration/smb/enum_smb.sh` | sin args al generador | escribe wrapper SMB a ruta externa según cuerpo | generador, no auditoría integrada ni backend SMB09 |
| `04_Enumeration/smb/enum_smb_advanced.sh` | host explícito | null/RPC/usuarios/shares/NSE/enum4linux | herramientas opcionales con omisiones; más que shares anónimos |
| `04_Enumeration/ssh/enum_ssh.sh` | host, puerto22 opcional | versión/auth/usuarios/algoritmos | requiere permiso users en09; no solo banner |
| `04_Enumeration/web/deepseeenum_web.sh` | sin args al generador | escribe enum_web.sh a su lado | puede reemplazar fuente; no ejecutar como prueba de ayuda |
| `04_Enumeration/web/enum_web.sh` | host, puerto/esquema o URL | headers/WhatWeb/robots/sitemap/ffuf con baseline | fuzzing activo; catch-all no se cuenta como hallazgo |
| `04_Enumeration/web/enum_web_advanced.sh` | host explícito | siete puertos y archivos sensibles | volumen adicional, no acción web original09 |
| `05_Exploitation/run_all_attacks.sh` | target explícito | encadena ataques de servicios/web/AD según hoja | activo e intrusivo; no usar como smoke test |
| `05_Exploitation/run_all_exploits.sh` | target explícito | recorre scripts de exploits | entradas diversas no hacen flujo operacional coherente por existir |
| `05_Exploitation/show_results.sh` | objetivo opcional | visor local por evidencia/clasificación | resultados indeterminados no son negativos limpios |
| `05_Exploitation/active_directory/kerberos_attack.sh` | DC_IP y dominio | Nmap88 y kinit password vacío para administrator/admin/guest/krbtgt/test | cache de tickets privado; respuestas/rechazos no acreditan compromiso AD |
| `05_Exploitation/custom_exploits/template.py` | target y opciones | plantilla Python para desarrollar prueba | ejemplo sin exploit real ni éxito de auditoría acreditado |
| `05_Exploitation/custom_exploits/template.sh` | target explícito | plantilla Bash de prueba | no vulnerabilidad confirmada ni exploit funcional por defecto |
| `05_Exploitation/database/mysql_attack.sh` | target, puerto3306 opcional | doce credenciales comunes, SELECT version; al verificar acceso SHOW DATABASES y tablas mysql | secretos en evidencia privada; denegación es evaluación, todo indeterminado rc1 |
| `05_Exploitation/database/postgres_attack.sh` | target, puerto5432 opcional | trece credenciales, versión y al verificar acceso bases/tablas/usuarios; SearchSploit local | descarta configuraciónPG heredada; secreto privado, no simple banner |
| `05_Exploitation/database/redis_attack.sh` | target, puerto6379 opcional | sin password INFO; solo si confirma acceso KEYS * y CONFIG GET * | lecturas sensibles, KEYS bloquea bases grandes; NOAUTH/NOPERM no acceso |
| `05_Exploitation/exploits/cve_2021_4034.sh` | host local sin target | imprime guía/referencias PwnKit y aviso EUID | no descarga/compila/ejecuta exploit ni comprueba versión instalada |
| `05_Exploitation/exploits/cve_2021_44228.sh` | target, puerto8080 opcional | imprime payload de ejemplo y referencias Log4Shell | no envía payload ni verifica OOB ni ejecuta exploit |
| `05_Exploitation/exploits/cve_2024_6387.sh` | target, puerto opcional | sonda banner/versión SSH regreSSHion | versión no confirma vulnerabilidad ni explotación |
| `05_Exploitation/exploits/reverse_shell.py` | LHOST y LPORT | programa Python con conexión/socket y shell | no generador inerte; ejecutarlo puede abrir canal remoto |
| `05_Exploitation/network/ftp_bruteforce.sh` | host, puerto/wordlist opcionales | Hydra FTP con candidatos | intentos pueden bloquear cuentas; no perfil general09 |
| `05_Exploitation/network/ssh_attack.sh` | target, puerto opcional | pruebas de acceso/SSH según hoja | activo, no confundir salida informativa con credencial válida |
| `05_Exploitation/network/ssh_bruteforce.sh` | host, puerto/wordlist opcionales | Hydra con cuentas root/admin/user/test de hoja | no usado por09, que exige cuenta y límites explícitos |
| `05_Exploitation/web/http_inject.sh` | petición .req, objetivo opcional | replay query/form/JSON con sesión y baselines | CONFIRMADO/FUERTE/DEBIL por evidencia;429/503 cortan sin puntuar |
| `05_Exploitation/web/rate_limit_probe.sh` | petición login, intentos opcionales | cambia solo contraseña wrong-N, máximo200 y corte primer freno | puede bloquear cuenta;403/200 falso/000 indeterminados, no freno |
| `05_Exploitation/web/reverse_shell_php.sh` | LHOST y LPORT | genera archivo PHP payload | no lo ejecuta ni prueba acceso remoto |
| `05_Exploitation/web/sql_injection.sh` | host/puerto/ruta o URL | sondas SQLi activas con evidencia/baseline | palabras SQL/eco/catch-all no confirman inyección |
| `05_Exploitation/web/sqlmap_request.sh` | petición .req, objetivo opcional | sqlmap sonda/replay/enum/dump muestra50filas | SQLMAP_SI, SQLMAP_ENUMERAR, SQLMAP_TABLA separados; indeterminado ante rate limit |
| `05_Exploitation/web/web_attack.sh` | target/puerto o URL | conjunto de sondas web de hoja | activo y dependiente de cobertura, no éxito por mensaje |
| `05_Exploitation/web/web_login_bruteforce.sh` | petición y diccionario, usuario opcional; o manual y diccionario | intentos de login HTTP con candidatos reales | puede bloquear cuentas; default200/tope1000, no rate_limit_probe wrong-N; éxito heurístico no identidad confirmada |
| `05_Exploitation/web/xss.sh` | host/puerto/ruta o URL | sondas/reflexiones XSS con guardas de eco | reflejo no demuestra ejecución en navegador |
| `05_Exploitation/wireless/wifi_attack.sh` | interfaz explícita | verifica interfaz y sudo iwlist scan, guarda redes y errores | no deauth/cracking; hardware/privilegios/alcance radio no verificados |
| `06_PostExploitation/run_all_post.sh` | target explícito | combina operaciones locales sensibles y hojas | no es post remoto coherente; no registrado en09 |
| `06_PostExploitation/show_results.sh` | objetivo opcional | visor local de metadata/evidencia | no recolecta ni valida operacionalmente técnicas |
| `06_PostExploitation/cleanup/logs_cleaner.sh` | confirmaciones locales | limpieza/truncado de logs del host | destructivo; nunca usar para limpiar fixtures del checkout |
| `06_PostExploitation/credential_access/history_parser.sh` | host local sin target | lee historiales y extrae candidatos sensibles | puede exponer secretos; coincidencia no credencial vigente |
| `06_PostExploitation/credential_access/linux_creds.sh` | host local sin target | recoge archivos/datos credenciales locales | requiere permisos; no implica descifrado ni acceso remoto |
| `06_PostExploitation/lateral_movement/port_forward.sh` | target/local_port/remote_port/user opcional | crea túnel SSH | listener y acceso lateral requieren alcance; no rollback automático |
| `06_PostExploitation/lateral_movement/ps_exec.sh` | IP/domain/user/password/command del generado | escribe wrapper PSExec fuera repo | generador no ejecuta auditoría; datos sensibles en comandos |
| `06_PostExploitation/lateral_movement/ssh_jump.sh` | target/user/port opcionales | conexión SSH al destino | necesita credenciales; no se ejecuta en preview09 |
| `06_PostExploitation/loot/file_collector.sh` | host local sin target | copia archivos a loot del módulo | sensible, no saneamiento ni custodia legal |
| `06_PostExploitation/loot/screenshot_collector.sh` | host local sin target | capturas de pantalla locales en loot | no captura de host remoto por target de sesión |
| `06_PostExploitation/persistence/cron_persistence.sh` | comando explícito | crea persistencia en cron local | modifica sistema, requiere permiso específico |
| `06_PostExploitation/persistence/ssh_backdoor.sh` | puerto opcional | configura acceso SSH persistente local | no usar como prueba; cambios de servicios/credenciales sensibles |
| `06_PostExploitation/privilege_escalation/capabilities_check.sh` | host local sin target | inventaría capabilities | candidatos no son escalada demostrada |
| `06_PostExploitation/privilege_escalation/cron_check.sh` | host local sin target | inspecciona cron y permisos | lectura de host, no prueba explotabilidad |
| `06_PostExploitation/privilege_escalation/linpeas.sh` | sin args al generador | escribe wrapper linpeas fuera repo | descarga/ejecución del generado no probado ni integrado |
| `06_PostExploitation/privilege_escalation/suid_check.sh` | host local sin target | busca SUID/SGID locales | hallazgo de permiso no equivale a escalada probada |
| `07_Wireless/run_all_wireless.sh` | interfaz explícita | WiFi scan, monitor y Bluetooth | heredado no integrado operacionalmente; altera radio/interfaces |
| `07_Wireless/bluetooth/bt_discover.sh` | MAC explícita | sudo hcitool info/sdptool/gatttool y logs | radio activo; hardware y rc fiables no acreditados |
| `07_Wireless/bluetooth/bt_scan.sh` | sin argumentos | sudo hcitool/bluetoothctl discovery | no disponibilidad solamente; requiere hardware/permisos |
| `07_Wireless/scripts/channel_hopper.sh` | interfaz explícita | bucle canales1–11 vía sudo iw | altera radio hasta Ctrl+C; no restaura automáticamente |
| `07_Wireless/scripts/interface_manager.sh` | list/monitor/managed y interfaz | lista o cambia modo con ip/iw | monitor/managed modifican interfaz; no captura por sí solo |
| `07_Wireless/wifi/wifi_crack.sh` | handshake y wordlist opcional | intenta aircrack local y guarda log | invocación histórica -b con archivo no demuestra cracking funcional |
| `07_Wireless/wifi/wifi_deauth.sh` | interfaz/BSSID/canal | sudo aireplay deauth continuo | disruptivo, detiene Ctrl+C, no demostración autorizada por defecto |
| `07_Wireless/wifi/wifi_handshake.sh` | interfaz explícita | crea directorio e imprime guía de captura/deauth/verificación | no captura ni verifica handshake automáticamente |
| `07_Wireless/wifi/wifi_monitor.sh` | interfaz explícita | ip/iw down/type monitor/up y comprobación | cambia sistema/radio, requiere sudo/hardware |
| `07_Wireless/wifi/wifi_scan.sh` | interfaz explícita | cambia monitor y sudo iw scan, guarda redes | no comprobación inocua local, no compatibilidad probada |
| `08_Forensics/requirements.sh` | check default o install explícito | disponibilidad o instalación confirmada de paquetes | command-v no acredita versión; instalación no en validación |
| `08_Forensics/run_all_forensics.sh` | fuentes memory/log/pcap/disk/timeline-auth o local explícito | coordina copias por fuente, espera cleanup al cancelar | no IP/glob/adquisición implícitos ni custodia legal |
| `08_Forensics/show_results.sh` | run/input/operation opcionales | metadata validada sin cuerpos ni originales | recibo cleanup independiente no repara análisis corrupto |
| `08_Forensics/disk/disk_forensics.sh` | imagen; physical/mount-copy/offset/length opcionales | metadata; montaje solo copia explícita | físico no montaje/hash exhaustivo; cleanup autenticado tras reapear |
| `08_Forensics/disk/file_carving.sh` | archivo/output opcional, physical explícito | Foremost -i, Scalpel imagen posicional, ddrescue | físico solo ddrescue confirmado, recuperado no evidencia validada automáticamente |
| `08_Forensics/logs/log_analyzer.sh` | log offline explícito | copia/hash, patrones y conteos | no incidente probado ni lectura host implícita |
| `08_Forensics/memory/memory_dump.sh` | padre/method auto/avml/lime/dd opcionales | adquisición local tras ADQUIRIR_MEMORIA | dd muestra1GiB parcial; RAM íntegra no verificada |
| `08_Forensics/memory/strings_analysis.sh` | archivo offline explícito | copia y strings mínimo8, indicadores | texto no prueba intrusión ni secretos vigentes |
| `08_Forensics/memory/volatility_analysis.sh` | memoria/backend/profile/symbols locales | análisis Windows offline en copias | sin descargas; compatibilidad real no certificada |
| `08_Forensics/pcaps/pcap_analyzer.sh` | PCAP offline explícito | capinfos valida formato; tshark obtiene indicadores | no captura en vivo, tráfico observado no vulnerabilidad confirmada |
| `08_Forensics/timeline/timeline_creator.sh` | fuentes/year/timezone/local explícitos | timeline por fuentes seleccionadas | sin fuentes NO_EVALUABLE; años no resueltos no inventados |
| `09_Automation/run_all_automation.sh` | vacío menú o target/flags | núcleo09 preview-first, rc propagado | no flujo99 ni permisos implícitos |
| `09_Automation/bash/auto_recon.sh` | target y flags | preview ping+scan_basic | execute/autorización/scanner separados |
| `09_Automation/bash/auto_enum.sh` | target y flags | preview SSH/shares/versionesBD y web opcional | users/anonymous_access; no puertos completos implícitos |
| `09_Automation/bash/auto_exploit.sh` | target y action explícita | sin acción muestra catálogo; con acción delega al núcleo | no Hydra/SQLmap por defecto, límites y gates en USE |
| `09_Automation/python/orchestrator.py` | selectores/inputs/execute/permisos | CLI común de catálogo cerrado y supervisor secuencial | sin shell strings, preview no lee datos, no objetivo de sesión |
| `09_Automation/python/auto_audit.py` | target/fase opcional/flags | compatibilidad recon/scan/enum/web sobre núcleo | perfiles conservadores, no auditoría completa por mensaje |
| `09_Automation/python/report_generator.py` | input/output/target y execute/report_read | shim preview; motor11 --json, valida generación propia y publica nombres fijos externos | no consume HTML legacy/latest; históricos del input explícito; Linux renameat2 mismo filesystem, EXDEV conserva originales |
| `09_Automation/powershell/auto_enum.ps1` | OutputDirectory y Execute | cinco fuentes locales Windows a subdir privado nuevo | padre controlado, no anti-TOCTOU ni probado en Windows |
| `10_Evidence/auto_capture.sh` | --web URL; --traffic HOST --interface IFACE; --scan HOST --scan-profile basic/full; --system | captura solo selecciones explícitas; --authorize-network para red; --duration 1–300 y --packet-limit 1–10000 solo tráfico; --help sin efectos | sin sudo/instalación; contexto system del operador; diagnósticos privados, fallo/parcial no acredita adquisición |
| `10_Evidence/evidence_manager.sh` | --add/--list/--verify/--package o --help/-h; --target solo add | delega manage al núcleo Python, copia SHA-256, inventario/verificación/exportación | una operación; conserva MD5 legacy sin migración; paquetes confidenciales sin cifrar, no custodia legal |
| `10_Evidence/run_all_evidence.sh` | --offline o --capture con selecciones; --help | offline lista/verifica; capture adquiere solo selecciones explícitas y después lista/verifica | --web/--traffic/--interface/--scan/--scan-profile/--system/--duration/--packet-limit como auto_capture y --authorize-network para red; TARGET antiguo rc2 sin adquirir; no empaqueta ni repara99 |
| `11_Reports/report_engine.py` | --objetivo/--tipo/--scans/--fuentes/--salida; --json para recibo | findings.json y técnico/cliente md/html por generación runs/id con run.json | atribución/cobertura, rc3 sin evidencia evaluable; input puede incluir históricos; automatizar por recibo, no archivos planos |
| `11_Reports/report_generator.sh` | tipo opcional y flags del motor | wrapper motor11 con objetivo/perfil explícito o sesión según CLI11 | cada generación propia; recibo --json identifica salida; informes no prueban fases actuales ni ausencia de fallos |
| `11_Reports/run_all_reports.sh` | objetivo explícito | genera ambos con wrapper/motor y enumera archivos del recibo actual --json | rc0/3 conservados; no presenta histórico tras fallo, ni ejecuta auditoría o empaquetado automático |
| `12_Knowledge_Base/run_all_kb.sh` | término opcional | lista contenido o busca término | documentación local, no técnicas ejecutadas |
| `12_Knowledge_Base/search_kb.sh` | término explícito | grep/búsqueda en guías y cheatsheets | coincidencias son referencias, no hallazgos de objetivo |
| `13_Labs/main.sh` | menú interactivo | gestión carpetas/notas, herramientas, VPN y borrado | no despliegue integral; comandos activos no tienen gates09 |
| `13_Labs/run_all_labs.sh` | sin argumentos | lista laboratorios por categoría | no instala ni arranca máquinas |
| `13_Labs/setup_lab.sh` | tipo htb/thm/ad/web/cloud y nombre | despacha setup de categoría | plantillas locales, no orquestación de infraestructura |
| `13_Labs/hackthebox/htb_setup.sh` | máquina explícita | crea recon/exploits/loot/notes y README | no inicia máquina ni conecta VPN |
| `13_Labs/tryhackme/thm_setup.sh` | sala explícita | crea estructura y notas de sala | no inicia instancia ni registra usuario |
| `13_Labs/active_directory/ad_setup.sh` | dominio explícito | crea estructura/guías AD | no crea dominio real ni controlador |
| `13_Labs/web_apps/web_setup.sh` | aplicación explícita | crea carpetas/notas de pruebas web | no instala app ni servidor vulnerable |
| `13_Labs/cloud/cloud_setup.sh` | nombre explícito | crea estructura/notas cloud | no aprovisiona recursos ni consulta cuenta |

## Verificación y alcance documental

**Historia Round1 (superada, no describe el runner actual): ejecución BLOQUEADA.** Las pruebas nuevas/modificadas se escribieron
sin ejecutarlas. No hay nueva validación RED/GREEN ni aislamiento SO heredado
acreditado. `tests/run_automation.sh` solo contiene un diagnóstico builtin y
exit2; no discovery, intérpretes, probes ni fallback. Los resultados anteriores
son históricos, no autorización para reanudar.

**Observación acotada del controlador,2026-11-14, sobre82663d7
(`82663d746e1b9347a74c7f7836fa6722f04c92a1`):** selector `--suite` rc0;
60sandbox units,0fallos0errores0SKIP;179integration,0fallos0errores1SKIP.
SKIP explícito: `test_automation_powershell.PowerShellTests.test_ps_mock_contract_and_ast`,
pwsh dinámico ausente del runtime; no acredita Windows. Recibos existentes:
`/tmp/opencode/automation-isolated-7708be2f5ddb4d5fb021a35bccce754b/evidence/`
(`inside-result.json` PASS/rc0/tests_started=true, `host-wait.json` rc0,
`sandbox-units.json`, `suite.json`). Es GREEN del selector en ese SHA, no del
finalfix posterior (GREEN **NOT RUN**). No cierra Task4/Task9/global09 ni toda
la rama, ni acredita nuevas carreras/cancelación, Docker u operación real.
Esta conciliación documental no ejecuta nada ni autoriza repetir el selector;
el siguiente gate es revisión independiente acotada y autorización exacta del controlador.

**Historia Task3 Phase B previa al GREEN (2026-11-14):** el controlador observó RED
sobre37c558b:60units PASS;179integration,6fallos0errores1SKIP, solo ficha09
ausente en seis subcasos del casoCLI existente; contratos10/informes sin fallos.
El puente/texto09 se implementan ahora, sin modificar las pruebas Phase A.
GREEN NOT RUN; requiere revisión independiente y comando exacto del controlador.

**Historia Task3 Phase A (2026-11-14):** el controlador ya observó
sobre fdf578f60units PASS y179integration con10fallos,0errores,1SKIP;
los10fallos restantes eran tres casos del contrato10 antiguo (1+8+1), no fallos
de sus backends. Los25casos de informes quedaron GREEN. Esta entrega cambia
extracción/docs10 y exige ficha09 en el puente real; NO ejecuta pruebas nuevas,
no observa aún su RED ni implementa la ficha en el puente. Solo el controlador,
tras revisión estática independiente, puede autorizar el selector exacto09.
No se descubre/ejecuta test_module_intro ni se amplían los25permisos. El antiguo
conteo130hojas/217filas no acredita semántica de la combinación ni cierre global.

Cobertura **estructural** diseñada en `tests/test_automation_contract.py` y
`tests/automation_menu_inventory.py`: cada ruta/opción requerida tiene una fila
con entrada y explicación, no solo título. Mutaciones escritas eliminan cada
fila de los namespaces siguientes e insertan nuevas opciones en texto fuente;
se espera fallo por falta de fila o contrato desconocido. Esto NO contrasta por
sí solo el significado de las celdas con los efectos reales. La **revisión
semántica** exige leer despacho/hojas; K.4 se contrastó específicamente con la
llamada directa a sincronizar, sin confirmación adicional. Una longitud mínima
o una prueba estructural verde nunca certifican veracidad semántica global.

| Namespace | Fuente de opciones | Contrato estructural y límites |
|---|---|---|
| Principal00–13/99/R/T/K/?/Q | cyber_framework.sh:main_menu y main | etiquetas fijas y case de despacho, aliases explícitos, vacío sin acción; sintaxis no reconocida exige revisión |
| R.* | quick_report:case eleccion y abrir | deriva opciones numéricas y selector abrir; selección HTML es una acción, no una fila por alias s/si/sí |
| T.* | change_target:sel/nuevo y etiquetas | índice dinámico→T.numero, manual→T.0; límites/registro contrastados como contrato de fuente; nueva opción literal requiere fila |
| lista.* | run_module_scripts:choice/scripts | índice dinámico→lista.numero,0/recargarR por etiquetas/comparaciones; no números fijos por archivo |
| K.* y K.herramienta.* | keys_menu y keys_elegir_herramienta | case/etiquetas y selector dinámico; elegir4 escribe directamente, sin añadir un gate ficticio |
| 00.wizard.* | config_wizard.sh:main | case de modos y conjunto de prompts de confirmar/duplicados/otro/guardar; cambio de prompts exige revisar contrato |
| 00.keys.* | api_keys.py:main/add_parser (AST como dato) | comandos derivados del parser, no lista fija; firmas de argumentos requieren revisión semántica separada (M1 diferido) |
| 10.add/list/verify/package/help/target | evidence/cli.py:_main/manage.add_argument (AST como dato), wrapper delega manage | flags literales y alias -h→help explícito; root y capture/run excluidos; filas exactas en ambas direcciones, adición/eliminación y alias desconocido exigen revisión |
| 10.0–10.9 | evidence_menu.bash:evidence_menu/case choice | despacho real; ! alias de0, EOF cancela; mutaciones de alta/baja de opciones, namespace distinto de CLI manage |
| 03–08/09/13 submenús | *_menu.bash, CLI09 y main.sh Labs | branches/etiquetas/contratos de fuente; incluye timeline y shell_opt, no ejecución de menús |

Las bibliotecas no son herramientas. La matriz09 cubre ORIGINAL y catálogo,
no certifica integración operacional. Los documentos de cada módulo prevalecen
para detalles; no cambia comportamiento00–08/10–13 ni aprueba fichas ajenas.
