# Uso de 09 — contratos, no autorización

**Implementación/verificación lista PARA revisión final independiente; NO
aprobación global.** Sobre1fde308 el controlador verificó60sandbox units PASS y
159legacy/integration,0fallos0errores1SKIP dinámico (pwsh ausente del runtime),
rc0;25casos autorizados ejecutados, workers con Landlock ABI7 observado.
Carreras:20repeticiones×8=160PASS/rc0. Cancelación externa tras primera repetición:
SIGINT130 con24descendientes observados salidos y SIGTERM143 con23salidos;
señales solo al launcher directo por pidfd según controlador, runs parciales
conservados. Resultados sintéticos, no auditoría ni compatibilidad operacional.
El usuario autorizó delete/replace de descartables sintéticos NUEVOS por caso.
Los estados sintéticos intermedios nuevos son descartables: no se exigen
before-images de cada run.json. La habilitación escrita usa worker fork por caso
con Landlock ABI≥3 heredado por fork/exec, raíz nueva fijada y permiso cerrado
para25IDs; si falta soporte, BLOCKED sin fallback. El controlador conserva
recibos/logs por pipe y los árboles finales, nunca cleanup global. Fuentes/config
real, evidencias/logs y runs previos quedan fuera de la excepción. Pendiente
revisión final aislador/global09; M1 terminal-receipt sigue diferido. Sin
certificado kernel/hostil, validación Windows/Docker ni rama completa verde.
Esta actualización solo documenta recibos existentes: no autoriza nuevos runs,
auditorías, instalaciones ni limpieza global; se conserva el incidente histórico.
[Uso, selectores y límites del aislador de pruebas](../../docs/AUTOMATION-TEST-ISOLATION-2026-11-13.md).

[Inventario completo del gestor, módulos 00–13 y todas sus entradas](../../docs/MENU-OPCIONES.md).
Los ejemplos parten del directorio `CyberSecurity-Framework`, con destinos
documentales 192.0.2.1/example.com. No son instrucciones para ejecutar pruebas
reales sin alcance escrito. Presencia en PATH no prueba funcionamiento.

## Preview primero; ejecución separada

```bash
python3 -I 09_Automation/python/orchestrator.py --target 192.0.2.1
```

Preview valida fuentes/entradas y muestra herramientas, volumen, destinos y
gates; no abre scans, configuración, credenciales o peticiones ni crea runs.
El YAML explícitamente seleccionado sí se lee. El objetivo no se toma de sesión,
no se registra en scope/targets y no se persisten permisos.

Solo después de revisar el plan y contar con autorización:

```bash
python3 -I 09_Automation/python/orchestrator.py --target 192.0.2.1 --execute --authorized-target 192.0.2.1 --allow scan_basic:scanner
```

`--execute` no autoriza por sí solo: cada destino de red requiere
`--authorized-target` y cada gate `--allow id_paso:gate`. Flags huérfanos se
rechazan. Seleccionar perfil no concede permisos. El menú pide EJECUTAR,
destino literal y tokens por paso; EOF/cancelar no ejecuta. `--list` lista
catálogo y `--check` comprueba disponibilidad sin lanzar binarios; son modos
exclusivos. Sin argumentos la CLI muestra ayuda; el wrapper abre menú.

## Perfiles y menú

Opciones: 1 disponibilidad; 2 guía sin datos; 3 quick (target); 4 full (target);
5 avanzadas (acción y sus campos); 6 workflow (ruta YAML y target default);
11 lista original (solo muestra archivos); 0 vuelve. 3–6 previsualizan y solo
ejecutan mediante confirmaciones nuevas. No existe bypass por extensión.

Quick/recon = ping y scan_basic dependiente; full añade db_versions después
del scan. Son perfiles conservadores: no incluyen puertos completos, NSE, SO,
SSH/SMB, Nikto, Hydra ni SQLmap implícitamente. `--domain example.com` añade
OSINT con destino/autorización propios; `--url http://192.0.2.1` añade WhatWeb
con host concordante; `--include-config` añade lectura local opt-in.
`--report-input /ruta/scans` añade informe al final, solo si no falló antes.
Los pasos `report` repetidos con IDs distintos son válidos: cada uno reserva
`<run>/report-<step-id>/report-profile` y `reports/` privados, sin sobrescribir
otro paso. El shim de informe único conserva sus nombres externos y códigos
raw del motor; publica desde el namespace del paso `report`.
`--phase scan` usa scan_basic; `--phase enum` pide permisos users y
anonymous_access para SSH/shares, añade versiones BD y WhatWeb solo con URL;
`--phase web` usa WhatWeb y Nikto. `--phase exploit` exige elegir `--action`.
`--phase post` es guía a 06: preview rc0, ejecución rc2, sin persistencia ni
cleanup registrados. Para acciones adicionales usar `--action` y no combinar
selectores. Ejemplo local sin ejecución:

```bash
python3 -I 09_Automation/python/orchestrator.py --action services --target 192.0.2.1 --ports 22,80
python3 -I 09_Automation/python/orchestrator.py --workflow 09_Automation/workflows/quick_scan.yaml --target 192.0.2.1
```

YAML v1 admite solo nombres/acciones/inputs/dependencias validados, no código,
shell, env, ejecutables ni overrides de raíz. Máximo 64 KiB, profundidad12,
64 pasos; timeout global 1–86400 s; quick600/full3600, paso300, SQLmap900,
limitado por presupuesto restante. IPv4/dominios, no IPv6 literal de host;
URL y target concordantes; puertos TCP explícitos y volumen visible, sin
reutilizar parsing histórico para elegir puertos. SSH default22 visible.

## Acciones conservadas y condiciones

| Acción | Entrada | Efectos/backend | Gate y límites |
|---|---|---|---|
| ping | target explícito | un paquete ICMP | sin gate adicional; silencio no prueba apagado |
| scan_basic | target explícito | hoja03 Nmap100 TCP/versiones ligeras, salida compartida | scanner; sin NSE, lock09 no coordina invocaciones externas |
| ports_full | target explícito | Nmap65535 TCP, XML privado | full_ports; no encadena parsing de servicios |
| services | target y ports | Nmap -Pn -sV, XML privado | sin gate adicional; solo puertos declarados |
| nse_services | target y ports | Nmap -sV -sC, XML privado | nse; scripts activos |
| os_detect | target explícito | Nmap -O, XML privado | os; sin sudo automático |
| scan_vuln | target y ports | Nmap NSE vuln, XML privado | nse_vuln; no confirma vulnerabilidad |
| ssh_enum | target, port opcional | hoja04 versión/auth/usuarios/algoritmos | users; no es solo banner |
| smb_shares | target explícito | smbclient anónimo -L -N | anonymous_access; no RPC adicional |
| db_versions | target explícito | Nmap3306/5432/6379 | sin gate adicional; sin contraseñas, consultas ni KEYS |
| web_tech | target y url | WhatWeb -a3 | sin gate adicional; host concordante |
| web_scan | target y url | hoja03 Nikto | web_scan; tráfico activo, evaluación completa exigida |
| smb_audit | target explícito | hoja04 RPC/shares/NSE | smb_users; enum4linux opcional con omisión visible |
| osint_domains | domain explícito | hoja01 WHOIS/DNS a salida privada | osint; PyYAML requerido; herramientas opcionales no inventan cobertura |
| config_check | sin target | validador00 lee config/wordlists | config_read; nunca durante preview |
| ssh_attempts | target, account, wordlist, max_attempts, max_seconds, port opcional | Hydra una cuenta, copia privada acotada, t1/f | credential_attempts; 1–200 intentos, 1–300s; puede bloquear cuenta |
| sqlmap_request | target, request_file regular, scheme; database/table opcionales | hoja05 petición real y muestra50 filas | sqlmap_probe y sqlmap_replay obligatorios; enum/dump independientes, ver abajo |
| exploit_lookup | product/versión | SearchSploit local, argumento único | sin red ni ejecución de exploits |
| report | target y report_input | motor11, salida privada | report_read; input puede contener históricos, no acredita fases actuales |

Hydra usa `--account`, `--wordlist`, `--max-attempts`, `--max-seconds`; no
hereda las cuatro cuentas fijas de la hoja05. SQLmap usa `--request-file` y
`--scheme http` o https; preview no lee la petición. Ejecución valida su
autoridad/contexto antes de contactar, rechaza directorios/stdin y conflictos
de host. `--allow sqlmap_request:sqlmap_probe` permite la sonda; además exige
`--allow sqlmap_request:sqlmap_replay` incluso si no acaba necesitándose replay.
No hereda `SQLMAP_*`. Sin sqlmap_enum no enumera bases; con
`--allow sqlmap_request:sqlmap_enum` sin database permite modo dbs; con
`--database` autoriza tables. `--table` exige base o base.tabla y permiso
`--allow sqlmap_request:sqlmap_dump`, además de enum. Seleccionar tabla no
concede permiso de volcado. La hoja conserva SQLMAP_SI/SQLMAP_ENUMERAR/SQLMAP_TABLA,
traducidos por el adaptador, no debilitados. 429/503 no se puntúan como hallazgo.

## Matriz de entradas originales de 09

| Entrada original | Propósito/entrada | Efectos actuales | Condiciones/límites |
|---|---|---|---|
| `bash/auto_recon.sh` | target y flags CLI | preview recon común, ping+scan_basic | ejecución/gates separados; no barrido /24 implícito |
| `bash/auto_enum.sh` | target y flags CLI | preview enum SSH/shares/BD, web solo con URL | users/anonymous_access; smb_audit opt-in conserva enum4linux |
| `bash/auto_exploit.sh` | target y acción explícita | sin acción solo catálogo; delega al núcleo | no Hydra/SQLmap implícitos; permisos por acción |
| `python/orchestrator.py` | selectores, inputs y permisos CLI | planifica y ejecuta secuencialmente por opt-in | sin os.system/shell strings ni objetivo de sesión |
| `python/auto_audit.py` | target, recon/scan/enum/web opcional y flags | compatibilidad sobre mismo núcleo | full conservador; post no ejecución; no éxito incondicional |
| `python/report_generator.py` | input/output/target explícitos | shim obsoleto preview; ejecución motor11 y publicación | report_read; nombres fijos, padre nuevo, Linux renameat2, ver abajo |
| `powershell/auto_enum.ps1` | OutputDirectory local existente y Execute separados | sistema, usuarios, top20CPU, netstat y tareas | sin red remota; padre controlado, no garantía anti-TOCTOU |
| `workflows/quick_scan.yaml` | YAMLv1 más target default CLI | ping y scan_basic declarativos | no intérprete de comandos ni ejecución al leer |
| `workflows/full_audit.yaml` | YAMLv1 más target default CLI | quick y versiones BD declarativos | no credenciales, NSE, persistencia ni cleanup implícitos |
| `docker/Dockerfile` | fuentes allowlist exacta | define imagen Kali/usuario toolkit y dependencias | estático, no build probado ni sandbox |
| `docker/docker-compose.yml` | contexto framework con filtro específico | define servicio no root sin montajes/host network/privilegios | estático; no up probado; red de contenedor no autoriza destino |
| `run_all_automation.sh` | vacío menú; target/flags CLI | entrada común preview-first; nunca flujo99 | rc propagado; ejecución requiere opt-in |
| `README.md` | lectura de guía local | enlaza uso/inventario/estado | documentación no acredita operación real |

## Salidas, fallos y plataformas

Ejecución crea `scans/automation/<run>/` privado (directorios700, archivos600),
manifiesto atómico `run.json` y logs stdout/stderr por paso. Un rc0 del backend
sin datos no fabrica hallazgos/cobertura: el manifiesto describe procesos, no
evaluación de seguridad. Primer fallo/timeout/cancelación omite el resto con
causa. Estados pendiente/ejecutando/completado/fallido/cancelado/omitido; CLI rc2
entrada/permisos inválidos, rc1 backend/preflight/timeout, rc130/143 señales.
Motor11 rc3 (sin evidencia evaluable) no se convierte en informe evaluable;
el shim conserva ese rc. Logs y copias de peticiones/diccionarios pueden ser
sensibles: conservar bajo control y no publicar. Scan básico/Nikto/SSH/SMB/SQLmap
pueden mantener salidas compartidas heredadas además del run09; lock09 no
coordina lanzamientos directos de otros módulos.

Supervisor POSIX controla grupo de procesos, TERM gracia2s y luego KILL,
reapea líder sin iniciar paso siguiente tras cancelación; no promete controlar
procesos que se escapen de su grupo/sesión ni herramientas arbitrarias. Entorno
reconstruido: BASH_ENV/PYTHONPATH/SQLMAP_* heredados no autorizan ni cargan código.

Informe exige input explícito, target y report_read; puede incluir **históricos**
atribuibles de ese árbol. No certifica que fases09 los hayan generado. Shim:
el directorio padre indicado por output debe ser nuevo; publica nombres fijos
findings.json e informes técnico/cliente md/html. Publicación Linux `renameat2`
sin reemplazo, **mismo filesystem**; `EXDEV` falla conservando originales en el
run privado, sin fallback de copia ni sobrescritura. No basta que exista HTML
para afirmar evaluación exitosa.

PowerShell solo recolecta localmente tras ambos parámetros, en subdirectorio
nuevo; padre local preexistente y controlado, rechaza enlaces/reparse points
detectables, pero no es garantía anti-TOCTOU ante sustitución concurrente de
ancestros. No probado en Windows. Docker solo se verificó estáticamente: no
build ni up probado; filtro deny-by-default por nombres exactos, sin config,
credenciales ni evidencias; no es un sandbox ni permiso operacional.
