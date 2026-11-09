# 01_OSINT — recopilación real y trazable

Los seis scripts comparten un núcleo en `00_Config/lib/osint/`. No generan
perfiles concatenando nombres con URLs ni anuncian éxito cuando falla una fuente.
Requisitos: Python 3 y PyYAML; WHOIS, whatweb, dig y extractores locales son
opcionales y se informa si no están disponibles. No se instala nada al ejecutar.

## Uso

Desde `01_OSINT/` (las rutas de salida no dependen del directorio del llamador):

```bash
./run_all_osint.sh example.com
./run_all_osint.sh example.com documento.pdf 'Example Corp'
# Empresa explícita sin documento; en el gestor deja archivo vacío:
./run_all_osint.sh example.com '' 'Example Corp'

./scripts/social_media_search.sh 'Example Corp'
# Dar el dominio ayuda a vincular perfiles desde el sitio oficial:
./scripts/social_media_search.sh 'Example Corp' '' example.com
./scripts/email_harvester.sh example.com
./scripts/osint_harvester.sh example.com
./scripts/subdomain_finder.sh example.com
./scripts/metadata_extractor.sh documento.pdf
```

Los scripts individuales admiten `[directorio_salida]` como segundo argumento.
Una salida explícita externa se permite con advertencia: puede no estar ignorada
por git. `run_all` comparte las consultas al sitio, certificados y DNS; no
ejecuta cinco recolecciones independientes. Si no das empresa, busca el dominio
completo y lo anuncia: no inventa el nombre quitando etiquetas del dominio.

## Qué consulta y qué no

- Redes: enlaces de la página principal oficial y búsquedas reales de cuentas
  GitHub. Con Brave configurado consulta búsquedas para LinkedIn, X, GitHub,
  Instagram, Facebook y TikTok. No raspa redes tras login ni evade CAPTCHA.
- Emails: direcciones publicadas en la página consultada y Hunter Domain Search
  si hay clave. Solo el dominio solicitado, sin inventar patrones ni tratar
  nombres de usuario como correos. No verifica entregabilidad ni busca filtraciones.
- Dominios: WHOIS, whatweb de bajo impacto, certificados públicos de crt.sh y
  resolución DNS de los nombres observados. Un certificado no prueba que el
  host resuelva hoy y DNS no prueba disponibilidad HTTP.
- Metadatos: únicamente archivo local proporcionado. `pdfinfo` para PDF,
  `exiftool` para imágenes/Office y hasta 50 líneas de `strings` para otros
  formatos, etiquetadas como texto observado, no metadatos estructurados.

### APIs y cobertura

La opción `K` del gestor configura el registro existente. Esta entrega utiliza
`theharvester.brave.key`, `theharvester.github.key` y
`theharvester.hunter.key`. Si un campo falta en el registro, lee el primer
`api-keys.yaml` efectivo en `~/.theHarvester`, `/etc/theHarvester` o
`/usr/local/etc/theHarvester`. No escribe ni sincroniza claves durante OSINT.
`KEYS_FILE` y `KEYS_HARVESTER_DIRS` conservan sus overrides para pruebas.

Las claves viajan en cabeceras, nunca en argv ni informes. Que haya una clave
no garantiza que sea válida o que tenga cuota: un rechazo aparece como bloqueo.
GitHub puede funcionar sin clave con sus límites públicos; Brave y Hunter sin
clave se anuncian como omitidos. No se promete compatibilidad universal con las
otras APIs configurables en K. Sin Brave no hay búsqueda web general de redes;
sin dominio no puede haber vínculo desde el sitio oficial.

**theHarvester CLI se anuncia omitido**: sus fuentes inspeccionadas ocultan
errores y hacen reintentos internos que impiden garantizar el presupuesto.
Se usan adaptadores directos para las fuentes integradas; no se ejecuta `-b all`.

Cobertura deliberadamente acotada: página principal, primera página de GitHub
(30 cuentas), Brave (10 resultados por consulta a seis plataformas) y Hunter
(10 direcciones). No son inventarios exhaustivos.

## Fuerza bruta de subdominios (DNS, no contraseñas)

Solo sobre dominios autorizados. No se activa desde `run_all` ni al dejar vacío
el diccionario. En el gestor, el tercer campo de `subdomain_finder.sh` es el
diccionario; el cuarto, IP de resolver opcional.

```bash
./scripts/subdomain_finder.sh example.com '' ./subdominios.txt
# Resolver explícito opcional, sin imponer un DNS público:
./scripts/subdomain_finder.sh example.com '' ./subdominios.txt 192.0.2.53
```

Exige escribir **DNS_SI** antes de consultar. EOF o cualquier otra respuesta
cancela. El diccionario debe ser local: una etiqueta o prefijo por línea, `#`
para comentarios. Deduplica, valida y rechaza más de **1.000 candidatos únicos**
antes de empezar. No descarga diccionarios.

Como máximo **5 consultas DNS/s agregadas**, incluyendo tres nombres de control
aleatorios, A/AAAA/CNAME y reintentos; esta versión usa un trabajador, sin
reintentos ocultos. Presupuesto DNS de **120 s**: puede terminar parcial antes
de completar el diccionario y lo indica. Tras tres candidatos consecutivos con
fallos de DNS, se detiene. NXDOMAIN no es un fallo de transporte.

Respuestas iguales a los controles wildcard o controles rotatorios se etiquetan
`ambiguo_wildcard`, no descubrimientos confirmados. Es una guarda conservadora,
no una garantía ante cualquier DNS dinámico. No hay AXFR automático ni modo AXFR
en esta entrega; tampoco fuerza bruta de credenciales.

## Evidencia, estados y salida

Cada ejecución crea `osint_<objetivo>_<id>/` dentro de:

| Entrada | Directorio por defecto |
|---|---|
| run_all / osint_harvester | `01_OSINT/domains/` |
| email_harvester | `01_OSINT/emails/` |
| social_media_search | `01_OSINT/social_media/` |
| subdomain_finder | `01_OSINT/subdomains/` |
| metadata_extractor | `01_OSINT/metadata/` |

Contiene `resultados.json` (versión 1), `resumen.txt` y `errores.log`. Guarda
objetivo, fecha UTC, fuentes, estados y evidencia; no pisa ejecuciones anteriores.
Los árboles por defecto están ignorados por git: no publiques resultados reales.
El motor de informes de vulnerabilidades no consume estos datos OSINT todavía.

- `vinculado_desde_sitio`: el sitio de referencia publicó el enlace; no prueba
  propiedad ni que el perfil esté disponible.
- `candidato`: coincidencia de búsqueda sin atribución.
- `descubierto`: nombre observado en certificados; `resuelto`: respuesta DNS.
- Cada fuente indica CON RESULTADOS, SIN RESULTADOS, OMITIDA, BLOQUEADA, FALLIDA
  o TIEMPO AGOTADO. Cero resultados no equivale a fuente fallida.

Máximo 15 s por solicitud HTTP, 120 s por herramienta/fuente y 10 solicitudes
por API y ejecución (incluidos reintentos). Ante 429/503 reintenta una vez con
Retry-After; si la espera no cabe, corta sin dormir indefinidamente. El bloqueo
persistente no genera resultados de esa fuente.

Códigos: **0**, fuentes ejecutadas completadas (incluso vacías); **1**, ejecución
parcial, bloqueo, fallo, timeout o ninguna fuente utilizable; **2**, argumentos,
configuración, cancelación o escritura inválidos. Las omisiones previstas no
fallan solas, pero siempre aparecen en cobertura. Logs pueden incluir omisiones
y límites de paginación, no únicamente errores fatales.

## Verificación local

`bash CyberSecurity-Framework/tests/run_osint.sh` desde la raíz. Usa fixtures,
herramientas falsas y red externa bloqueada, sin claves ni cuotas reales. Estas
pruebas no equivalen a una integración en vivo con cada proveedor.
