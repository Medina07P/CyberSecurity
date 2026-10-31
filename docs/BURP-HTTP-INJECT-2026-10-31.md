# Fase Burp: petición capturada, inyección y validación por niveles

- **Fecha:** 2026-10-31
- **Diseño:** `docs/superpowers/specs/2026-10-31-burp-http-inject-design.md`
- **Plan:** `docs/superpowers/plans/2026-10-31-burp-http-inject.md`

## Qué se construyó y por qué

El framework solo atacaba URLs que él mismo construía: GET sobre una lista fija de
parámetros. Contra una aplicación que autentica por cabecera y habla JSON por POST eso no
prueba nada, y además imprime «sin diferencias», que se lee como «objetivo limpio». La pieza
que faltaba era aceptar **la petición que el operador ya capturó en Burp** y probar inyección
sobre sus parámetros reales, con sesión y cuerpo incluidos.

Dos piezas nuevas:

| Pieza | Dónde | Qué hace |
|---|---|---|
| `http_inject.sh` | `05_Exploitation/web/` | Inyecta en query, formulario y JSON de una petición cruda; clasifica cada diferencia por evidencia |
| `burp_launcher.sh` | `03_Scanners/web_scanners/burpsuite/` | Arranca Burp desde el gestor, comprueba el puerto real, verifica la captura y explica el flujo manual |

## Lo que se comprobó en Burp Community (2026.3.2, Kali)

| Hecho | Evidencia |
|---|---|
| `--project-file` se ignora: «Disk-based projects are only supported on Burp Suite Professional» | diálogo de arranque |
| El arranque se para en un diálogo «Start Burp»; no hay modo desatendido | ventana, y `xdotool` para pulsarlo |
| `java -jar` directo se para además en un modal «JRE warning»; el wrapper `/usr/bin/burpsuite` ya pasa `--suppress-jre-check` | dos arranques |
| El listener por defecto es 127.0.0.1:8080 | `ss -ltnp` |
| No se pudo confirmar que `--config-file` cambie el puerto del listener | con el 8080 ocupado no apareció listener ni en 8080 ni en 8099 |
| Community no tiene Scanner ni REST API | comportamiento y edición |

Por eso el lanzador **no asume el puerto: lo comprueba**, y avisa de que al cerrar Burp se
pierde el historial.

## Uso

```bash
# 1. Arranca Burp (puerto opcional; si no, 8080 y luego 8080-8099)
./CyberSecurity-Framework/03_Scanners/web_scanners/burpsuite/burp_launcher.sh

# 2. Captura una petición en Repeater y guárdala como texto:
#    scans/burp/peticion_<objetivo>.txt

# 3. Prueba la inyección sobre ella
cd CyberSecurity-Framework
./05_Exploitation/web/http_inject.sh ../scans/burp/peticion_127.0.0.1.txt 127.0.0.1

# 4. Cierra el Burp que arrancaste
./03_Scanners/web_scanners/burpsuite/burp_launcher.sh --parar
```

`http_inject.sh` también lee de la entrada estándar con `-` (pegar y Ctrl-D).

### Opciones por entorno

`HTTP_INJECT_NIVEL=fuertes` (menos detalle en consola), `HTTP_INJECT_PARAM=<nombre>`,
`HTTP_INJECT_RETARDO`, `HTTP_INJECT_ESQUEMA`, `HTTP_INJECT_PROXY`, `HTTP_INJECT_SI=1`
(sin confirmación, para automatizar), `HTTP_INJECT_MAX` (tope de peticiones, 400),
`HTTP_INJECT_SLEEP` y `HTTP_INJECT_UMBRAL` (retardo de los payloads y umbral de confirmación).

## Qué significa cada nivel

| Nivel | Regla | Qué NO significa |
|---|---|---|
| `CONFIRMADO` | Diferencial reproducible que un valor benigno no puede producir: par booleano (verdadera = línea base, falsa distinta, 2/2), retardo 2/2, `49` de SSTI, reflejo sin escapar en HTML/JS | No significa «explotado»: significa que hay que mirarlo con la evidencia en Repeater |
| `FUERTE` | Diferencia específica del payload sin prueba de impacto: error de BD solo con comilla, reflejo escapado, un único retardo | Puede ser un WAF o un error genérico |
| `DEBIL` | Cualquier otra diferencia con la línea base, incluidos los parámetros con línea base inestable | Con catch-all detectado es ruido |

Guardas que sostienen los niveles: línea base ×3 por parámetro, neutralización del eco (el
payload y sus variantes URL/HTML se sustituyen antes de comparar), detector de catch-all,
aviso de sesión caducada (401/403) y repetición 2/2 para confirmar.

## Salidas

En `scans/web/` (git-ignored):

- `http_inject_<objetivo>_<puerto>.txt` — informe legible por niveles.
- `http_inject_<objetivo>_<puerto>.tsv` — máquina: `nivel param clase payload codigo tamano ms evidencia`.
- `http_inject_<objetivo>_<puerto>/` — pares `.req`/`.resp` de lo CONFIRMADO y FUERTE, con la
  respuesta truncada a 64 KB, listos para pegar en Repeater.

## Verificación

- `tests/run_tests.sh` → 196 asserts, 0 fallos (incluye servidor de prueba con login JSON,
  catch-all, línea base inestable, par booleano, error de BD, retardo, XSS, SSTI y comandos).
- `tests/run_e2e.sh` → 11/0 · `tests/run_smoke.sh` → 0 fallos · `tests/run_wizard.sh` → 58/0.
- `bash -n` sobre los 116 `.sh` y los 6 `.bash`, con `stderr` capturado: limpio.
- Prueba real contra el servidor de prueba: `GET /sqli?id=1` → 1 CONFIRMADO (`sqli_bool`) con
  su par `.req`/`.resp`; `GET /safe?id=1` (catch-all) → 0 confirmados y aviso de ruido.

## Límites conocidos

- Community no escanea y no guarda proyectos: el lanzador lo dice y no promete más.
- `multipart/form-data` y `Transfer-Encoding: chunked` se rechazan con mensaje.
- El cuerpo JSON exige `python3`.
- Repetir una petición puede tener efectos reales en el cliente (altas, cobros): con métodos
  distintos de `GET`/`HEAD` hay confirmación explícita con el número de peticiones y un tope.
