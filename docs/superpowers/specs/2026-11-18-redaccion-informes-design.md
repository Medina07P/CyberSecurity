# Redacción en `report_engine.py` — Design (corto)

**Estado:** aprobado por el usuario en conversación (sin preguntas abiertas
adicionales). Alcance acordado explícitamente: solo `report_engine.py`.
`10_Evidence/` queda fuera a propósito (ver "Anti-goals").

## Intención y por qué

`AGENTS.md` registra una brecha: la redacción de secretos que protege la
ingestión del asistente IA local (tecla `I`) no cubre `report_engine.py`,
que sí lee los mismos árboles de `scans/`. Los 14 parsers de
`11_Reports/lib/parsers/*.py` copian líneas literales de las salidas de
herramientas al campo `extracto` de cada `Evidence`, y ese texto llega sin
tocar a `findings.json` y a los informes técnico/cliente en Markdown y
HTML. Algunos de esos parsers (`headers.py`, `sqlmap.py`, `http_inject.py`)
son justamente los que capturan cabeceras `Cookie`/`Authorization` o
volcados de `sqlmap`.

## Goals

- Ningún `extracto` de `Evidence` que llegue a `findings.json` o a un
  informe renderizado puede contener un secreto en texto claro que
  `00_Config/lib/ai/redact.py` ya sepa reconocer.
- Un solo punto de aplicación, no 14 ediciones de parser.
- `redact()` se reutiliza tal cual (mismo criterio que pidió el usuario
  para `avml`/`api_keys.py`: nunca reimplementar lo que ya existe). Cero
  cambios en `00_Config/lib/ai/redact.py`.

## Non-goals

- No se toca `descripcion`, `impacto_cliente`, `recomendacion`, `titulo`:
  son plantillas fijas del catálogo (`lib/catalog.py::_RULES`), no texto
  crudo de `scans/`. Sus huecos (`{variable}`) ya vienen de valores cortos
  y controlados (CVE, CVSS, nombres de regla), no de líneas de salida de
  herramientas.
- No se añade redacción a `activo` (IP/host) ni a `archivo`/`linea`: son
  metadatos de ubicación, no contenido capturado.
- No se cambia el formato de `findings.json` ni la API pública del motor
  (`collect()`, `Finding`, `Evidence` mantienen su firma).

## Anti-goals (lo que esto NO debe convertirse en)

- **No redactar `10_Evidence/`.** `00_Config/lib/evidence/package.py` es
  un paquete de custodia forense: hash SHA-256 por miembro, detección de
  modificación, garantía de "esto es exactamente lo que se capturó".
  Redactar esos bytes rompe esa garantía. La categoría `credentials/` de
  `00_Config/lib/evidence/inventory.py::CATEGORIES` guarda secretos **a
  propósito** — no es un descuido que corregir. Esta brecha se documenta
  como decisión de diseño consciente, no como pendiente técnico.
- No se construye ninguna "exportación compartible redactada" nueva para
  `10_Evidence/`. Si en el futuro se pide, es una feature nueva aparte,
  con su propio brainstorming.

## Constraints

- `redact()` es puro (`str -> str`), sin estado ni I/O; importarlo desde
  `11_Reports/lib/engine.py` no introduce una dependencia nueva fuera de
  biblioteca estándar (el comentario de cabecera de `model.py` dice
  "Solo biblioteca estándar: el motor debe funcionar en cualquier Kali sin
  dependencias adicionales" — `redact.py` también es solo `re`, así que
  esto se mantiene).
- El punto de aplicación es `lib/engine.py::collect()`, después de que los
  parsers construyen los `Finding` y antes de `merge_findings`/
  `sort_findings` (aplicar antes de fusionar es más simple: redactar una
  vez por `Evidence` original, no después de deduplicar listas).
- La ruta de re-render (`--desde-json` → `from_json` → `finding_from_dict`)
  **no** vuelve a redactar: un `findings.json` ya escrito ya pasó por este
  punto una vez; redactar dos veces es inocuo pero innecesario, así que no
  se añade ahí a propósito (YAGNI).

## Approaches considerados

1. **Redactar en cada parser** (en el punto donde cada uno construye
   `Evidence(extracto=...)`). Rechazado: 14 ediciones casi idénticas,
   fácil que un parser nuevo futuro se olvide de aplicarlo.
2. **Redactar en `render.py`, justo antes de escribir cada línea del
   informe.** Cubre los informes pero no `findings.json` (que se escribe
   desde `to_json(collected, meta)` antes de `write_reports`, con los
   mismos `Finding` sin redactar) — dejaría `findings.json` con el secreto
   en claro aunque el `.md`/`.html` no lo tuviera. Rechazado: brecha
   parcial, justo el tipo de resultado que este trabajo quiere cerrar.
3. **Redactar una vez en `collect()`, mutando los `Evidence.extracto`
   antes de devolver `ParseResult`/`Finding`.** Elegido: un solo punto,
   cubre `findings.json` y ambos informes por construcción (todo lo que
   sale de `collect()` ya está limpio), y no depende de que cada parser lo
   recuerde.

## Lo que decide el builder

- Nombre exacto de la función nueva en `lib/engine.py` (p. ej.
  `_redact_evidence` o inline en el bucle de `collect()`); la firma debe
  operar sobre `list[Finding]` o sobre cada `Finding.evidencia`, con
  `Evidence` inmutable (`frozen=True` en `model.py`) — hay que reconstruir
  cada `Evidence` con `extracto` redactado, no mutarla in place.
- Si conviene un helper en `model.py` (p. ej. `redact_findings(findings)`)
  para que el import de `redact.py` quede cerca del modelo, o dejarlo
  directamente en `engine.py`. Cualquiera de las dos es correcta; el
  builder decide y lo deja como su llamada en el plan/commit.
