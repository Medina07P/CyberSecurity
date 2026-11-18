# Contexto de módulos y persistencia del resumen — Plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** El asistente IA del framework (tecla `I`) sabe explicar qué hace cada
módulo 00–13 incluso en conversación libre (opción 7), y recupera
automáticamente el resumen guardado de la conversación anterior para el
objetivo de sesión en vez de empezar siempre de cero.

**Architecture:** Dos añadidos aislados sobre el paquete existente
`00_Config/lib/ai/`: (1) un fichero nuevo `modules.py` con una tabla fija de
los 14 módulos, inyectada en los dos prompts `system` (`prompts.py`); (2) una
función de lectura `load_saved_summary()` en `assistant.py` que
`make_assistant()` (`09_Automation/ai/ai_assistant.py`) usa para precargar
`Conversation.summary`, con un aviso de una sola vez en `menu.py`.

**Tech Stack:** Python 3 estándar (sin dependencias nuevas); `unittest` para
las pruebas, siguiendo los ficheros `tests/test_ai_*.py` ya existentes.

**Spec:** `docs/superpowers/specs/2026-11-18-asistente-ia-contexto-modulos-design.md`

## Global Constraints

- Todo texto que llegue al modelo o se muestre pasa por `redact.redact()`,
  incluido el resumen cargado desde disco (defensa en profundidad: puede
  haberse editado a mano).
- `summaries/<slug>.md` no cambia de formato, ubicación ni permisos (`600`).
- El resumen se guarda y se carga por `sources.slug(target)`, nunca de forma
  global ni cruzada entre objetivos.
- Reutilizar `context.SUMMARY_CAP`/`context._cap` para el recorte; no inventar
  un límite de tamaño nuevo (hay precedente de acceder a un nombre "privado"
  de otro submódulo del mismo paquete: `index.py` ya llama a
  `_sources._walk`/`_sources.is_data_path`).
- La tabla de módulos cubre exactamente `00`–`13` (14 entradas); no incluye
  `R`/`T`/`K`/`?`/`Q` (son acciones del gestor, no módulos del framework).
- El aviso de resumen recuperado se imprime **una sola vez**, en el primer
  dibujado de la cabecera de `menu.run()`; no debe reaparecer en redibujados
  posteriores (respuestas, vueltas de los submodos 5/6/7, Enter en blanco).

## Review Focus

- Resumen guardado con un secreto pegado a mano (editado fuera del flujo
  normal de guardado) → debe redactarse igual al cargarlo. Test: Task 2.
- Fichero de resumen sin la línea de cabecera `# Resumen de la
  conversación...` (corrupto o editado) → no debe reventar; se usa el cuerpo
  tal cual, o `None` si queda vacío. Test: Task 2.
- `target` ausente o slug vacío → no debe construir una ruta como
  `summaries/.md` ni lanzar excepción. Test: Task 2 (`make_assistant()` en
  Task 3 ni siquiera llama a `load_saved_summary` cuando `target` es falsy,
  por construcción del `if target:`).
- Resumen guardado para OTRO objetivo (slug distinto al actual) no debe
  filtrarse al objetivo que se está abriendo ahora. Test: Task 2.
- El aviso de resumen recuperado no debe repetirse en redibujados
  posteriores de la cabecera. Test: Task 3.

---

## Task 1: Tabla de módulos y su inyección en los prompts

**Files:**
- Create: `CyberSecurity-Framework/00_Config/lib/ai/modules.py`
- Modify: `CyberSecurity-Framework/00_Config/lib/ai/prompts.py`
- Test: `CyberSecurity-Framework/tests/test_ai_modules.py` (nuevo)

**Interfaces:**
- Produces: `modules.MODULES: Tuple[Tuple[str, str, str], ...]` — 14 tuplas
  `(tecla, nombre, resumen)`, ordenadas `"00"` a `"13"`.
- Produces: `modules.modules_context_block() -> str` — texto listo para pegar
  en un prompt `system`, una línea por módulo.
- Consumes (en `prompts.py`): `modules.modules_context_block()`.
- Produces (para Task 3, indirectamente): nada — este task no toca
  `assistant.py` ni `menu.py`.

- [ ] **Step 1: Escribir el test que falla**

En `tests/test_ai_modules.py`:

```python
import sys
from pathlib import Path

FW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FW / "00_Config" / "lib"))

from ai import modules  # noqa: E402
from ai import prompts  # noqa: E402

EXPECTED_KEYS = tuple("%02d" % i for i in range(14))


def test_modules_has_14_entries_00_to_13_in_order():
    assert tuple(t[0] for t in modules.MODULES) == EXPECTED_KEYS


def test_modules_entries_have_nonempty_name_and_summary():
    for tecla, nombre, resumen in modules.MODULES:
        assert nombre.strip()
        assert resumen.strip()


def test_modules_context_block_mentions_every_key_and_name():
    bloque = modules.modules_context_block()
    for tecla, nombre, _ in modules.MODULES:
        assert tecla in bloque
        assert nombre in bloque


def test_system_prompt_includes_modules_block():
    assert modules.modules_context_block() in prompts.SYSTEM


def test_system_libre_prompt_includes_modules_block():
    assert modules.modules_context_block() in prompts.SYSTEM_LIBRE
```

- [ ] **Step 2: Ejecutar y comprobar que falla**

Run: `cd CyberSecurity-Framework && python3 -m pytest tests/test_ai_modules.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'ai.modules'` o
`AttributeError`).

- [ ] **Step 3: Implementar `00_Config/lib/ai/modules.py`**

`MODULES` con estas 14 entradas exactas (tecla, nombre, resumen — resumen en
una frase, sin punto final, derivada de `docs/MENU-OPCIONES.md`):

```python
MODULES = (
    ("00", "Configuración y claves",
     "valida y edita datos locales (scope, targets, claves de API); no lanza ni autoriza una auditoría"),
    ("01", "OSINT",
     "busca información pública del objetivo (dominios, correos, redes sociales, metadatos)"),
    ("02", "Reconocimiento",
     "descubre hosts, DNS y huellas de red alrededor del objetivo"),
    ("03", "Escáneres",
     "analiza puertos y servicios con Nmap, Nikto, Nuclei y Burp, de básico a avanzado"),
    ("04", "Enumeración de servicios",
     "profundiza en un servicio concreto: SSH, FTP, SMB, LDAP, web, bases de datos"),
    ("05", "Explotación",
     "prueba activa de vulnerabilidades (inyección, fuerza bruta acotada, plantillas); no todo es un exploit funcional"),
    ("06", "Post-explotación",
     "mantenimiento tras el acceso: persistencia, movimiento lateral, botín"),
    ("07", "Wireless y radio",
     "mantenimiento y guías de redes inalámbricas; no transmite ni captura por sí solo"),
    ("08", "Forense",
     "análisis offline por copias de disco, memoria o red, sin tocar el objetivo en vivo"),
    ("09", "Automatización",
     "encadena otras fases bajo permisos explícitos, con vista previa antes de ejecutar"),
    ("10", "Evidencia",
     "organiza capturas, logs y pruebas del objetivo sin adoptarlo como sesión"),
    ("11", "Informes",
     "genera los informes técnico y de cliente a partir de los resultados existentes (tecla R)"),
    ("12", "Base de conocimiento",
     "consulta cheatsheets y referencias técnicas guardadas localmente"),
    ("13", "Laboratorios",
     "abre entornos de práctica (plantillas, VPN, limpieza) para entrenar sin un objetivo real"),
)


def modules_context_block() -> str:
    cabecera = "Módulos del framework (tecla → nombre — qué hace):"
    lineas = ["«%s» %s — %s." % t for t in MODULES]
    return cabecera + "\n" + "\n".join(lineas)
```

- [ ] **Step 4: Modificar `00_Config/lib/ai/prompts.py`**

Importar `from . import modules` arriba del fichero. Añadir, tras definir cada
constante de texto existente, una frase de introducción y el bloque:

```python
_MODULOS_INTRO = ("Estos son los módulos del framework y qué hace cada uno "
                  "(información fija del propio framework, no un dato del "
                  "objetivo de la persona):\n")

SYSTEM = SYSTEM + "\n" + _MODULOS_INTRO + modules.modules_context_block()
SYSTEM_LIBRE = SYSTEM_LIBRE + "\n" + _MODULOS_INTRO + modules.modules_context_block()
```

(Se añade **después** de que `SYSTEM`/`SYSTEM_LIBRE` ya estén completamente
definidas como están hoy, sin reescribir su texto existente.)

- [ ] **Step 5: Ejecutar y comprobar que pasa**

Run: `cd CyberSecurity-Framework && python3 -m pytest tests/test_ai_modules.py -v`
Expected: PASS (5 tests).

- [ ] **Step 6: Ejecutar la suite completa del paquete `ai` para comprobar que no rompió nada**

Run: `cd CyberSecurity-Framework && python3 -m pytest tests/test_ai_assistant.py tests/test_ai_context.py -v`
Expected: PASS (sin regresiones; `prompts.SYSTEM`/`SYSTEM_LIBRE` más largos no
rompen nada porque ningún test existente fija su longitud exacta).

- [ ] **Step 7: Commit**

```bash
git add CyberSecurity-Framework/00_Config/lib/ai/modules.py \
       CyberSecurity-Framework/00_Config/lib/ai/prompts.py \
       CyberSecurity-Framework/tests/test_ai_modules.py
git commit -m "feat(ai): tabla fija de los 14 módulos en ambos prompts del asistente"
```

---

## Task 2: `load_saved_summary()` en el núcleo del asistente

**Files:**
- Modify: `CyberSecurity-Framework/00_Config/lib/ai/assistant.py`
- Test: `CyberSecurity-Framework/tests/test_ai_assistant.py`

**Interfaces:**
- Consumes: `redact.redact(text: str) -> str` (ya existe en `redact.py`);
  `context._cap(text: str) -> str` y `context.SUMMARY_CAP` (ya existen en
  `context.py`, acceso de paquete como el que ya usa `index.py` con
  `_sources`).
- Produces: `assistant.load_saved_summary(data_dir, slug: Optional[str]) -> Optional[str]`,
  función de módulo (no método de `Assistant`), para que Task 3 la importe
  como `from ai.assistant import load_saved_summary`.

- [ ] **Step 1: Escribir los tests que fallan**

Añadir a `tests/test_ai_assistant.py` (reutilizar el helper `_write` y el
patrón `tempfile.TemporaryDirectory()` ya usados en ese fichero):

```python
class LoadSavedSummaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data = Path(self.tmp.name)
        self.summaries = self.data / "summaries"
        self.summaries.mkdir()

    def _write_summary(self, slug, body, header=True):
        texto = (("# Resumen de la conversación — objetivo: %s\n\n" % slug)
                 if header else "") + body
        _write(self.summaries / ("%s.md" % slug), texto)

    def test_returns_none_when_file_absent(self):
        self.assertIsNone(asst.load_saved_summary(self.data, "10.0.0.5"))

    def test_returns_none_when_slug_empty_or_none(self):
        self.assertIsNone(asst.load_saved_summary(self.data, ""))
        self.assertIsNone(asst.load_saved_summary(self.data, None))

    def test_returns_body_without_header_line(self):
        self._write_summary("10.0.0.5", "Hablamos del puerto 22 abierto.\n")
        out = asst.load_saved_summary(self.data, "10.0.0.5")
        self.assertIn("puerto 22", out)
        self.assertNotIn("Resumen de la conversación", out)

    def test_returns_body_when_header_missing(self):
        self._write_summary("10.0.0.5", "Texto sin cabecera.\n", header=False)
        out = asst.load_saved_summary(self.data, "10.0.0.5")
        self.assertEqual(out, "Texto sin cabecera.")

    def test_returns_none_for_other_target_slug(self):
        self._write_summary("otro-objetivo", "Esto es de otro objetivo.\n")
        self.assertIsNone(asst.load_saved_summary(self.data, "10.0.0.5"))

    def test_redacts_secret_in_loaded_body(self):
        self._write_summary("10.0.0.5", "La contraseña es password=SuperSecreto123\n")
        out = asst.load_saved_summary(self.data, "10.0.0.5")
        self.assertNotIn("SuperSecreto123", out)
        self.assertIn("[REDACTADO]", out)

    def test_caps_long_summary_like_conversation_cap(self):
        largo = "x" * (context.SUMMARY_CAP + 500)
        self._write_summary("10.0.0.5", largo)
        out = asst.load_saved_summary(self.data, "10.0.0.5")
        self.assertLessEqual(len(out), context.SUMMARY_CAP)
```

- [ ] **Step 2: Ejecutar y comprobar que fallan**

Run: `cd CyberSecurity-Framework && python3 -m pytest tests/test_ai_assistant.py::LoadSavedSummaryTests -v`
Expected: FAIL (`AttributeError: module 'ai.assistant' has no attribute 'load_saved_summary'`).

- [ ] **Step 3: Implementar `load_saved_summary` en `00_Config/lib/ai/assistant.py`**

Añadir `from . import context as _context` a los imports del fichero (junto a
los ya existentes `from . import prompts`, `from . import redact as _redact`,
`from . import sources`). Implementar:

```python
def load_saved_summary(data_dir, slug: Optional[str]) -> Optional[str]:
    """Lee <data_dir>/summaries/<slug>.md si existe y devuelve su cuerpo
    (sin la línea de cabecera), redactado y recortado al mismo límite que usa
    Conversation. None si no hay nada que cargar o la lectura falla."""
    if not slug:
        return None
    path = Path(data_dir) / "summaries" / ("%s.md" % slug)
    try:
        if not path.is_file() or path.is_symlink():
            return None
        texto = path.read_text(encoding="utf-8")
    except OSError:
        return None
    lineas = texto.splitlines()
    if lineas and lineas[0].startswith("#"):
        lineas = lineas[1:]
    cuerpo = "\n".join(lineas).strip()
    if not cuerpo:
        return None
    return _context._cap(_redact.redact(cuerpo))
```

- [ ] **Step 4: Ejecutar y comprobar que pasan**

Run: `cd CyberSecurity-Framework && python3 -m pytest tests/test_ai_assistant.py::LoadSavedSummaryTests -v`
Expected: PASS (7 tests).

- [ ] **Step 5: Ejecutar toda la suite del fichero para comprobar que no rompió nada**

Run: `cd CyberSecurity-Framework && python3 -m pytest tests/test_ai_assistant.py -v`
Expected: PASS, mismo número de tests que antes + 7.

- [ ] **Step 6: Commit**

```bash
git add CyberSecurity-Framework/00_Config/lib/ai/assistant.py \
       CyberSecurity-Framework/tests/test_ai_assistant.py
git commit -m "feat(ai): load_saved_summary lee y redacta el resumen guardado del objetivo"
```

---

## Task 3: Carga automática al abrir el asistente y aviso de una sola vez

**Files:**
- Modify: `CyberSecurity-Framework/09_Automation/ai/ai_assistant.py:45-47,123-128`
- Modify: `CyberSecurity-Framework/00_Config/lib/ai/menu.py:282-296` (bucle `run`)
- Test: `CyberSecurity-Framework/tests/test_ai_cli.py`

**Interfaces:**
- Consumes: `assistant.load_saved_summary(data_dir, slug)` de Task 2;
  `sources.slug(target) -> str` (ya existe).
- Produces: `Assistant.resumen_recuperado: bool` — atributo opcional fijado
  por `make_assistant()` tras la construcción (mismo patrón que el ya
  existente `asis.data_dir = str(data_dir())`); ausente o `False` cuando no
  había nada que cargar. `menu.run()` lo lee con
  `getattr(assistant, "resumen_recuperado", False)`.

- [ ] **Step 1: Escribir los tests que fallan**

Añadir a `tests/test_ai_cli.py`, en la clase `MenuTests` (o una clase nueva
`SummaryRecoveryTests(CliBase)` si se prefiere aislar):

```python
NOTICE_MARK = "He recuperado el resumen"


class SummaryRecoveryTests(CliBase):
    # self.data es la ruta que _env() ya expone como AI_DATA_DIR; se escribe
    # directamente ahí, sin leer variables de entorno.

    def test_menu_shows_recovered_summary_notice_once(self):
        resumen_dir = self.data / "summaries"
        resumen_dir.mkdir(parents=True)
        (resumen_dir / ("%s.md" % SLUG)).write_text(
            "# Resumen de la conversación — objetivo: %s\n\n"
            "Hablamos de puertos abiertos en el objetivo.\n" % TARGET,
            encoding="utf-8")
        p = self.run_cli([], stdin_text="   \n0\n", server="ok")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.count(NOTICE_MARK), 1)

    def test_menu_no_notice_without_saved_summary(self):
        p = self.run_cli([], stdin_text="   \n0\n", server="ok")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn(NOTICE_MARK, p.stdout)
```

- [ ] **Step 2: Ejecutar y comprobar que falla**

Run: `cd CyberSecurity-Framework && python3 -m pytest tests/test_ai_cli.py -k recovered_summary -v`
Expected: FAIL (`test_menu_shows_recovered_summary_notice_once` falla porque
`NOTICE_MARK` nunca aparece; `test_menu_no_notice_without_saved_summary` ya
pasaría tal cual — se escribe de todas formas para fijar el comportamiento).

- [ ] **Step 3: Modificar `09_Automation/ai/ai_assistant.py`**

Cambiar la línea de import:

```python
from ai.assistant import Assistant                        # noqa: E402
```

por:

```python
from ai.assistant import Assistant, load_saved_summary     # noqa: E402
```

Modificar `make_assistant`:

```python
def make_assistant(fw, cfg, idx, target, client):
    conv = Conversation(max_tokens=cfg["contexto_max_tokens"],
                        literal_turns=cfg["turnos_literales"])
    asis = Assistant(fw, client, idx, conv, target, top_k=cfg["top_k"])
    asis.data_dir = str(data_dir())
    if target:
        resumen = load_saved_summary(asis.data_dir, sources.slug(target))
        if resumen:
            conv.summary = resumen
            asis.resumen_recuperado = True
    return asis
```

- [ ] **Step 4: Modificar `00_Config/lib/ai/menu.py`**

En `run()`, añadir una bandera local y el aviso de una sola vez justo antes de
`_header`:

```python
def run(stdin, stdout, assistant_factory):
    assistant = assistant_factory()
    primera_vuelta = True
    while True:
        try:
            status = _model_status(assistant)
            if primera_vuelta:
                if getattr(assistant, "resumen_recuperado", False):
                    stdout.write(
                        "He recuperado el resumen de tu conversación anterior "
                        "sobre «%s».\n" % assistant.target)
                primera_vuelta = False
            _header(stdout, assistant, status)
            ...
```

(el resto del cuerpo de `run()` no cambia; solo se inserta el bloque anterior
entre el cálculo de `status` y la llamada a `_header`, y se declara
`primera_vuelta = True` antes del `while True`).

- [ ] **Step 5: Ejecutar y comprobar que pasan**

Run: `cd CyberSecurity-Framework && python3 -m pytest tests/test_ai_cli.py -k recovered_summary -v`
Expected: PASS (2 tests).

- [ ] **Step 6: Ejecutar toda la suite del asistente para comprobar que no rompió nada**

Run: `cd CyberSecurity-Framework && python3 -m pytest tests/test_ai_cli.py tests/test_ai_assistant.py tests/test_ai_modules.py -v`
Expected: PASS, sin regresiones en los tests ya existentes de `test_ai_cli.py`
(en particular `test_eof_exits_zero_without_side_effects`, que no escribe
ningún resumen guardado y por tanto no debe mostrar el aviso).

- [ ] **Step 7: Commit**

```bash
git add CyberSecurity-Framework/09_Automation/ai/ai_assistant.py \
       CyberSecurity-Framework/00_Config/lib/ai/menu.py \
       CyberSecurity-Framework/tests/test_ai_cli.py
git commit -m "feat(ai): recupera el resumen guardado al abrir el asistente, aviso de una sola vez"
```
