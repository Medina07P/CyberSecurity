"""Pruebas de la tabla fija de módulos del framework (00-13) y su inyección
en los prompts del asistente IA."""
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
