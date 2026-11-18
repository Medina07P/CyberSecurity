"""Pruebas de la tabla fija de módulos del framework (00-13) y su inyección
en los prompts del asistente IA."""
import sys
import unittest
from pathlib import Path

FW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FW / "00_Config" / "lib"))

from ai import modules  # noqa: E402
from ai import prompts  # noqa: E402

EXPECTED_KEYS = tuple("%02d" % i for i in range(14))


class ModulesTests(unittest.TestCase):
    def test_modules_has_14_entries_00_to_13_in_order(self):
        self.assertEqual(tuple(t[0] for t in modules.MODULES), EXPECTED_KEYS)

    def test_modules_entries_have_nonempty_name_and_summary(self):
        for tecla, nombre, resumen in modules.MODULES:
            self.assertTrue(nombre.strip())
            self.assertTrue(resumen.strip())

    def test_modules_context_block_mentions_every_key_and_name(self):
        bloque = modules.modules_context_block()
        for tecla, nombre, _ in modules.MODULES:
            self.assertIn(tecla, bloque)
            self.assertIn(nombre, bloque)

    def test_system_prompt_includes_modules_block(self):
        self.assertIn(modules.modules_context_block(), prompts.SYSTEM)

    def test_system_libre_prompt_includes_modules_block(self):
        self.assertIn(modules.modules_context_block(), prompts.SYSTEM_LIBRE)

    def test_prompts_state_modules_table_needs_no_citation(self):
        # La tabla es información fija del propio prompt, no un fragmento
        # recuperado: el modelo no debe negarse a usarla por falta de cita
        # [ruta:líneas] ni tratarla como un dato sin respaldo.
        for system in (prompts.SYSTEM, prompts.SYSTEM_LIBRE):
            self.assertIn("sin necesitar citar una fuente", system)


if __name__ == "__main__":
    unittest.main()
