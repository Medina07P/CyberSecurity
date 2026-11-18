"""Pruebas del gestor de contexto del asistente IA."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

FW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FW / "00_Config" / "lib"))

from ai import context  # noqa: E402
from ai.context import Conversation, estimate_tokens  # noqa: E402


def fill(conv, n, size=10):
    for i in range(n):
        conv.add("user" if i % 2 == 0 else "assistant", f"m{i:02d}" + "x" * size)


class ContextTests(unittest.TestCase):
    def test_estimate_tokens(self):
        self.assertEqual(estimate_tokens(""), 0)
        self.assertEqual(estimate_tokens("a" * 40), 10)

    def test_keeps_only_last_n_literal_turns(self):
        c = Conversation(max_tokens=10000, literal_turns=4)
        fill(c, 10)
        lit = [m for m in c.messages() if m["role"] != "system"]
        self.assertEqual(len(lit), 4)
        self.assertTrue(lit[0]["content"].startswith("m06"))
        self.assertTrue(lit[-1]["content"].startswith("m09"))

    def test_dropped_turns_go_to_summary(self):
        c = Conversation(max_tokens=10000, literal_turns=2)
        c.add("user", "A" * 500)
        c.add("assistant", "respuesta")
        c.add("user", "tres")
        c.add("assistant", "cuatro")
        self.assertIn("user: " + "A" * 200, c.summary)
        self.assertNotIn("A" * 201, c.summary)
        self.assertIn("assistant: respuesta", c.summary)
        first = c.messages()[0]
        self.assertEqual(first["role"], "system")
        self.assertIn("Resumen de la conversación anterior", first["content"])

    def test_no_summary_message_when_nothing_dropped(self):
        c = Conversation(max_tokens=1000)
        c.add("user", "hola")
        self.assertEqual(c.summary, "")
        self.assertEqual([m["role"] for m in c.messages()], ["user"])

    def test_summary_is_capped(self):
        c = Conversation(max_tokens=10**6, literal_turns=1)
        for i in range(200):
            c.add("user", f"{i:03d}" + "y" * 300)
        self.assertLessEqual(len(c.summary), context.SUMMARY_CAP)
        self.assertIn("198", c.summary)  # lo más reciente se conserva

    def test_cap_preserves_provenance_prefix_after_fold(self):
        c = Conversation(max_tokens=100000, literal_turns=2)
        aviso = context.AVISO_RESUMEN_CARGADO
        c.summary = aviso + "y" * (context.SUMMARY_CAP - 10)
        fill(c, 6, size=50)  # fuerza al menos un _fold con literal_turns=2
        self.assertTrue(c.summary.startswith(aviso))
        sin_aviso = c.summary[len(aviso):]
        self.assertLessEqual(len(sin_aviso), context.SUMMARY_CAP)
        self.assertEqual(c.summary.count(aviso), 1)

    def test_usage_percent_grows_and_warns_at_80(self):
        c = Conversation(max_tokens=100, literal_turns=50)
        self.assertEqual(c.usage_percent(), 0)
        self.assertFalse(c.needs_warning())
        c.add("user", "x" * 200)  # 50 tokens
        self.assertEqual(c.usage_percent(), 50)
        self.assertFalse(c.needs_warning())
        c.add("assistant", "x" * 120)  # +30
        self.assertEqual(c.usage_percent(), 80)
        self.assertTrue(c.needs_warning())
        c.add("user", "x" * 4000)
        self.assertEqual(c.usage_percent(), 100)

    def test_usage_guard_for_bad_max_tokens(self):
        c = Conversation(max_tokens=0)
        c.add("user", "hola")
        self.assertEqual(c.usage_percent(), 100)
        self.assertEqual(Conversation(max_tokens=0).usage_percent(), 0)

    def test_reset_clears_history_and_returns_summary_when_asked(self):
        c = Conversation(max_tokens=1000, literal_turns=1)
        c.add("user", "uno")
        c.add("assistant", "dos")
        s = c.reset(save_summary=True)
        self.assertIn("uno", s)
        self.assertEqual(c.messages(), [])
        self.assertEqual(c.summary, "")

    def test_reset_digest_when_nothing_dropped(self):
        c = Conversation(max_tokens=1000)
        c.add("user", "pregunta")
        s = c.reset(save_summary=True)
        self.assertIn("user: pregunta", s)

    def test_reset_without_save_returns_none(self):
        c = Conversation(max_tokens=1000)
        c.add("user", "hola")
        self.assertIsNone(c.reset())
        self.assertEqual(c.messages(), [])

    def test_reset_empty_with_save_returns_none(self):
        self.assertIsNone(Conversation(max_tokens=1000).reset(save_summary=True))

    def test_reset_combines_existing_summary_with_unfolded_turns(self):
        c = Conversation(max_tokens=1000, literal_turns=1)
        c.add("user", "uno")
        c.add("assistant", "dos")  # pliega "uno", queda resumen
        self.assertTrue(c.summary)
        c.add("user", "tres")  # queda sin plegar: literal_turns=1 lo mantiene
        s = c.reset(save_summary=True)
        self.assertIn("uno", s)
        self.assertIn("tres", s)

    def test_summarizer_callback_used_when_given(self):
        calls = []

        def summ(msgs):
            calls.append(msgs)
            return "RESUMEN-X"

        c = Conversation(max_tokens=1000, literal_turns=1, summarizer=summ)
        c.add("user", "a")
        c.add("assistant", "b")
        c.add("user", "c")
        self.assertTrue(calls)
        self.assertIn("RESUMEN-X", c.summary)
        self.assertNotIn("user: a", c.summary)

    def test_summarizer_output_is_capped(self):
        c = Conversation(max_tokens=1000, literal_turns=1,
                         summarizer=lambda m: "z" * 10000)
        c.add("user", "a")
        c.add("user", "b")
        self.assertLessEqual(len(c.summary), context.SUMMARY_CAP)

    def test_summarizer_failure_falls_back_to_extractive(self):
        def boom(msgs):
            raise RuntimeError("modelo caído")

        c = Conversation(max_tokens=1000, literal_turns=1, summarizer=boom)
        c.add("user", "importante")
        c.add("assistant", "ok")
        self.assertIn("user: importante", c.summary)

    def test_unknown_role_rejected(self):
        with self.assertRaises(ValueError):
            Conversation(max_tokens=100).add("tool", "x")

    def test_empty_content_is_ignored(self):
        c = Conversation(max_tokens=100)
        c.add("user", "")
        c.add("user", "   ")
        self.assertEqual(c.messages(), [])

    def test_content_stored_as_given(self):
        c = Conversation(max_tokens=100)
        c.add("user", "  con espacios \n")
        self.assertEqual(c.messages()[0]["content"], "  con espacios \n")

    def test_nothing_written_to_disk(self):
        with tempfile.TemporaryDirectory() as d:
            cwd = os.getcwd()
            os.chdir(d)
            try:
                c = Conversation(max_tokens=100, literal_turns=1)
                fill(c, 6)
                c.messages(), c.usage_percent(), c.reset(save_summary=True)
                self.assertEqual(os.listdir(d), [])
            finally:
                os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()
