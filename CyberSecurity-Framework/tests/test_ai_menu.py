"""Pruebas unitarias del bucle de menu.py con un assistant doble (sin subproceso)."""
import io
import sys
import unittest
from pathlib import Path

FW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FW / "00_Config" / "lib"))

from ai import context, menu  # noqa: E402


class _TogglingClient:
    """is_up() es False la primera vez que se consulta y True después."""

    def __init__(self):
        self.calls = 0
        self.model = "fake:1b"

    def is_up(self):
        self.calls += 1
        return self.calls > 1

    def has_model(self):
        return True


class _AlwaysDownClient:
    """is_up() siempre False: el modelo nunca llega a estar disponible."""

    def __init__(self):
        self.model = "fake:1b"

    def is_up(self):
        return False

    def has_model(self):
        return True


class _FakeAssistant:
    def __init__(self, client, resumen_recuperado=True):
        self.client = client
        self.conversation = context.Conversation(max_tokens=10000)
        self.target = "10.0.0.5"
        self.resumen_recuperado = resumen_recuperado


class NoticeTimingTests(unittest.TestCase):
    def test_notice_shown_once_when_model_becomes_available_mid_session(self):
        assistant = _FakeAssistant(_TogglingClient())
        stdin = io.StringIO("\n\n0\n")
        stdout = io.StringIO()
        rc = menu.run(stdin, stdout, lambda: assistant)
        self.assertEqual(rc, 0)
        out = stdout.getvalue()
        self.assertEqual(out.count("He recuperado el resumen"), 1)

    def test_no_notice_when_model_never_becomes_available(self):
        client = _AlwaysDownClient()
        assistant = _FakeAssistant(client)
        stdin = io.StringIO("0\n")
        stdout = io.StringIO()
        menu.run(stdin, stdout, lambda: assistant)
        self.assertNotIn("He recuperado el resumen", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
