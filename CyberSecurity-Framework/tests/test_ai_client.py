"""Pruebas del cliente Ollama contra el servidor falso (solo loopback)."""
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

FW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FW / "00_Config" / "lib"))

from ai.ollama_client import OllamaClient, OllamaError  # noqa: E402

FAKE = FW / "tests" / "fixtures" / "ollama_fake.py"


class FakeServer:
    def __init__(self, mode="ok"):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.tmp.name, "chat.json")
        ready = os.path.join(self.tmp.name, "ready")
        env = dict(os.environ, FAKE_OLLAMA_MODE=mode, FAKE_OLLAMA_LOG=self.log,
                   PYTHONDONTWRITEBYTECODE="1")
        self.proc = subprocess.Popen([sys.executable, str(FAKE), "0", ready], env=env)
        for _ in range(100):
            if os.path.exists(ready) and " " in Path(ready).read_text().strip():
                break
            time.sleep(0.05)
        self.port = int(Path(ready).read_text().split()[1])
        self.url = "http://127.0.0.1:%d" % self.port

    def stop(self):
        self.proc.terminate()
        self.proc.wait(5)
        self.tmp.cleanup()


class ClientTests(unittest.TestCase):
    def serve(self, mode="ok"):
        s = FakeServer(mode)
        self.addCleanup(s.stop)
        return s

    def test_chat_streams_and_returns_full_text(self):
        s = self.serve()
        c = OllamaClient(s.url, "fake:1b")
        self.assertTrue(c.is_up())
        self.assertTrue(c.has_model())
        self.assertEqual(c.chat([{"role": "user", "content": "hi"}]), "Hola, mundo")

    def test_stream_callback_receives_chunks(self):
        s = self.serve()
        got = []
        OllamaClient(s.url, "fake:1b").chat([{"role": "user", "content": "x"}],
                                            stream_to=got.append)
        self.assertEqual(got, ["Hola", ", ", "mundo"])

    def test_remote_endpoint_rejected_without_flag(self):
        with self.assertRaises(OllamaError):
            OllamaClient("http://192.0.2.1:11434", "m")
        with self.assertRaises(OllamaError):
            OllamaClient("http://192.0.2.1:11434", "m", allow_remote="yes")
        OllamaClient("http://192.0.2.1:11434", "m", allow_remote=True)

    def test_connection_refused_gives_spanish_message(self):
        s = self.serve()
        url = s.url
        s.stop()
        c = OllamaClient(url, "fake:1b", timeout=3)
        self.assertFalse(c.is_up())
        with self.assertRaises(OllamaError) as cm:
            c.chat([{"role": "user", "content": "x"}])
        self.assertIn("Ollama", cm.exception.user_message)
        self.assertNotIn("Traceback", cm.exception.user_message)

    def test_missing_model_message_includes_pull_command(self):
        s = self.serve("no_model")
        c = OllamaClient(s.url, "fake:1b")
        self.assertFalse(c.has_model())
        with self.assertRaises(OllamaError) as cm:
            c.chat([{"role": "user", "content": "x"}])
        self.assertIn("ollama pull fake:1b", cm.exception.user_message)

    def test_truncated_stream_raises_ollama_error(self):
        s = self.serve("truncated")
        with self.assertRaises(OllamaError) as cm:
            OllamaClient(s.url, "fake:1b").chat([{"role": "user", "content": "x"}])
        self.assertNotIn("Traceback", cm.exception.user_message)

    def test_unload_sends_keep_alive_zero(self):
        import json
        s = self.serve()
        OllamaClient(s.url, "fake:1b").unload()
        body = json.loads(Path(s.log).read_text())
        self.assertEqual(body["keep_alive"], 0)
        self.assertEqual(body["model"], "fake:1b")


if __name__ == "__main__":
    unittest.main()
