"""Pruebas del cliente Ollama contra el servidor falso (solo loopback)."""
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

FW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FW / "00_Config" / "lib"))

from ai.ollama_client import OllamaClient, OllamaError  # noqa: E402

FAKE = FW / "tests" / "fixtures" / "ollama_fake.py"


class FakeServer:
    def __init__(self, mode="ok", extra_env=None):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.tmp.name, "chat.json")
        ready = os.path.join(self.tmp.name, "ready")
        env = dict(os.environ, FAKE_OLLAMA_MODE=mode, FAKE_OLLAMA_LOG=self.log,
                   PYTHONDONTWRITEBYTECODE="1", **(extra_env or {}))
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
    def serve(self, mode="ok", extra_env=None):
        s = FakeServer(mode, extra_env)
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

    def test_default_timeout_allows_slow_cpu_only_hardware(self):
        # Medido el 2026-11-18 contra qwen2.5:3b real en CPU sin GPU: un prompt
        # realista con 4 fragmentos tardó ~96.7s (~3 tok/s en generación). 120s
        # se queda corto para una respuesta algo más larga; 300s da margen.
        s = self.serve()
        c = OllamaClient(s.url, "fake:1b")
        self.assertEqual(c.timeout, 300)

    def test_remote_endpoint_rejected_without_flag(self):
        with self.assertRaises(OllamaError):
            OllamaClient("http://192.0.2.1:11434", "m")
        with self.assertRaises(OllamaError):
            OllamaClient("http://192.0.2.1:11434", "m", allow_remote="yes")
        OllamaClient("http://192.0.2.1:11434", "m", allow_remote=True)

    def test_loopback_literal_rules_no_dns(self):
        import socket
        called = []
        orig = socket.gethostbyname
        socket.gethostbyname = lambda h: called.append(h) or "127.0.0.1"
        try:
            for bad in ("http://localhost.evil.com:11434", "http://127.0.0.1.nip.io:11434",
                        "http://localhost@evil.example/"):
                with self.assertRaises(OllamaError, msg=bad):
                    OllamaClient(bad, "m")
            for good in ("http://LOCALHOST:11434", "http://[::1]:11434",
                         "http://127.0.0.2:11434"):
                OllamaClient(good, "m")
        finally:
            socket.gethostbyname = orig
        self.assertEqual(called, [], "no debe resolver nombres por DNS")

    def test_malformed_endpoint_is_ollama_error(self):
        with self.assertRaises(OllamaError):
            OllamaClient("http://[::1", "m")

    def test_userinfo_not_echoed(self):
        with self.assertRaises(OllamaError) as cm:
            OllamaClient("http://user:s3cretpw@192.0.2.1:11434", "m")
        self.assertNotIn("s3cretpw", str(cm.exception))
        self.assertNotIn("s3cretpw", cm.exception.user_message)

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

    def test_list_models_returns_sorted_names(self):
        s = self.serve(extra_env={"FAKE_OLLAMA_MODELS": "zeta:1b,alpha:3b"})
        c = OllamaClient(s.url, "alpha:3b")
        self.assertEqual(c.list_models(), ["alpha:3b", "zeta:1b"])

    def test_list_models_empty_when_no_models(self):
        s = self.serve("no_model")
        c = OllamaClient(s.url, "fake:1b")
        self.assertEqual(c.list_models(), [])

    def test_list_models_empty_without_server(self):
        c = OllamaClient("http://127.0.0.1:1", "fake:1b")
        self.assertEqual(c.list_models(), [])

    def test_truncated_stream_raises_ollama_error(self):
        s = self.serve("truncated")
        with self.assertRaises(OllamaError) as cm:
            OllamaClient(s.url, "fake:1b").chat([{"role": "user", "content": "x"}])
        self.assertNotIn("Traceback", cm.exception.user_message)

    def test_malformed_message_field_raises_ollama_error(self):
        s = self.serve("bad_message")
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

    def test_env_proxies_are_ignored(self):
        names = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                 "http_proxy", "https_proxy", "all_proxy")
        old = {n: os.environ.get(n) for n in names}
        os.environ.pop("NO_PROXY", None)
        os.environ.pop("no_proxy", None)
        try:
            s = self.serve()
            for n in names:
                os.environ[n] = "http://127.0.0.1:1"
            c = OllamaClient(s.url, "fake:1b")
            self.assertTrue(c.is_up())
            self.assertEqual(c.chat([{"role": "user", "content": "x"}]), "Hola, mundo")
        finally:
            for n, v in old.items():
                if v is None:
                    os.environ.pop(n, None)
                else:
                    os.environ[n] = v

    def test_redirect_is_not_followed(self):
        hits = []

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                hits.append(self.path)
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_POST = do_GET

        other = ThreadingHTTPServer(("127.0.0.1", 0), H)
        t = threading.Thread(target=other.serve_forever, daemon=True)
        t.start()
        self.addCleanup(other.server_close)
        self.addCleanup(other.shutdown)
        target = "http://127.0.0.1:%d/api/chat" % other.server_address[1]
        s = self.serve("redirect", {"FAKE_OLLAMA_REDIRECT_TO": target})
        with self.assertRaises(OllamaError) as cm:
            OllamaClient(s.url, "fake:1b").chat([{"role": "user", "content": "secreto"}])
        self.assertNotIn("secreto", cm.exception.user_message)
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
