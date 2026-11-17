"""Pruebas del punto de entrada ai_assistant.py: menú guiado y subcomandos.

El script real se invoca por subproceso con un entorno aislado (HOME, datos,
configuración y árbol del framework sintéticos) y un Ollama falso en loopback.
Nunca se toca la configuración real ni se ejecuta ninguna herramienta.
"""
import hashlib
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

FW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FW / "00_Config" / "lib"))

SCRIPT = FW / "09_Automation" / "ai" / "ai_assistant.py"
FAKE = FW / "tests" / "fixtures" / "ollama_fake.py"

TARGET = "127.0.0.1"
SLUG = "127.0.0.1"
MENU_MARK = "Asistente del framework"
FINDING_TITLE = "Puerto 22 abierto (SSH)"


class FakeOllama:
    """Lanza tests/fixtures/ollama_fake.py en 127.0.0.1 y expone su URL."""

    def __init__(self, mode="ok", model="fake:1b"):
        self.tmp = tempfile.TemporaryDirectory()
        ready = os.path.join(self.tmp.name, "ready")
        env = dict(os.environ, FAKE_OLLAMA_MODE=mode, FAKE_OLLAMA_MODEL=model,
                   PYTHONDONTWRITEBYTECODE="1")
        self.proc = subprocess.Popen([sys.executable, str(FAKE), "0", ready], env=env)
        for _ in range(200):
            if os.path.exists(ready) and " " in Path(ready).read_text().strip():
                break
            time.sleep(0.02)
        self.port = int(Path(ready).read_text().split()[1])
        self.url = "http://127.0.0.1:%d" % self.port

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.tmp.cleanup()


class CliBase(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.TemporaryDirectory()
        root = Path(self.base.name)
        self.home = root / "home"
        self.home.mkdir()
        self.data = root / "data"            # fuera del árbol del framework
        self.repo = root / "repo"
        self.fw = self.repo / "CyberSecurity-Framework"
        self.config_path = root / "ai_config.yaml"
        self.session_file = root / "session"
        self.session_file.write_text(TARGET + "\n", encoding="utf-8")
        self._build_tree()
        self.addCleanup(self.base.cleanup)

    def _build_tree(self):
        (self.fw / "00_Config").mkdir(parents=True)
        (self.fw / "00_Config" / "scope.yaml").write_text(
            "proyecto: prueba\nalcance:\n  - 127.0.0.1\n", encoding="utf-8")
        (self.fw / "00_Config" / "targets.txt").write_text(
            "127.0.0.1|22|tcp|Objetivo de prueba|A\n", encoding="utf-8")
        (self.fw / "README.md").write_text(
            "# Framework de pruebas\n\n"
            "Nmap es una herramienta de escaneo de puertos de red. "
            "Sirve para descubrir servicios abiertos en un objetivo.\n\n"
            "## Enumeracion\n\nLa enumeracion identifica servicios como SSH en el "
            "puerto 22 y permite entender la superficie expuesta.\n",
            encoding="utf-8")
        gen = self.fw / "11_Reports" / "generated" / SLUG
        gen.mkdir(parents=True)
        (gen / "findings.json").write_text(
            '{"objetivo": "127.0.0.1", "hallazgos": ['
            '{"severidad": "alta", "titulo": "%s", "activo": "127.0.0.1:22",'
            ' "descripcion": "El servicio SSH esta expuesto.",'
            ' "recomendacion": "Restringe el acceso por firewall."}]}' % FINDING_TITLE,
            encoding="utf-8")
        (gen / "informe_tecnico.md").write_text(
            "# Informe tecnico\n\n## Resumen\n\nSe encontro SSH abierto.\n",
            encoding="utf-8")
        scans = self.repo / "scans" / "nmap"
        scans.mkdir(parents=True)
        (scans / ("nmap_%s.txt" % SLUG)).write_text(
            "PORT   STATE SERVICE\n22/tcp open  ssh\n", encoding="utf-8")
        docs = self.repo / "docs"
        docs.mkdir()
        (docs / "guia.md").write_text(
            "# Guia\n\nEl informe se genera con la tecla R del menu.\n",
            encoding="utf-8")

    def _write_config(self, url, model="fake:1b"):
        self.config_path.write_text(
            "modelo: %s\nendpoint: %s\npermitir_endpoint_remoto: false\n"
            "contexto_max_tokens: 2048\nturnos_literales: 4\ntop_k: 4\n"
            "incluir_credenciales: false\n" % (model, url), encoding="utf-8")

    def _env(self):
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(self.home),
            "AI_DATA_DIR": str(self.data),
            "SESSION_FILE": str(self.session_file),
            "AI_CONFIG": str(self.config_path),
            "AI_FRAMEWORK_ROOT": str(self.fw),
            "PYTHONDONTWRITEBYTECODE": "1",
            "LC_ALL": "C.UTF-8",
            "LANG": "C.UTF-8",
        }
        for n in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                  "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
            env.pop(n, None)
        return env

    def run_cli(self, args, stdin_text="", server="ok", model="fake:1b", timeout=40):
        srv = None
        if server is not None:
            srv = FakeOllama(mode=server, model=model)
            self.addCleanup(srv.stop)
            self._write_config(srv.url, model)
        else:
            self._write_config("http://127.0.0.1:1", model)
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), *args], input=stdin_text,
            env=self._env(), capture_output=True, text=True, timeout=timeout)
        return proc


class MenuTests(CliBase):
    def test_eof_exits_zero_without_side_effects(self):
        p = self.run_cli([], stdin_text="", server="ok")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(MENU_MARK, p.stdout)

    def test_zero_returns(self):
        p = self.run_cli([], stdin_text="0\n", server="ok")
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_number_runs_option(self):
        # Sin modelo: la opcion 1 usa la ruta determinista y muestra el hallazgo.
        p = self.run_cli(["1"] and [], stdin_text="1\n0\n", server="no_model")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(FINDING_TITLE, p.stdout)

    def test_free_text_is_a_question(self):
        p = self.run_cli([], stdin_text="que es nmap\n0\n", server="no_model")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertRegex(p.stdout, r"\.md:\d+-\d+")

    def test_whitespace_input_ignored(self):
        p = self.run_cli([], stdin_text="   \n0\n", server="no_model")
        self.assertEqual(p.returncode, 0, p.stderr)
        # El menu se dibuja dos veces (inicial y tras ignorar el espacio), sin
        # producir ninguna respuesta entre medias.
        self.assertEqual(p.stdout.count(MENU_MARK), 2)

    def test_nueva_resets_and_keeps_index_files(self):
        p = self.run_cli([], stdin_text="que es nmap\n5\nn\n0\n", server="ok")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue((self.data / "index.json").is_file())
        summaries = self.data / "summaries"
        self.assertFalse(summaries.is_dir() and any(summaries.iterdir()))

    def test_save_summary_creates_file_600_labelled_by_target(self):
        p = self.run_cli([], stdin_text="que es nmap\n5\ns\n0\n", server="ok")
        self.assertEqual(p.returncode, 0, p.stderr)
        f = self.data / "summaries" / ("%s.md" % SLUG)
        self.assertTrue(f.is_file(), p.stdout)
        self.assertEqual(oct(f.stat().st_mode & 0o777), "0o600")
        self.assertIn(TARGET, f.read_text(encoding="utf-8"))

    def test_no_ollama_prints_what_is_missing_and_still_searches(self):
        p = self.run_cli([], stdin_text="que es nmap\n0\n", server="no_model")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("ollama pull", p.stdout)
        self.assertRegex(p.stdout, r"\.md:\d+-\d+")

    def test_ctrl_c_during_answer_returns_to_menu(self):
        import threading
        srv = FakeOllama(mode="slow")
        self.addCleanup(srv.stop)
        self._write_config(srv.url)
        proc = subprocess.Popen(
            [sys.executable, str(SCRIPT)], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=self._env())
        # Un hilo vacía stdout de forma continua (leer con read(1) y luego
        # communicate() pierde datos ya almacenados en el búfer de Python).
        buf = []
        sig_sent = threading.Event()

        def drain():
            while True:
                ch = proc.stdout.read(1)
                if ch == "":
                    break
                buf.append(ch)
                if not sig_sent.is_set() and "Hola" in "".join(buf):
                    sig_sent.set()
                    proc.send_signal(signal.SIGINT)

        reader = threading.Thread(target=drain)
        reader.start()
        proc.stdin.write("que es nmap\n")
        proc.stdin.flush()
        self.assertTrue(sig_sent.wait(20), "el modelo no empezó a responder")
        time.sleep(0.3)                      # deja que termine/cancele la respuesta
        try:
            proc.stdin.write("0\n")
            proc.stdin.close()
        except (BrokenPipeError, ValueError):
            pass
        proc.wait(timeout=20)
        reader.join(timeout=5)
        full = "".join(buf)
        self.assertEqual(proc.returncode, 0)
        # El proceso sobrevive al SIGINT y el menú vuelve a aparecer.
        self.assertGreaterEqual(full.count(MENU_MARK), 2)


class SubcommandTests(CliBase):
    def test_estado_and_modelo_subcommands_exit_zero(self):
        p = self.run_cli(["estado"], server="ok")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(TARGET, p.stdout)
        q = self.run_cli(["modelo"], server="ok")
        self.assertEqual(q.returncode, 0, q.stderr)
        self.assertIn("ollama pull", q.stdout)

    def test_unknown_subcommand_exits_2_with_usage(self):
        p = self.run_cli(["frobnicate"], server=None)
        self.assertEqual(p.returncode, 2)
        self.assertIn("Uso", p.stderr)

    def test_default_in_tree_data_dir_not_self_indexed(self):
        # Sin AI_DATA_DIR el directorio de datos cae dentro del framework
        # (09_Automation/ai/data). No debe indexarse a sí mismo: el caché vale
        # entre lanzamientos y el índice/resúmenes nunca se citan como fuente.
        env = self._env()
        env.pop("AI_DATA_DIR", None)
        self._write_config("http://127.0.0.1:1")      # sin modelo: ruta determinista
        data = self.fw / "09_Automation" / "ai" / "data"

        def launch():
            return subprocess.run(
                [sys.executable, str(SCRIPT)], input="que es nmap\n0\n",
                env=env, capture_output=True, text=True, timeout=40)

        p1 = launch()
        self.assertEqual(p1.returncode, 0, p1.stderr)
        self.assertTrue((data / "index.json").is_file())
        self.assertIn("Preparando el índice", p1.stdout)
        # Un resumen guardado tampoco invalida ni contamina el índice.
        (data / "summaries").mkdir(exist_ok=True)
        (data / "summaries" / ("%s.md" % SLUG)).write_text(
            "# Resumen\nnmap puerto abierto\n", encoding="utf-8")
        p2 = launch()
        self.assertEqual(p2.returncode, 0, p2.stderr)
        self.assertNotIn("Preparando el índice", p2.stdout)   # caché reutilizado
        both = p1.stdout + p2.stdout
        self.assertNotIn("09_Automation/ai/data", both)
        self.assertNotIn("index.json", both)
        self.assertNotIn("summaries", both)
        # Y sigue respondiendo con fragmentos citados (ruta:líneas).
        self.assertRegex(both, r"\.md:\d+-\d+")

    def test_never_writes_outside_data_dir(self):
        def snapshot():
            acc = {}
            for base in (self.fw, self.repo / "scans", self.repo / "docs"):
                for p in sorted(base.rglob("*")):
                    if p.is_file():
                        acc[str(p.relative_to(self.repo))] = hashlib.sha256(
                            p.read_bytes()).hexdigest()
            return acc

        before = snapshot()
        p = self.run_cli(["analizar"], server=None)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(snapshot(), before)
        self.assertFalse((self.fw / "09_Automation" / "ai" / "data").exists())


if __name__ == "__main__":
    unittest.main()
