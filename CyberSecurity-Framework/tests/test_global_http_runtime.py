"""Regresiones del ciclo de vida HTTP; ejecutar con red externa aislada."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


FW = Path(__file__).resolve().parents[1]
HELPER = FW / 'tests/fixtures/global_http_runtime.bash'


class GlobalHttpRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.fw = self.root / 'fw'
        fixtures = self.fw / 'tests/fixtures'
        fixtures.mkdir(parents=True)
        shutil.copy2(FW / 'tests/fixtures/http_target.py', fixtures)
        self.prefix = f'FW={str(self.fw)!r}; source {str(HELPER)!r} || exit 99;\n'

    def run_bash(self, body):
        result = subprocess.run(['bash', '-c', self.prefix + body],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stderr, '')

    def test_pid_visible_ready_and_reaped(self):
        self.run_bash('''
trap 'limpiar_evidencia_http; detener_servidor_http' EXIT
iniciar_servidor_http || exit 1
[[ "$HTTP_SRV_PID" =~ ^[0-9]+$ ]] || exit 2
pid=$HTTP_SRV_PID
curl --max-time 1 -fsS "http://127.0.0.1:$HPORT/safe" | grep -q 'pagina fija' || exit 3
detener_servidor_http
kill -0 "$pid" 2>/dev/null && exit 4
[[ -z "$HTTP_SRV_PID" ]] || exit 5
detener_servidor_http
''')

    def test_failed_start_reaped_and_not_success(self):
        (self.fw / 'tests/fixtures/http_target.py').write_text('raise SystemExit(1)\n')
        self.run_bash('''
iniciar_servidor_http && exit 1
[[ -z "$HTTP_SRV_PID" ]] || exit 2
detener_servidor_http
''')

    def test_other_listener_does_not_certify_failed_child_start(self):
        class OtherHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'OTHER SERVER')

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), OtherHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        fixture = self.fw / 'tests/fixtures/http_target.py'
        original = fixture.with_name('original_http_target.py')
        shutil.copy2(fixture, original)
        # El fixture REAL falla al enlazar el puerto ocupado; la pausa hace
        # determinista la ventana antes de que kill -0 observe la salida.
        fixture.write_text(f'''import runpy, sys, time
time.sleep(.2)
sys.argv[1] = {str(server.server_port)!r}
runpy.run_path({str(original)!r}, run_name='__main__')
''')
        self.run_bash(f'''
python3() {{
    if [[ "$1" == -c ]]; then printf '%s\\n' {server.server_port};
    else command python3 "$@"; fi
}}
trap 'limpiar_evidencia_http; detener_servidor_http' EXIT
iniciar_servidor_http && exit 1
[[ -z "$HTTP_SRV_PID" ]] || exit 2
[[ $(curl --noproxy '*' --max-time 1 -fsS http://127.0.0.1:{server.server_port}/safe) == 'OTHER SERVER' ]] || exit 3
''')

    def test_cleanup_exact_port_and_idempotent(self):
        self.run_bash('''
HPORT=12345
base="$FW/../scans/web/http_inject_127.0.0.1_"
mkdir -p "${base}12345/run_one" "${base}123456/run_two"
printf own > "${base}12345.txt"
printf own > "${base}12345.tsv"
printf keep > "${base}123456.txt"
printf keep > "${base}123456/run_two/001.req"
limpiar_evidencia_http || exit 1
[[ ! -e "${base}12345" && ! -e "${base}12345.txt" && ! -e "${base}12345.tsv" ]] || exit 2
[[ $(cat "${base}123456.txt") == keep && $(cat "${base}123456/run_two/001.req") == keep ]] || exit 3
limpiar_evidencia_http
HPORT='../escape'; limpiar_evidencia_http && exit 4
exit 0
''')

    def test_stop_preserves_other_server(self):
        self.run_bash('''
python3 "$FW/tests/fixtures/http_target.py" 0 >/dev/null 2>&1 &
other=$!
trap 'limpiar_evidencia_http; detener_servidor_http; kill "$other"; wait "$other" 2>/dev/null' EXIT
iniciar_servidor_http || exit 1
detener_servidor_http
kill -0 "$other" || exit 2
''')

    def test_term_preserves_status_and_reaps_server(self):
        self.check_runner_signal(signal.SIGTERM, 143)

    def test_int_preserves_status_and_reaps_server(self):
        self.check_runner_signal(signal.SIGINT, 130)

    def check_runner_signal(self, signum, expected_rc):
        ready = self.root / 'ready'
        shutil.copytree(FW / '00_Config/lib', self.fw / '00_Config/lib')
        shutil.copy2(HELPER, self.fw / 'tests/fixtures')
        # Ejecutar la inicialización real del runner, sin sus tandas lentas.
        # Así quitar sus traps rompe esta prueba, no solo un guion del test.
        header = (FW / 'tests/run_tests.sh').read_text().split('export SESSION_FILE=', 1)[0]
        script = header + f'''
iniciar_servidor_http || exit 1
printf '%s' "$HTTP_SRV_PID" > {str(ready)!r}
while :; do sleep .05; done
'''
        entrypoint = self.fw / 'tests/signal.sh'
        entrypoint.write_text(script)
        proc = subprocess.Popen(['bash', str(entrypoint)], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not ready.exists() and proc.poll() is None and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(ready.exists(), 'server did not become ready')
            pid = int(ready.read_text())
            proc.send_signal(signum)
            out, err = proc.communicate(timeout=5)
            self.assertEqual(proc.returncode, expected_rc, out + err)
            self.assertEqual(err, '')
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.communicate()


if __name__ == '__main__':
    unittest.main()
