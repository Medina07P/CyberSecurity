"""Contrato de fichas; Bash real en un sandbox con PATH cerrado."""
import hashlib
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


FRAMEWORK = Path(__file__).resolve().parents[1]
LIBRARY = FRAMEWORK / "00_Config/lib/module_intro.bash"
MODULES = (
    "00_Config", "01_OSINT", "02_Recon", "03_Scanners", "04_Enumeration",
    "05_Exploitation", "06_PostExploitation", "07_Wireless", "08_Forensics",
    "09_Automation", "10_Evidence", "11_Reports", "12_Knowledge_Base", "13_Labs",
)


def snapshot(root):
    return {str(p.relative_to(root)): (p.stat().st_mode,
            hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None)
            for p in root.rglob("*")}


class ModuleIntroTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(LIBRARY.is_file(), "biblioteca module_intro.bash ausente")
        self.tmp = tempfile.TemporaryDirectory(prefix="module-intro-", dir="/tmp/opencode")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for directory in ("sources", "home", "config", "outside", "bin"):
            (self.root / directory).mkdir()
        self.library = self.root / "sources/module_intro.bash"
        shutil.copy2(LIBRARY, self.library)
        (self.root / "config/scope.yaml").write_text("targets: []\n")
        (self.root / "config/targets.txt").write_text("# sintético\n")
        (self.root / "home/sentinel").write_text("no modificar\n")
        self.marker = self.root / "forbidden-calls"
        # Si una regresión intenta ejecutar herramientas, nunca sale del sandbox.
        for name in ("sudo", "curl", "wget", "nmap", "python3", "cat", "dirname",
                     "mkdir", "rm", "touch", "date", "stty", "tput", "clear"):
            stub = self.root / "bin" / name
            stub.write_text('#!/bin/bash\nprintf "%s\\n" "$0" >> "$MARKER"\nexit 97\n')
            stub.chmod(0o700)
        self.env = {"PATH": str(self.root / "bin"), "HOME": str(self.root / "home"),
                    "LC_ALL": "C.UTF-8", "MARKER": str(self.marker),
                    "SESSION_SCOPE_FILE": str(self.root / "config/scope.yaml"),
                    "SESSION_TARGETS_FILE": str(self.root / "config/targets.txt")}

    def run_bash(self, body, stdin="", source=True):
        before = snapshot(self.root)
        original = LIBRARY.read_bytes()
        prefix = 'source "$1"\n' if source else ""
        result = subprocess.run(
            ["/bin/bash", "--noprofile", "--norc", "-c", prefix + body,
             "test-module-intro", str(self.library)],
            cwd=self.root / "outside", env=self.env, input=stdin,
            text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertFalse(self.marker.exists(), "comando prohibido ejecutado")
        self.assertEqual(snapshot(self.root), before, "el sandbox cambió")
        self.assertEqual(LIBRARY.read_bytes(), original)
        return result.stdout

    # Detecta ramas faltantes, campos incompletos, fichas largas o ANSI.
    def test_all_fourteen_cards_have_fields(self):
        for module in MODULES:
            with self.subTest(module=module):
                output = self.run_bash('module_intro ' + module)
                lines = [line for line in output.splitlines() if line.strip()]
                self.assertLessEqual(len(lines), 8)
                for field in ("Para qué sirve:", "Entrada:", "Incluye:", "Precauciones:"):
                    self.assertEqual(output.count(field), 1)
                    self.assertTrue(output.split(field, 1)[1].splitlines()[0].strip())
                self.assertNotIn("\x1b", output)

    # Detecta fallback visible o error para argumentos que deben ser inocuos.
    def test_unknown_and_missing_are_silent(self):
        for argument in ("", "''", "desconocido", "01_osint", "../01_OSINT", "'$(touch nope)'"):
            with self.subTest(argument=argument):
                self.assertEqual(self.run_bash('module_intro ' + argument), "")

    # Detecta salida al cargar, variables exportadas, cwd/opciones/traps modificados.
    def test_source_has_no_effects(self):
        probe = ':; declare -p; pwd; set +o; trap -p; umask; printf "ARGS:%s\\n" "$@"'
        baseline = self.run_bash(probe, source=False)
        loaded = self.run_bash(probe)
        def stable(output):
            # Metadatos internos de Bash que cambia el propio builtin source,
            # incluso al cargar un archivo vacío, no variables de la biblioteca.
            return [line for line in output.splitlines()
                    if not line.startswith(('declare -- _=', 'declare -a BASH_LINENO=',
                                            'declare -a BASH_ARGC=', 'declare -a BASH_ARGV=',
                                            'declare -- BASH_EXECUTION_STRING='))]
        self.assertEqual(stable(loaded), stable(baseline))
        self.assertEqual(self.run_bash(""), "")
        for module in MODULES:
            with self.subTest(module=module):
                called = self.run_bash('module_intro ' + module + ' >/dev/null; ' + probe)
                self.assertEqual(stable(called), stable(baseline))

    # Detecta read/pausas al cargar o mostrar cualquiera de las fichas.
    def test_stdin_is_not_consumed(self):
        for module in MODULES:
            with self.subTest(module=module):
                output = self.run_bash('module_intro ' + module +
                                      '; IFS= read -r value; printf "RESTO:%s\\n" "$value"',
                                      stdin="sentinela\n")
                self.assertTrue(output.endswith("RESTO:sentinela\n"))

    # Detecta orientación engañosa o pérdida de límites críticos del diseño.
    def test_content_limits(self):
        required = {
            "00_Config": ("objetivos", "claves", "autorización"),
            "01_OSINT": ("WHOIS", "DNS", "certificados", "correos", "perfiles",
                         "IP privada", "Metasploitable", "02", "03", "04", "contacta"),
            "02_Recon": ("reconocimiento", "autorización", "tráfico"),
            "03_Scanners": ("escaneo", "autorización", "tráfico"),
            "04_Enumeration": ("enumeración", "autorización", "tráfico"),
            "05_Exploitation": ("explotación", "explícita", "impacto"),
            "06_PostExploitation": ("posteriores", "explícita", "impacto", "no"),
            "07_Wireless": ("mantenimiento", "disponibilidad", "guía", "WiFi", "Bluetooth"),
            "08_Forensics": ("offline", "fuentes", "adquisición", "legal", "no IP"),
            "09_Automation": ("planes", "YAML", "preview", "ejecución", "permisos explícitos"),
            "10_Evidence": ("evidencia", "escanean", "tráfico", "explícitas", "presencia", "no integridad"),
            "11_Reports": ("existentes", "no", "ausencia"),
            "12_Knowledge_Base": ("guías", "locales", "no se ejecutan"),
            "13_Labs": ("laboratorios", "VPN", "sistema", "red", "no garantiza"),
        }
        forbidden = ("totalmente pasivo", "custodia legal garantizada",
                     "compatibilidad operacional garantizada", "automatización integral validada",
                     "auditoría integrada garantizada", "entorno aislado garantizado")
        for module, tokens in required.items():
            with self.subTest(module=module):
                output = self.run_bash('module_intro ' + module)
                for token in tokens:
                    self.assertIn(token, output)
                for promise in forbidden:
                    self.assertNotIn(promise, output)


FUNCTIONS = (
    "config", "osint", "recon", "scanners", "enumeration", "exploitation",
    "postexploitation", "wireless", "forensics", "automation", "evidence",
    "reports", "knowledge", "labs",
)
SPECIALIZED = dict(zip(MODULES[3:9], FUNCTIONS[3:9]))
SPECIALIZED['10_Evidence'] = 'evidence'
PURPOSES = dict(zip(MODULES, (
    "Preparar la configuración", "Recopilar información pública", "Hacer reconocimiento inicial",
    "Realizar escaneo de puertos", "Profundizar en servicios concretos", "Probar explotación controlada",
    "Acceder a acciones posteriores", "Consultar mantenimiento inalámbrico",
    "Analizar fuentes explícitas offline", "Preparar planes de automatización",
    "Gestionar y capturar evidencia", "Elaborar informes desde resultados existentes",
    "Buscar y consultar guías locales", "Organizar laboratorios",
)))


class ModuleIntroIntegrationTests(unittest.TestCase):
    """Menús reales; únicamente fuentes UI y hojas inertes en copia sintética."""

    # 09 is NOT a generic discover/redraw menu. Its real bridge/CLI, including
    # standalone zero/EOF/original-list entry, is exercised ONLY by the existing
    # authorized09 selector's CliTests.test_manager_dispatch_09, not this runner.
    def test_automation_keeps_specific_bridge_contract(self):
        manager = (FRAMEWORK / 'cyber_framework.sh').read_text()
        body = manager.split('module_automation() {', 1)[1].split('\n}', 1)[0]
        self.assertIn('automation_menu', body)
        self.assertNotIn('run_module_scripts', body)
        bridge = (FRAMEWORK / '00_Config/lib/automation_menu.bash').read_text()
        self.assertIn('module_intro 09_Automation', bridge)
        self.assertNotIn('session_target', bridge)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="module-intro-ui-", dir="/tmp/opencode")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.fw = self.root / "framework"
        self.lib = self.fw / "00_Config/lib"
        self.lib.mkdir(parents=True)
        shutil.copy2(FRAMEWORK / "cyber_framework.sh", self.fw)
        for path in (FRAMEWORK / "00_Config/lib").glob("*.bash"):
            shutil.copy2(path, self.lib)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        # Solo utilidades locales de lectura/descubrimiento, sobre nuestro fixture.
        for name in ("dirname", "find", "sort", "grep", "sed", "head", "tr", "wc"):
            (self.bin / name).symlink_to(shutil.which(name))
        self.marker = self.root / "FORBIDDEN"
        denied = '#!/bin/bash\nprintf "%s\\n" "$0" >> "$MARKER"\nexit 97\n'
        for name in ("sudo", "curl", "wget", "nmap", "masscan", "hydra", "sqlmap",
                     "tshark", "tcpdump", "iw", "openvpn", "nc", "gobuster", "ffuf",
                     "whatweb", "python3", "rm", "chmod", "apt", "systemctl"):
            self.write_executable(self.bin / name, denied)
        self.write_executable(self.bin / "clear", '#!/bin/bash\nprintf "SCREEN\\n"\n')
        self.write_executable(self.bin / "ip", '#!/bin/bash\nexit 0\n')
        self.write_executable(self.bin / "sleep", '#!/bin/bash\nexit 0\n')
        for module in MODULES:
            folder = self.fw / module
            folder.mkdir(exist_ok=True)
            self.write_executable(folder / "inert.sh", denied)
        labs = self.fw / "13_Labs"
        # Arbol completo de Labs sin copiar datos: sus fuentes son hojas denegadas,
        # salvo el punto de entrada real y su dibujo extraído, sin cambiar producto.
        for path in (FRAMEWORK / "13_Labs").rglob("*.sh"):
            destination = labs / path.relative_to(FRAMEWORK / "13_Labs")
            destination.parent.mkdir(parents=True, exist_ok=True)
            self.write_executable(destination, denied)
        shutil.copy2(FRAMEWORK / "13_Labs/main.sh", labs / "main.sh")
        drawing = (labs / "main.sh").read_text().split("# ─── Ejecutar ─", 1)[0]
        (labs / "drawing.bash").write_text(drawing)
        for directory in ("hackthebox/machines", "tryhackme/rooms", "active_directory/machines"):
            (labs / directory).mkdir(parents=True, exist_ok=True)
        for name, text in (("scope.yaml", "targets: {ips: [], domains: []}\n"),
                           ("targets.txt", "# sintético\n"), (".session", "192.168.56.101\n")):
            (self.fw / "00_Config" / name).write_text(text)
        for directory in ("home", "scans", "framework/08_Forensics/analysis",
                          "framework/10_Evidence/proofs", "framework/07_Wireless/captures"):
            folder = self.root / directory
            folder.mkdir(parents=True, exist_ok=True)
            (folder / "sentinel").write_text("SYNTHETIC ONLY\n")
        self.env = dict(PATH=str(self.bin), HOME=str(self.root / "home"),
                        MARKER=str(self.marker), LC_ALL="C.UTF-8",
                        SESSION_FILE=str(self.fw / "00_Config/.session"),
                        SESSION_SCOPE_FILE=str(self.fw / "00_Config/scope.yaml"),
                        SESSION_TARGETS_FILE=str(self.fw / "00_Config/targets.txt"))

    @staticmethod
    def write_executable(path, content):
        path.write_text(content)
        path.chmod(0o755)

    def run_ui(self, command, inputs="0\n", source=None, direct=False):
        before = snapshot(self.root)
        source = source or self.fw / "cyber_framework.sh"
        if direct:
            argv = ["/bin/bash", str(source)]
        else:
            code = '''source "$1" || exit
clear_screen() { :; }
sleep() { :; }
pause() { printf 'PAUSE\\n'; }
''' + command
            argv = ["/bin/bash", "--noprofile", "--norc", "-c", code, "intro-ui", str(source)]
        result = subprocess.run(argv, input=inputs, text=True, capture_output=True,
                                cwd=self.root, env=self.env, timeout=10)
        self.assertEqual(snapshot(self.root), before, "hash/modo/config/HOME/evidencia alterados")
        self.assertFalse(self.marker.exists(), "hoja o comando prohibido ejecutado")
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def assert_card_before_options(self, output, module, count=1):
        plain = re.sub(r"\x1b\[[0-9;]*m", "", output)
        self.assertEqual(plain.count("Para qué sirve:"), count, module)
        screens = plain.split("Para qué sirve:")
        self.assertTrue("━━━" in screens[0] or "FORENSE 08" in screens[0] or
                        "13_LABS" in screens[0], "falta cabecera antes de ficha")
        for screen in screens[1:]:
            self.assertTrue(screen.lstrip().startswith(PURPOSES[module]), module)
            first_option = re.search(r"^\s*1[.)]", screen, re.MULTILINE)
            self.assertIsNotNone(first_option, screen)
            for field in ("Entrada:", "Incluye:", "Precauciones:"):
                self.assertLess(screen.index(field), first_option.start(), module)

    # Detecta ficha fuera del dibujo, después de opciones, lecturas/pausas nuevas.
    def test_each_entry_card_precedes_options(self):
        for module, function in zip(MODULES, FUNCTIONS):
            if function == 'automation':
                continue  # Specific09 real-bridge behavior lives in the09 selector.
            with self.subTest(module=module):
                inputs = "11\n" if function == "labs" else "0\nsentinela\n"
                command = "module_" + function
                if function != "labs":
                    command += '; IFS= read -r rest; printf "RESTO:%s\\n" "$rest"'
                result = self.run_ui(command, inputs)
                output = result.stderr if function in ("forensics", "evidence") else result.stdout
                self.assert_card_before_options(output, module)
                self.assertNotIn("PAUSE", result.stdout + result.stderr)
                if function != "labs":
                    self.assertIn("RESTO:sentinela\n", result.stdout)
                if function not in ("forensics", "evidence"):
                    self.assertEqual(result.stderr, "")

    # Detecta ficha impresa una sola vez fuera del bucle; conserva pausas heredadas.
    def test_redraw_keeps_card(self):
        for module, function in zip(MODULES[:-1], FUNCTIONS[:-1]):
            if function == 'automation':
                continue  # No inherited generic R/redraw contract for09.
            with self.subTest(module=module):
                choice = "invalida" if module in SPECIALIZED else "R"
                result = self.run_ui("module_" + function, choice + "\n0\n")
                output = result.stderr if function in ("forensics", "evidence") else result.stdout
                self.assert_card_before_options(output, module, count=2)
                self.assertEqual(result.stdout.count("PAUSE"),
                                 int(function in ("exploitation", "postexploitation")))

    # Detecta contaminación de stdout y de prompts cuyo resultado se captura.
    def test_forensics_keeps_stderr(self):
        result = self.run_ui("module_forensics")
        self.assertEqual(result.stdout, "")
        self.assert_card_before_options(result.stderr, "08_Forensics")
        result = self.run_ui('forensics_read "Fuente"', "archivo sintético\n")
        self.assertEqual(result.stdout, "archivo sintético\n")
        self.assertEqual(result.stderr, "Fuente (0/! cancelar): ")

    # Detecta dependencia obligatoria del helper en bibliotecas cargadas solas.
    def test_standalone_specialized_menus_without_helper(self):
        for module, function in SPECIALIZED.items():
            with self.subTest(module=module):
                result = self.run_ui('session_target() { printf "192.168.56.101\\n"; }; ' +
                                     function + "_menu", source=self.lib / (function + "_menu.bash"))
                output = result.stderr if function in ("forensics", "evidence") else result.stdout
                self.assertIn("Volver", output)
                self.assertRegex(output, r"(?m)^\s*1[.)]")
                self.assertEqual(result.stdout if function in ("forensics", "evidence") else result.stderr, "")
                self.assertNotIn("Para qué sirve:", result.stdout + result.stderr)
                self.assertNotIn("PAUSE", result.stdout + result.stderr)
                self.assertNotIn("not found", result.stderr)

    # Detecta lectura o acción al recibir EOF; Labs conserva su bucle heredado.
    def test_eof_preserved_for_manager_menus(self):
        for module, function in zip(MODULES[:-1], FUNCTIONS[:-1]):
            if function == 'automation':
                continue  # EOF covered by CliTests.test_manager_dispatch_09.
            with self.subTest(module=module):
                result = self.run_ui("module_" + function, "")
                self.assert_card_before_options(result.stderr if function in ("forensics", "evidence")
                                                else result.stdout, module)
                self.assertNotIn("PAUSE", result.stdout + result.stderr)

    # Detecta ficha borrada al lanzar Labs, dependencia de cwd o fallback sin ficha.
    def test_labs_own_screen_and_direct_launch(self):
        result = self.run_ui("", "11\n", source=self.fw / "13_Labs/main.sh", direct=True)
        self.assertEqual(result.stderr, "")
        self.assert_card_before_options(result.stdout.split("SCREEN\n")[-1], "13_Labs")
        self.assertLess(result.stdout.index("Precauciones:"), result.stdout.index("Estado de Conexiones"))
        result = self.run_ui("main_menu; main_menu", "", source=self.fw / "13_Labs/drawing.bash")
        self.assert_card_before_options(result.stdout, "13_Labs", count=2)
        (self.fw / "13_Labs/main.sh").unlink()
        result = self.run_ui("module_labs", "R\n0\n")
        self.assert_card_before_options(result.stdout, "13_Labs", count=2)


if __name__ == "__main__":
    unittest.main()
