"""Persistent per-selection synthetic fixture. Never a host test entrypoint.

No cleanup/finalizer, executable search fallback or copy of operator data.
New helper sources must be added explicitly WHEN their tasks create them.
"""
import json
import os
from pathlib import Path
import subprocess
from tempfile import mkdtemp

SOURCE_FILES = (
    'cyber_framework.sh',  # Existing RO allowlist entry; extract only ask_confirm.
    '00_Config/lib/consent/__init__.py',
    '00_Config/lib/consent/burp.py',
    '00_Config/lib/consent/burp_cli.py',
    '00_Config/lib/consent/files.py',
    '00_Config/lib/consent/cleanup.py',
    '00_Config/lib/consent/cleanup_cli.py',
    '06_PostExploitation/cleanup/logs_cleaner.sh',
    '03_Scanners/web_scanners/burpsuite/burp_launcher.sh',
    '03_Scanners/run_all_scanners.sh', '06_PostExploitation/run_all_post.sh',
    '00_Config/lib/scanners_menu.bash', '00_Config/lib/postexploitation_menu.bash',
    '00_Config/lib/scanner_runtime.bash', '00_Config/lib/scans.bash',
    '00_Config/lib/session.bash', '00_Config/lib/postexploitation_runtime.bash',
    '00_Config/lib/web_target.bash', '00_Config/lib/prompt.bash',
    '00_Config/lib/params.bash',
)

WEB_SOURCE_FILES = (
    '00_Config/lib/http_request.bash', '00_Config/lib/scans.bash',
    '00_Config/lib/session.bash',
    '05_Exploitation/web/web_login_bruteforce.sh',
    '05_Exploitation/web/rate_limit_probe.sh',
)
PURE_SOURCE_FILES = ('00_Config/lib/http_request.bash',)


def _new_text(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        stream.write(value)


# Exact synthetic dispatch destinations, NOT copied/read child sources. Genuine
# originals stay in the staged RO /source manifest; coordinators use new inerts.
COORDINATOR_LEAVES = (
    '03_Scanners/network_scanners/nmap/nmap_smart.sh',
    '03_Scanners/network_scanners/masscan/masscan_scan.sh',
    '03_Scanners/web_scanners/nikto/nikto_scan.sh',
    '03_Scanners/web_scanners/nuclei/nuclei_scan.sh',
    '06_PostExploitation/privilege_escalation/linpeas.sh',
    '06_PostExploitation/privilege_escalation/suid_check.sh',
    '06_PostExploitation/privilege_escalation/capabilities_check.sh',
    '06_PostExploitation/privilege_escalation/cron_check.sh',
    '06_PostExploitation/credential_access/linux_creds.sh',
    '06_PostExploitation/credential_access/history_parser.sh',
    '06_PostExploitation/loot/file_collector.sh',
    '06_PostExploitation/loot/screenshot_collector.sh',
)


def _private_json(path, value):
    """Exclusive new evidence/input, never overwrite an invocation artifact."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, sort_keys=True)
        stream.write('\n')


class CrossModuleFixture:
    def __init__(self, group: str):
        import __main__ as controller
        import automation_case_scope as scope
        from automation_suite_selection import case_disposable_allowed
        from cross_module_selection import group_cases, group_grants, WEB_CASES
        names = group_cases(group)
        if (getattr(controller, '__file__', None) !=
                '/source/CyberSecurity-Framework/tests/automation_sandbox_inside.py' or
                getattr(controller, 'validated_selection', lambda: None)() != group or
                not scope.in_worker() or scope._SCOPE[3] not in names or
                scope._SCOPE[4] != (scope._SCOPE[3] in group_grants(group)) or
                case_disposable_allowed(scope._SCOPE[3]) != scope._SCOPE[4]):
            raise ValueError('Cross fixture requires validated current per-case worker')
        from automation_sandbox_prepare import copy_regular, source_names
        self.group = group
        pure = group == '--cross-web' and scope._SCOPE[3] in WEB_CASES[:2]
        self.source_files = SOURCE_FILES
        if group == '--cross-web':
            self.source_files = PURE_SOURCE_FILES if pure else WEB_SOURCE_FILES
        self.repo = Path(mkdtemp(prefix=group[2:] + '-', dir=scope.fixture_parent()))
        self.framework = self.repo / 'CyberSecurity-Framework'
        self.home = self.repo / 'home'
        self.bin = self.repo / 'bin'
        self.output = self.repo / 'harness-output'
        self.log = self.repo / 'processes.jsonl'
        for directory in (self.framework, self.home, self.bin, self.output):
            directory.mkdir(mode=0o700)
        manifest = source_names()
        for relative in self.source_files:
            name = 'CyberSecurity-Framework/' + relative
            if name not in manifest:
                raise ValueError('Missing exact cross fixture source: ' + name)
            destination = self.framework / relative
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            copy_regular(Path('/source') / name, destination, 0o500)
        config = self.framework / '00_Config'
        _new_text(config / 'scope.yaml', 'targets: {domains: [example.test]}\n')
        _new_text(config / 'targets.txt', 'example.test|443|https|Synthetic|B\n')
        _new_text(self.home / '.bash_history', 'synthetic-history-sentinel\n')
        self.env = {
            'PATH': str(self.bin) + ':/usr/bin:/bin', 'HOME': str(self.home),
            # The exact sandbox omits locale archives: C is always available.
            # Python UTF-8 mode retains Unicode without setlocale warnings.
            'LANG': 'C', 'LC_ALL': 'C', 'PYTHONUTF8': '1',
            'PYTHONDONTWRITEBYTECODE': '1',
            'SESSION_FILE': str(config / '.session'),
            'SESSION_SCOPE_FILE': str(config / 'scope.yaml'),
            'SESSION_TARGETS_FILE': str(config / 'targets.txt'),
        }
        self._invocations = 0
        self._ss_configurations = 0
        self._curl_configurations = 0
        if group == '--cross-web':
            if not pure:
                temporary = self.repo / 'tmp'
                temporary.mkdir(mode=0o700)
                self.env['TMPDIR'] = str(temporary)  # mktemp must stay in this pinned case
                name = 'CyberSecurity-Framework/tests/cross_web_curl_double.py'
                if name not in manifest:
                    raise ValueError('Missing mandatory web curl double')
                copy_regular(Path('/source') / name, self.bin / 'curl', 0o500)
                self.configure_curl([{'code': '401', 'time': '0.010', 'headers': {}, 'body': 'denied'}])
            return
        for name in ('curl', 'ss', 'sudo', 'burpsuite', 'sleep', 'last',
                     'xdotool', 'xwininfo', 'whoami', 'record-dispatch'):
            self.stub(name)
        self.configure_ss((
            'State Recv-Q Send-Q Local Address:Port Peer Address:Port\n',
            'State Recv-Q Send-Q Local Address:Port Peer Address:Port\n'
            'LISTEN 0 128 127.0.0.1:8080 0.0.0.0:*\n'))

    def configure_curl(self, responses):
        if self.group != '--cross-web' or not responses:
            raise ValueError('Web transport requires nonempty programmed responses')
        self._curl_configurations += 1
        path = self.output / ('curl-program-' + str(self._curl_configurations) + '.json')
        _private_json(path, responses)
        self.env['CROSS_CURL_PROGRAM'] = str(path)
        self.env['CROSS_CURL_RECORDS'] = str(self.output / 'curl-records.jsonl')

    def curl_records(self):
        path = self.output / 'curl-records.jsonl'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def configure_ss(self, responses):
        """Transport data only; repeat the last response, never open a socket."""
        if not responses or not all(isinstance(value, str) for value in responses):
            raise ValueError('Expected nonempty literal ss response strings')
        self._ss_configurations += 1
        path = self.output / ('ss-transport-' + str(self._ss_configurations) + '.json')
        _private_json(path, list(responses))
        self.env['CROSS_SS_RESPONSES'] = str(path)

    def stub(self, name):
        if '/' in name or name in ('', '.', '..'):
            raise ValueError('Expected fixed double basename')
        path = self.bin / name
        # Exclusive new file, never replace/adopt a backend from the environment.
        with path.open('x') as stream:
            stream.write('#!/usr/bin/python3\nimport json, os, sys\nfrom pathlib import Path\n'
                         'name = ' + repr(name) + '\n'
                         'log = Path(' + repr(str(self.log)) + ')\n'
                         'prior = log.read_text().splitlines() if log.exists() else []\n'
                         'with log.open("a") as out:\n'
                         '    out.write(json.dumps([name, *sys.argv[1:]]) + "\\n")\n'
                         'if name == "sudo":\n'
                         '    print("synthetic sudo refusal", file=sys.stderr)\n'
                         '    sys.exit(1)\n'
                         'if name == "ss":\n'
                         '    responses = json.loads(Path(os.environ["CROSS_SS_RESPONSES"]).read_text())\n'
                         '    index = sum(json.loads(row)[0] == "ss" for row in prior)\n'
                         '    print(responses[min(index, len(responses) - 1)], end="")\n'
                         'if name == "curl": print("200", end="")\n'
                         'if name == "whoami": print("synthetic-user")\n'
                         'if name in ("xdotool", "xwininfo"): sys.exit(1)\n'
                         'if name == "last": print("synthetic login snapshot")\n'
                         'if name == "nmap": print("80/tcp open http")\n')
        path.chmod(0o700)
        return path

    def set_session(self, target):
        # New synthetic session only; never session_set_target/scope registration.
        with (self.framework / '00_Config/.session').open('x') as stream:
            stream.write(target + '\n')

    def records(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def snapshot(self):
        """Synthetic bytes/metadata only, excluding this fixture's own receipts."""
        rows = []
        for path in sorted(self.repo.rglob('*')):
            if path == self.log or self.output == path or self.output in path.parents:
                continue
            info = path.lstat()
            rows.append((str(path.relative_to(self.repo)), info.st_mode, info.st_dev, info.st_ino,
                         info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink,
                         path.read_bytes() if path.is_file() and not path.is_symlink() else None))
        return rows

    def _run(self, argv, stdin):
        self._invocations += 1
        root = self.output / str(self._invocations)
        root.mkdir(mode=0o700)  # EEXIST blocks before launch; retain prior artifacts.
        _private_json(root / 'argv.json', list(argv))
        _private_json(root / 'started.json', {'state': 'STARTING', 'timeout': 15})
        receipt = {'argv': list(argv), 'state': 'INTERRUPTED', 'returncode': None}
        try:
            # Direct retained streams preserve partial bytes even if run raises.
            with (root / 'stdout').open('xb') as stdout, (root / 'stderr').open('xb') as stderr:
                os.fchmod(stdout.fileno(), 0o600)
                os.fchmod(stderr.fileno(), 0o600)
                result = subprocess.run(argv, input=stdin, text=True, stdout=stdout, stderr=stderr,
                                        cwd=self.framework, env=self.env, timeout=15, close_fds=True)
            receipt.update(state='DONE', returncode=result.returncode)
        except subprocess.TimeoutExpired:
            receipt.update(state='TIMEOUT', timeout=15, error_type='TimeoutExpired')
            raise
        except OSError as exc:
            receipt.update(state='LAUNCH_ERROR', error_type=type(exc).__name__, errno=exc.errno)
            raise
        except BaseException as exc:
            receipt.update(error_type=type(exc).__name__)
            raise
        finally:
            _private_json(root / 'result.json', receipt)
        return subprocess.CompletedProcess(
            result.args, result.returncode,
            (root / 'stdout').read_text(encoding='utf-8', errors='replace'),
            (root / 'stderr').read_text(encoding='utf-8', errors='replace'))

    def run_leaf(self, relative, args=(), stdin=''):
        if (relative == 'cyber_framework.sh' or relative not in self.source_files or
                not relative.endswith('.sh')):
            raise ValueError('Not a fixed current-selection leaf/coordinator')
        return self._run(['/bin/bash', '--noprofile', '--norc',
                          str(self.framework / relative), *args], stdin)

    def run_menu(self, name, stdin):
        if name not in ('scanners_menu', 'postexploitation_menu'):
            raise ValueError('Unknown fixed consent menu')
        # Consume the real manager consent classifier as source, without sourcing
        # its initialization/main. Display policy is also real; only clear/pause
        # and execution/list transports are doubled.
        source = (self.framework / 'cyber_framework.sh').read_text()
        policies = ''
        for function in ('ask_confirm', 'script_arguments_summary'):
            header = '\n' + function + '() {\n'
            if source.count(header) != 1:
                raise ValueError('Manager policy source shape changed')
            body, closing, _ = source.split(header, 1)[1].partition('\n}')
            if not closing:
                raise ValueError('Manager policy closing brace missing')
            policies += function + '() {\n' + body + '\n}\n'
        driver = self.output / ('menu-' + str(self._invocations) + '.sh')
        with driver.open('x') as stream:
            stream.write('source "$1/00_Config/lib/params.bash"\n'
                         'source "$1/00_Config/lib/prompt.bash"\n'
                         'source "$1/00_Config/lib/session.bash"\n'
                         'source "$1/00_Config/lib/' + name + '.bash"\n'
                         'clear_screen() { :; }; pause() { :; }\n'
                         + policies +
                         'execute_script() { local -a original=("$@"); local script_path="$1"; shift 2; '
                         '[[ "${1:-}" != --prepared ]] || shift; '
                         'script_arguments_summary "$script_path" "$@"; record-dispatch "${original[@]}"; }\n'
                         'run_module_scripts() { record-dispatch "$@"; }\n' + name + '\n')
        return self._run(['/bin/bash', '--noprofile', '--norc', str(driver), str(self.framework)], stdin)

    def record_coordinator_leaves(self):
        # Only these two real leaves were copied for their business tests.
        # Preserve their scratch copies before using recorders for exclusions.
        for relative in (
                '06_PostExploitation/cleanup/logs_cleaner.sh',
                '03_Scanners/web_scanners/burpsuite/burp_launcher.sh'):
            path = self.framework / relative
            path.rename(path.with_name(path.name + '.retained-source'))
        for relative in COORDINATOR_LEAVES + (
                '06_PostExploitation/cleanup/logs_cleaner.sh',
                '03_Scanners/web_scanners/burpsuite/burp_launcher.sh'):
            path = self.framework / relative
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with path.open('x') as stream:
                stream.write('#!/bin/bash\nrecord-dispatch ' + repr(relative) + ' "$@"\n')
        self.stub('nmap')
