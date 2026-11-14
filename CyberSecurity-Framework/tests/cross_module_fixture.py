"""Persistent consent-only synthetic fixture. Never a host test entrypoint.

No cleanup/finalizer, executable search fallback or copy of operator data.
New consent core sources must be added explicitly WHEN their tasks create them.
"""
import json
import os
from pathlib import Path
import subprocess
from tempfile import mkdtemp

SOURCE_FILES = (
    '06_PostExploitation/cleanup/logs_cleaner.sh',
    '03_Scanners/web_scanners/burpsuite/burp_launcher.sh',
    '03_Scanners/run_all_scanners.sh', '06_PostExploitation/run_all_post.sh',
    '00_Config/lib/scanners_menu.bash', '00_Config/lib/postexploitation_menu.bash',
    '00_Config/lib/scanner_runtime.bash', '00_Config/lib/scans.bash',
    '00_Config/lib/session.bash', '00_Config/lib/postexploitation_runtime.bash',
    '00_Config/lib/web_target.bash', '00_Config/lib/prompt.bash',
    '00_Config/lib/params.bash',
)

# Exact existing child sources. Only the coordinator test replaces these copied
# leaves with recorder transports; no leaf's real business executes in that test.
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


class CrossModuleFixture:
    def __init__(self, group: str):
        import __main__ as controller
        import automation_case_scope as scope
        from automation_suite_selection import case_disposable_allowed
        from cross_module_selection import group_cases
        names = group_cases(group)
        if (getattr(controller, '__file__', None) !=
                '/source/CyberSecurity-Framework/tests/automation_sandbox_inside.py' or
                getattr(controller, 'validated_selection', lambda: None)() != group or
                not scope.in_worker() or scope._SCOPE[3] not in names or
                not case_disposable_allowed(scope._SCOPE[3])):
            raise ValueError('Cross fixture requires validated current granted worker')
        from automation_sandbox_prepare import copy_regular, source_names
        self.repo = Path(mkdtemp(prefix='cross-consent-', dir=scope.fixture_parent()))
        self.framework = self.repo / 'CyberSecurity-Framework'
        self.home = self.repo / 'home'
        self.bin = self.repo / 'bin'
        self.output = self.repo / 'harness-output'
        self.log = self.repo / 'processes.jsonl'
        for directory in (self.framework, self.home, self.bin, self.output):
            directory.mkdir(mode=0o700)
        manifest = source_names()
        for relative in SOURCE_FILES + COORDINATOR_LEAVES:
            name = 'CyberSecurity-Framework/' + relative
            if name not in manifest:
                raise ValueError('Missing exact cross fixture source: ' + name)
            destination = self.framework / relative
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            copy_regular(Path('/source') / name, destination, 0o500)
        config = self.framework / '00_Config'
        (config / 'scope.yaml').write_text('targets: {domains: [example.test]}\n')
        (config / 'targets.txt').write_text('example.test|443|https|Synthetic|B\n')
        (self.home / '.bash_history').write_text('synthetic-history-sentinel\n')
        self.env = {
            'PATH': str(self.bin) + ':/usr/bin:/bin', 'HOME': str(self.home),
            'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1',
            'SESSION_FILE': str(config / '.session'),
            'SESSION_SCOPE_FILE': str(config / 'scope.yaml'),
            'SESSION_TARGETS_FILE': str(config / 'targets.txt'),
        }
        self._invocations = 0
        for name in ('curl', 'ss', 'sudo', 'burpsuite', 'sleep', 'last',
                     'xdotool', 'xwininfo', 'whoami', 'record-dispatch'):
            self.stub(name)

    def stub(self, name):
        if '/' in name or name in ('', '.', '..'):
            raise ValueError('Expected fixed double basename')
        path = self.bin / name
        # Exclusive new file, never replace/adopt a backend from the environment.
        with path.open('x') as stream:
            stream.write('#!/usr/bin/python3\nimport json, sys\nfrom pathlib import Path\n'
                         'name = ' + repr(name) + '\n'
                         'log = Path(' + repr(str(self.log)) + ')\n'
                         'prior = log.read_text().splitlines() if log.exists() else []\n'
                         'with log.open("a") as out:\n'
                         '    out.write(json.dumps([name, *sys.argv[1:]]) + "\\n")\n'
                         'if name == "sudo":\n'
                         '    print("synthetic sudo refusal", file=sys.stderr)\n'
                         '    sys.exit(1)\n'
                         'if name == "ss":\n'
                         '    print("State Recv-Q Send-Q Local Address:Port Peer Address:Port")\n'
                         '    if any(json.loads(row)[0] == "ss" for row in prior):\n'
                         '        print("LISTEN 0 128 127.0.0.1:8080 0.0.0.0:*")\n'
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
            rows.append((str(path.relative_to(self.repo)), info.st_mode,
                         path.read_bytes() if path.is_file() and not path.is_symlink() else None))
        return rows

    def _run(self, argv, stdin):
        self._invocations += 1
        result = subprocess.run(argv, input=stdin, text=True, capture_output=True,
                                cwd=self.framework, env=self.env, timeout=15, close_fds=True)
        root = self.output / str(self._invocations)
        root.mkdir(mode=0o700)
        (root / 'stdout').write_text(result.stdout)
        (root / 'stderr').write_text(result.stderr)
        (root / 'result.json').write_text(json.dumps({'argv': argv, 'returncode': result.returncode}))
        return result

    def run_leaf(self, relative, args=(), stdin=''):
        if relative not in SOURCE_FILES + COORDINATOR_LEAVES or not relative.endswith('.sh'):
            raise ValueError('Not a fixed consent leaf/coordinator')
        return self._run(['/bin/bash', '--noprofile', '--norc',
                          str(self.framework / relative), *args], stdin)

    def run_menu(self, name, stdin):
        if name not in ('scanners_menu', 'postexploitation_menu'):
            raise ValueError('Unknown fixed consent menu')
        driver = self.output / ('menu-' + str(self._invocations) + '.sh')
        with driver.open('x') as stream:
            stream.write('source "$1/00_Config/lib/params.bash"\n'
                         'source "$1/00_Config/lib/prompt.bash"\n'
                         'source "$1/00_Config/lib/session.bash"\n'
                         'source "$1/00_Config/lib/' + name + '.bash"\n'
                         'clear_screen() { :; }; pause() { :; }\n'
                         'ask_confirm() { printf "%s\\n" "$1"; local answer; IFS= read -r answer || return 1; '
                         '[[ "$answer" == s || "$answer" == si ]]; }\n'
                         'execute_script() { record-dispatch "$@"; }\n'
                         'run_module_scripts() { record-dispatch "$@"; }\n' + name + '\n')
        return self._run(['/bin/bash', '--noprofile', '--norc', str(driver), str(self.framework)], stdin)

    def record_coordinator_leaves(self):
        # Retain copied source bytes before creating in-place inert transports.
        for relative in COORDINATOR_LEAVES + (
                '06_PostExploitation/cleanup/logs_cleaner.sh',
                '03_Scanners/web_scanners/burpsuite/burp_launcher.sh'):
            path = self.framework / relative
            path.rename(path.with_name(path.name + '.retained-source'))
            with path.open('x') as stream:
                stream.write('#!/bin/bash\nrecord-dispatch ' + repr(relative) + ' "$@"\n')
        self.stub('nmap')
