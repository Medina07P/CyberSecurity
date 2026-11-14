"""Synthetic-only automation workspace; never copy configuration or evidence."""
from pathlib import Path
import json
import shutil
import sys
from tempfile import mkdtemp


def preserve(path):
    """Archive a test-owned object intact; NEVER replace product cleanup."""
    path = Path(path)
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    archive = Path(mkdtemp(prefix='.preserved-', dir=path.parent))
    destination = archive / path.name
    path.rename(destination)
    after = destination.lstat()
    def identity(info):
        return [info.st_dev, info.st_ino, info.st_mode, info.st_size]
    if identity(before) != identity(after):
        raise RuntimeError('Preservation identity changed; retain archive and stop')
    with (archive / 'preservation.json').open('x', encoding='utf-8') as stream:
        json.dump({'original': str(path), 'retained': str(destination),
                   'before': identity(before), 'after': identity(after)}, stream)
        stream.write('\n')
    return destination


SOURCE_FILES = tuple(
    '00_Config/lib/automation/' + name + '.py'
    for name in ('__init__', 'model', 'validation', 'catalog', 'planner', 'workflows',
                 'storage', 'runner', 'adapters', 'reporting')
) + ('09_Automation/workflows/quick_scan.yaml',
     '09_Automation/workflows/full_audit.yaml',
     '00_Config/lib/dangerous.txt',
     '03_Scanners/network_scanners/nmap/nmap_smart.sh',
     '03_Scanners/web_scanners/nikto/nikto_scan.sh',
     '04_Enumeration/ssh/enum_ssh.sh',
     '04_Enumeration/smb/enum_smb_advanced.sh',
     '01_OSINT/scripts/osint_harvester.sh',
     '00_Config/scripts/validate_config.sh',
     '05_Exploitation/web/sqlmap_request.sh')

SOURCE_FILES += tuple('00_Config/lib/' + name for name in (
    'scanner_runtime.bash', 'scans.bash', 'enumeration_services.bash',
    'enumeration_runtime.bash', 'enumeration_evidence.py', 'http_request.bash',
    'session.bash')) + tuple('00_Config/lib/osint/' + name + '.py' for name in (
    '__init__', 'cli', 'credentials', 'discovery', 'dns', 'model', 'runtime', 'sources'
)) + ('11_Reports/report_engine.py',)

SOURCE_FILES += ('09_Automation/python/report_generator.py',
                 '00_Config/lib/postexploitation_evidence.py') + tuple(
    '11_Reports/lib/' + name + '.py' for name in (
        '__init__', 'attribution', 'catalog', 'engine', 'model', 'render', 'sources',
        'parsers/__init__', 'parsers/exploitation', 'parsers/ffuf', 'parsers/headers',
        'parsers/host_sources', 'parsers/http_inject', 'parsers/nikto', 'parsers/nmap',
        'parsers/nuclei', 'parsers/postexploitation', 'parsers/rate_limit',
        'parsers/sqli_findings', 'parsers/sqlmap'))

SOURCE_FILES += ('tests/fixtures/automation/powershell_contract.ps1',)

SOURCE_FILES += ('00_Config/lib/automation/cli.py',
                 '00_Config/lib/automation_menu.bash', 'cyber_framework.sh',
                 '09_Automation/python/orchestrator.py',
                 '09_Automation/python/auto_audit.py',
                 '09_Automation/bash/auto_recon.sh',
                 '09_Automation/bash/auto_enum.sh',
                 '09_Automation/bash/auto_exploit.sh',
                 '09_Automation/run_all_automation.sh',
                 '09_Automation/powershell/auto_enum.ps1',
                 '09_Automation/docker/Dockerfile',
                 '09_Automation/docker/docker-compose.yml',
                 '09_Automation/README.md')
SOURCE_FILES += ('09_Automation/USE.md',)


class AutomationFixture:
    def __init__(self):
        self.repo = Path(mkdtemp(prefix='automation-', dir='/work/fixtures'))
        self.framework = self.repo / 'CyberSecurity-Framework'
        self.bin = self.repo / 'bin'
        self.home = self.repo / 'home'
        self.log = self.repo / 'processes.jsonl'
        self.bin.mkdir()
        self.home.mkdir()
        source = Path(__file__).resolve().parents[1]
        for relative in SOURCE_FILES:
            origin = source / relative
            if origin.is_file():
                destination = self.framework / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(origin, destination)
        config = self.framework / '00_Config'
        config.mkdir(parents=True, exist_ok=True)
        (config / 'scope.yaml').write_text('targets: {domains: [example.test]}\n')
        (config / 'targets.txt').write_text('192.0.2.1|22|tcp|Synthetic|B\n')

    def stub(self, name, rc=0):
        if not name or '/' in name or name in ('.', '..'):
            raise ValueError('Expected a basename')
        executable = self.bin / name
        preserve(executable)
        executable.write_text(
            '#!' + sys.executable + '\nimport json, sys\n'
            + 'with open(' + repr(str(self.log)) + ', "a") as stream:\n'
            + '    stream.write(json.dumps(sys.argv) + "\\n")\n'
            + 'sys.exit(' + repr(int(rc)) + ')\n'
        )
        executable.chmod(0o700)
        return executable

    def records(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def close(self):
        # No live handles owned; persistent trees have no finalizer or cleanup.
        pass
