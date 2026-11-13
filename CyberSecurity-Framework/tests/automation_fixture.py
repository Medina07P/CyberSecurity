"""Synthetic-only automation workspace; never copy configuration or evidence."""
from pathlib import Path
import json
import shutil
import sys
from tempfile import TemporaryDirectory


SOURCE_FILES = tuple(
    '00_Config/lib/automation/' + name + '.py'
    for name in ('__init__', 'model', 'validation', 'catalog', 'planner', 'workflows')
) + ('09_Automation/workflows/quick_scan.yaml',
     '09_Automation/workflows/full_audit.yaml')


class AutomationFixture:
    def __init__(self):
        self.temporary = TemporaryDirectory(prefix='automation-', dir='/tmp/opencode')
        self.repo = Path(self.temporary.name)
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
        self.temporary.cleanup()
