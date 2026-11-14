"""Written for static review only: execution BLOCKED in Task9 round1.

Publication structure/source contracts, not global semantic or OS containment
proof. Do not run even these tests until the controller explicitly authorizes.
"""
import ast
from pathlib import Path
import re
import unittest

from automation_menu_inventory import function_body, literal_options, special_options

FW = Path(__file__).resolve().parents[1]
ROOT = FW.parent


def source_paths():
    # Exact reviewed inventory; no .git or generated/recovered tools required.
    from automation_sandbox_prepare import source_names
    return [ROOT / name for name in source_names()
            if name.startswith('CyberSecurity-Framework/')]


def explained_row(doc, key):
    row = next((line for line in doc.splitlines() if line.startswith('| `' + key + '` |')), '')
    cells = [c.strip() for c in row.split('|')[1:-1]]
    # Short tool names (SSH, FTP) and "0 o EOF" are legitimate inputs;
    # require substantive effects/limits rather than padding their labels.
    if len(cells) != 4 or len(cells[1]) < 3 or len(cells[2]) < 5 or len(cells[3]) < 20:
        raise AssertionError('Falta finalidad/entrada/efectos/límites: ' + key)
    return row


def leaf_inventory(doc, paths):
    leaves = set()
    for source in paths:
        relative = source.relative_to(FW)
        if ('lib' not in relative.parts and 'tests' not in relative.parts and
                re.match(r'^\d\d_', relative.parts[0]) and
                source.suffix in ('.sh', '.py', '.ps1')):
            leaves.add(relative.as_posix())
    rows = set(re.findall(r'^\| `([0-9][0-9]_[^`]+\.(?:sh|py|ps1))` \|', doc, re.M))
    if leaves != rows:
        raise AssertionError('Source/doc leaf inventory changed: ' + repr(sorted(leaves ^ rows)))
    return leaves


def special_sources():
    # Source text only; this does not import/execute any framework entry.
    return {name: (FW / relative).read_text() for name, relative in (
        ('manager', 'cyber_framework.sh'),
        ('wizard', '00_Config/scripts/config_wizard.sh'),
        ('keys', '00_Config/scripts/api_keys.py'),
        ('evidence', '10_Evidence/evidence_manager.sh'))}


def explain_special_options(doc, sources):
    for key in special_options(sources):
        explained_row(doc, key)


def numeric_case_options(text, variable, occurrence=0):
    """Read fixed Bash case arms (including aliases/inline arms), never run UI."""
    headers = list(re.finditer(r'\bcase\s+["\']?\$' + variable + r'["\']?\s+in\b', text))
    start = headers[occurrence].end()
    depth, cursor, parts = 1, start, []
    for token in re.finditer(r'\bcase\s+["\']?\$\w+["\']?\s+in\b|\besac\b', text[start:]):
        begin, end = start + token.start(), start + token.end()
        if token[0] == 'esac':
            depth -= 1
            if depth == 0:
                parts.append(text[cursor:begin])
                break
            if depth == 1:
                cursor = end
        else:
            if depth == 1:
                parts.append(text[cursor:begin])
            depth += 1
    else:
        raise AssertionError('Unterminated static case: ' + variable)
    body = '\n'.join(parts)
    choices = set()
    for arm in re.findall(r'(?:^|;;)\s*([0-9][0-9|]*)\)', body, re.M):
        choices.update(arm.split('|'))
    # Mixed numeric/cancel arms, such as 0|'!', still have a numeric option.
    choices.update(re.findall(r'^\s*(\d+)\|[\'"!]', body, re.M))
    if not choices:
        raise AssertionError('No numeric options found: ' + variable)
    return choices


class Contracts(unittest.TestCase):
    def test_no_legacy_success_or_shell_execution(self):
        for source in source_paths():
            if source.suffix != '.py' or not ('09_Automation' in source.parts or
                                             source.parent.name == 'automation'):
                continue
            tree = ast.parse(source.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    self.assertFalse(isinstance(node.func, ast.Attribute) and
                                     isinstance(node.func.value, ast.Name) and
                                     node.func.value.id == 'os' and node.func.attr == 'system')
                    self.assertFalse(any(k.arg == 'shell' and isinstance(k.value, ast.Constant)
                                         and k.value.value is True for k in node.keywords))
        self.assertNotIn('Auditoría completa con Bash', (FW / '09_Automation/README.md').read_text())

    def test_complete_capability_matrix(self):
        use = (FW / '09_Automation/USE.md').read_text()
        cli = ast.parse((FW / '00_Config/lib/automation/cli.py').read_text())
        originals = next(ast.literal_eval(n.value) for n in cli.body
                         if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'ORIGINAL' for t in n.targets))
        for entry in originals:
            row = next((line for line in use.splitlines() if '`' + entry + '`' in line), '')
            self.assertGreaterEqual(len(row.split('|')), 6, entry)
            self.assertTrue(all(len(c.strip()) > 8 for c in row.split('|')[2:5]), entry)

    def test_docs_use_real_flags(self):
        use = (FW / '09_Automation/USE.md').read_text()
        for text in ('post', '--authorized-target', '--allow', 'sqlmap_replay', 'EXDEV', 'renameat2', 'históricos'):
            self.assertIn(text, use)
        cli = (FW / '00_Config/lib/automation/cli.py').read_text()
        accepted = set(re.findall(r"'(--[a-z-]+)'", cli))
        accepted.update('--' + k.replace('_', '-') for k in ('target url domain ports port request_file scheme account wordlist max_attempts max_seconds product database table report_input menu list check execute include_config').split())
        for flag in re.findall(r'--[a-z][a-z-]+', use):
            self.assertIn(flag, accepted, flag)

    def test_suite_isolated(self):
        """Fixed launcher only; dynamic boundary evidence belongs to probes."""
        runner = (FW / 'tests/run_automation.sh').read_text()
        self.assertIn('/usr/bin/python3 -I -B', runner)
        self.assertIn('automation_sandbox_launch.py', runner)
        self.assertNotIn('discover', runner)
        self.assertNotIn('eval ', runner)
        fixture = (FW / 'tests/automation_fixture.py').read_text()
        self.assertNotIn('copytree', fixture)
        self.assertNotIn('scope.yaml', fixture.split('class AutomationFixture:')[0])

    def test_every_leaf_explained(self):
        doc = (ROOT / 'docs/MENU-OPCIONES.md').read_text()
        leaf_inventory(doc, source_paths())
        for source in source_paths():
            relative = source.relative_to(FW)
            if ('lib' in relative.parts or 'tests' in relative.parts or
                    not re.match(r'^\d\d_', relative.parts[0]) or
                    source.suffix not in ('.sh', '.py', '.ps1')):
                continue
            explained_row(doc, relative.as_posix())

    def test_source_manifest_leaf_deletion_and_addition_mutations(self):
        doc = (ROOT / 'docs/MENU-OPCIONES.md').read_text()
        paths = source_paths()
        known = FW / '09_Automation/bash/auto_recon.sh'
        self.assertIn(known, paths)
        for changed in ([p for p in paths if p != known],
                        paths + [FW / '09_Automation/bash/future_action.sh']):
            with self.assertRaises(AssertionError):
                leaf_inventory(doc, changed)

    def test_every_menu_option_explained(self):
        doc = (ROOT / 'docs/MENU-OPCIONES.md').read_text()
        explain_special_options(doc, special_sources())
        # Main case arms of each source function; nested case arms are checked
        # separately below. New numeric options cannot silently lose coverage.
        for module, name in (('03', 'scanners'), ('04', 'enumeration'),
                             ('05', 'exploitation'), ('06', 'postexploitation'),
                             ('07', 'wireless'), ('08', 'forensics')):
            text = (FW / f'00_Config/lib/{name}_menu.bash').read_text()
            function = text.split(f'{name}_menu() {{', 1)[1]
            for option in numeric_case_options(function, 'choice'):
                explained_row(doc, f'{module}.{option}')
        for name, variable, occurrence, prefix in (
                ('scanners', 'web_choice', 0, '03.web'),
                ('enumeration', 'sub', 0, '04.bd'),
                ('enumeration', 'sub', 1, '04.web'),
                ('postexploitation', 'sub', 0, '06.persist'),
                ('postexploitation', 'sub', 1, '06.lateral'),
                ('forensics', 'action', 0, '08.disk'),
                ('forensics', 'action', 1, '08.local'),
                ('forensics', 'choice', 0, '08.requirements')):
            text = (FW / f'00_Config/lib/{name}_menu.bash').read_text()
            for option in numeric_case_options(text, variable, occurrence):
                explained_row(doc, prefix + '.' + option)
        cli = ast.parse((FW / '00_Config/lib/automation/cli.py').read_text())
        menu = next(n for n in cli.body if isinstance(n, ast.FunctionDef) and n.name == 'menu')
        labels = [n.args[0].value for n in ast.walk(menu) if isinstance(n, ast.Call)
                  and isinstance(n.func, ast.Name) and n.func.id == 'print'
                  and n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str)]
        for label in labels:
            match = re.match(r'^(\d+) ', label)
            if match:
                explained_row(doc, '09.' + match[1])
        labs = (FW / '13_Labs/main.sh').read_text()
        for name, prefix in [('main_menu', '13'), ('htb_menu', '13.htb'),
                             ('thm_menu', '13.thm'), ('ad_menu', '13.ad'),
                             ('web_menu', '13.web'), ('cloud_menu', '13.cloud'),
                             ('tools_menu', '13.tools'), ('vpn_menu', '13.vpn'),
                             ('delete_menu', '13.delete')]:
            body = labs.split(name + '() {', 1)[1].split('\n}', 1)[0]
            for option in re.findall(r'echo -e "\$\{GREEN\}(\d+)\.', body):
                # Nested shell choices are a distinct namespace.
                if name == 'tools_menu' and option in ('1', '2', '3', '4', '5'):
                    explained_row(doc, '13.shell.' + option)
                explained_row(doc, prefix + '.' + option)
        for prefix, options in [('03.web', range(3)), ('04.bd', range(4)),
                                ('04.web', range(3)), ('06.persist', range(3)),
                                ('06.lateral', range(4)), ('08.disk', (1, 2)),
                                ('08.local', range(1, 7)), ('08.requirements', (1, 2))]:
            for option in options:
                explained_row(doc, prefix + '.' + str(option))
        for option in literal_options((FW / '00_Config/lib/forensics_menu.bash').read_text(), 'choice', 1):
            explained_row(doc, '08.timeline.' + option)
        for option in literal_options(function_body(labs, 'tools_menu'), 'shell_opt'):
            explained_row(doc, '13.shell.' + option)
        # Mutation checks: a header/name without explanation must fail.
        for broken in ('| `09.3` | | | |', '| `09.3` | Quick | target | preview |'):
            with self.assertRaises(AssertionError):
                explained_row(broken, '09.3')

    def test_special_namespace_row_deletion_mutations(self):
        """Structure only: deletion must fail, wording still needs source review."""
        doc = (ROOT / 'docs/MENU-OPCIONES.md').read_text()
        sources = special_sources()
        required = special_options(sources)
        # Explicitly assert the previously untested source/contract namespaces.
        for key in ('R.abrir', 'T.numero', 'T.0', 'lista.numero', 'lista.0', 'lista.R'):
            self.assertIn(key, required)
        for prefix in ('00.keys.', '10.', 'K.herramienta.'):
            self.assertTrue(any(key.startswith(prefix) for key in required), prefix)
        for key in sorted(required):
            with self.subTest(deleted=key):
                row = explained_row(doc, key)
                with self.assertRaises(AssertionError):
                    explain_special_options(doc.replace(row, '', 1), sources)

    def test_new_special_source_options_require_rows(self):
        """Mutate source STRINGS; never run a menu, parser, or backend."""
        doc = (ROOT / 'docs/MENU-OPCIONES.md').read_text()
        sources = special_sources()
        mutations = (
            ('manager', '99) full_workflow ;;', '14) module_config ;;\n            99) full_workflow ;;', '14'),
            ('manager', '3) tipo="ambos" ;;', '3) tipo="ambos" ;;\n        4) tipo="extra" ;;', 'R.4'),
            ('manager', '4) keys_helper sincronizar ;;', '4) keys_helper sincronizar ;;\n        6) keys_helper estado ;;', 'K.6'),
            ('manager', 'if [[ "$sel" =~', 'if [[ "$sel" == "X" ]]; then :; fi\n        if [[ "$sel" =~', 'T.X'),
            ('manager', 'if [[ "$choice" == "0" ]]; then', 'if [[ "$choice" == "X" ]]; then :; fi\n        if [[ "$choice" == "0" ]]; then', 'lista.X'),
            ('wizard', '1|2) WZ_MODE=', '3) WZ_MODE=3 ;;\n            1|2) WZ_MODE=', '00.wizard.3'),
            ('keys', 'args = parser.parse_args()', 'subparsers.add_parser("future")\n    args = parser.parse_args()', '00.keys.future'),
            ('evidence', '--verify)  verify_evidence ;;', '--future) list_evidence ;;\n    --verify)  verify_evidence ;;', '10.future'),
        )
        for source, old, new, key in mutations:
            with self.subTest(added=key):
                self.assertIn(old, sources[source], 'Source shape changed; review mutation contract')
                changed = dict(sources, **{source: sources[source].replace(old, new, 1)})
                self.assertIn(key, special_options(changed))
                with self.assertRaises(AssertionError):
                    explain_special_options(doc, changed)
        changed = dict(sources, wizard=sources['wizard'].replace('¿Otro objetivo?', '¿Otra acción?'))
        with self.assertRaises(AssertionError):
            special_options(changed)

    def test_k_sync_semantic_source_contract(self):
        # Deliberately narrow semantic check for I2, not a claim that row length
        # validates the meaning of every other menu/tool explanation.
        manager = special_sources()['manager']
        self.assertIn('4) keys_helper sincronizar ;;', manager)
        row = explained_row((ROOT / 'docs/MENU-OPCIONES.md').read_text(), 'K.4')
        self.assertIn('sin confirmación adicional', row)
        self.assertIn('directamente', row)

    def test_catalog_actions_have_effects_and_conditions(self):
        source = ast.parse((FW / '00_Config/lib/automation/catalog.py').read_text())
        use = (FW / '09_Automation/USE.md').read_text()
        for node in ast.walk(source):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == '_action':
                action = ast.literal_eval(node.args[0])
                line = next((s for s in use.splitlines() if s.startswith('| ' + action + ' |')), '')
                cells = [c.strip() for c in line.split('|')[1:-1]]
                self.assertEqual(len(cells), 4, action)
                self.assertTrue(all(len(c) >= 9 for c in cells[1:]), action)

    def test_controller_guard_is_additional_only_and_blocks_unvalidated_spawn(self):
        from automation_test_guard import check_event
        from unittest.mock import patch
        root = Path('/synthetic-not-a-host-checkout')
        for path in (root / 'CyberSecurity-Framework/00_Config/scope.yaml',
                     root / 'scans/fake.txt'):
            with self.assertRaises(PermissionError):
                check_event(root, 'open', (str(path), 'r', 0))
        # All are inert strings passed directly to a guard function: no Popen.
        for executable in ('synthetic_backend', '/tmp/opencode/automation-unregistered/stub',
                           'bash', 'python3', 'pwsh', 'git'):
            with self.subTest(executable=executable), patch.dict('sys.modules', {'__main__': None}), self.assertRaises(PermissionError):
                check_event(root, 'subprocess.Popen', (executable, [executable], None, None))


if __name__ == '__main__':
    unittest.main()
