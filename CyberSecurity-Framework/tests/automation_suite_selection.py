"""Closed, inside-only selection. NOT RUN; no launcher or arbitrary command API."""
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
UNIT_MODULES = ('test_automation_sandbox_prepare', 'test_automation_sandbox_policy',
                'test_automation_sandbox_boundary')
RACES = tuple('test_automation_runner.RunnerTests.' + name for name in (
    'test_ancestor_swap_after_spawn_reaps', 'test_timeout_and_signals',
    'test_term_is_not_inherited_blocked', 'test_signal_during_final_state',
    'test_spawn_publication_race', 'test_storage_error_after_spawn_reaps',
    'test_grandchild_ignoring_term_and_leader_exit',
    'test_handlers_restored_and_foreign_process_untouched'))


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def preservation_inventory():
    data = json.loads((HERE / 'automation_preservation_cases.json').read_text())
    if set(data) != {'version', 'blocked', 'authorization'} or data['version'] != 2:
        raise ValueError('Invalid preservation inventory')
    blocked = data['blocked']
    permission = data['authorization']
    if (not isinstance(blocked, dict) or len(blocked) != 25 or
            not isinstance(permission, dict) or
            set(permission) != {'grant', 'scope', 'case_ids', 'required_observer'} or
            permission['grant'] != 'explicit-user-new-synthetic-disposables-only' or
            permission['scope'] != 'registered-current-case-fixture-only' or
            permission['required_observer'] != 'inherited-before-images-and-own-fixture-boundary' or
            not isinstance(permission['case_ids'], list) or
            len(permission['case_ids']) != 25 or
            any(not isinstance(name, str) for name in permission['case_ids']) or
            set(permission['case_ids']) != set(blocked)):
        raise ValueError('Invalid closed synthetic-disposable authorization')
    if not all(isinstance(reason, str) and reason.startswith('BLOCKED-preservation:')
               for reason in blocked.values()):
        raise ValueError('Invalid preservation history')
    return data


def classify(cases):
    data = preservation_inventory()
    history = data['blocked']
    ids = [case.id() for case in cases]
    if len(ids) != len(set(ids)) or not set(history) <= set(ids):
        raise ValueError('Duplicate/missing test IDs; review preservation inventory')
    # Permission is real, but a local Python hook is not an inherited observer.
    # Do NOT enable these cases until current case roots can be pinned and both
    # before-images and own-fixture access enforced for descendants too. No
    # registry/coverage is fabricated from argv, environment or a path prefix.
    blocked = {name: ('BLOCKED-preservation: NEEDS_CONTEXT-descendant-boundary; '
                      'user exception granted, inherited before-images and '
                      'own-fixture enforcement unavailable. History: ' + reason)
               for name, reason in history.items()}
    return [case for case in cases if case.id() not in blocked], blocked


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.records.append({'id': test.id(), 'state': 'PASS'})

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.records.append({'id': test.id(), 'state': 'SKIP', 'reason': reason})

    def addError(self, test, error):
        super().addError(test, error)
        self.records.append({'id': test.id(), 'state': 'ERROR'})

    def addFailure(self, test, error):
        super().addFailure(test, error)
        self.records.append({'id': test.id(), 'state': 'FAIL'})


def _run(cases):
    result = unittest.TextTestRunner(verbosity=2, resultclass=RecordedResult).run(
        unittest.TestSuite(cases))
    return {'tests_run': result.testsRun, 'successful': result.wasSuccessful(),
            'records': result.records, 'failures': len(result.failures),
            'errors': len(result.errors), 'skipped': len(result.skipped)}


def run_selection(selector, write_receipt):
    # Recheck genuine controller state; a CLI/env flag is never authority.
    import __main__ as controller
    if (getattr(controller, '__file__', None) != str(HERE / 'automation_sandbox_inside.py') or
            not getattr(controller, 'validated_diagnostic_context', lambda: False)()):
        raise ValueError('BLOCKED: only validated fixed inside controller may discover')
    if selector not in ('--suite', '--races'):
        raise ValueError('Unknown closed selection')
    from automation_sandbox_prepare import source_names
    modules = sorted(Path(name).stem for name in source_names()
                     if name.startswith('CyberSecurity-Framework/tests/test_automation_')
                     and name.endswith('.py'))
    if not set(UNIT_MODULES) <= set(modules):
        raise ValueError('Missing sandbox unit source')
    # Load Task3 units first; no legacy fixture imported until after their run.
    units = unittest.defaultTestLoader.loadTestsFromNames(UNIT_MODULES)
    unit_result = _run(list(flatten(units)))
    write_receipt('/evidence/sandbox-units.json', unit_result)
    if not unit_result['successful']:
        return 'FAIL', 1, 'Sandbox unit contracts failed; legacy selection not started'
    from automation_test_guard import install
    install('/source')  # redundant controller diagnostics, never OS authority
    legacy = [name for name in modules if name not in UNIT_MODULES]
    cases = list(flatten(unittest.defaultTestLoader.loadTestsFromNames(legacy)))
    allowed, blocked = classify(cases)
    for name, reason in blocked.items():
        print(name + ': ' + reason, file=sys.stderr)
    write_receipt('/evidence/preservation.json', {
        'version': 2, 'state': 'NEEDS_CONTEXT' if blocked else 'PASS',
        'authorization': preservation_inventory()['authorization'],
        'blocked': blocked, 'eligible': [case.id() for case in allowed]})
    if selector == '--suite':
        result = _run(allowed)
        write_receipt('/evidence/suite.json', result)
        if not result['successful']:
            return 'FAIL', 1, 'Eligible subset failed; see named preservation blocks too'
    else:
        available = {case.id(): case for case in cases}
        if not set(RACES) <= set(available):
            raise ValueError('Race source contract changed')
        # Fresh instances for each repetition. Blocked names are NEVER run or
        # passed; each requested repetition still has its own explicit receipt.
        for repetition in range(1, 21):
            selected = [name for name in RACES if name not in blocked]
            result = (_run(list(flatten(unittest.defaultTestLoader.loadTestsFromNames(selected))))
                      if selected else {'tests_run': 0, 'successful': None, 'records': [],
                                        'state': 'NEEDS_CONTEXT'})
            result['blocked'] = {name: blocked[name] for name in RACES if name in blocked}
            result['repetition'] = repetition
            write_receipt('/evidence/races-' + str(repetition).zfill(2) + '.json', result)
            if result['successful'] is False:
                return 'FAIL', 1, 'Eligible race repetition failed'
    if blocked:
        return ('BLOCKED', 2, 'NEEDS_CONTEXT-descendant-boundary: user exception '
                'granted; inherited case-scoped observation/confinement unavailable')
    return 'PASS', 0, 'All selected tests passed'
