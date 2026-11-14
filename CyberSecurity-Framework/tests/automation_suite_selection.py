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
            set(permission) != {'grant', 'scope', 'case_ids', 'required_observer', 'disposable_states'} or
            permission['grant'] != 'explicit-user-new-synthetic-disposables-only' or
            permission['scope'] != 'registered-current-case-fixture-only' or
            permission['required_observer'] != 'landlock-abi3-current-case-worker' or
            permission['disposable_states'] != 'new-synthetic-intermediate-states' or
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
    # Eligible for the verified worker gate, NOT direct inline execution. ABI/
    # rule installation failure produces a real BLOCKED result before case.run.
    return list(cases), {}


def case_disposable_allowed(case_id: str) -> bool:
    """Selection-bound local diagnostic; never OS authority or an env token."""
    import __main__ as controller
    if (getattr(controller, '__file__', None) !=
            '/source/CyberSecurity-Framework/tests/automation_sandbox_inside.py' or
            not getattr(controller, 'validated_diagnostic_context', lambda: False)()):
        return False
    selector = getattr(controller, 'validated_selection', lambda: None)()
    if selector in ('--suite', '--races'):
        return case_id in preservation_inventory()['authorization']['case_ids']
    if selector == '--cross-consent':
        from cross_module_selection import group_grants
        return case_id in group_grants(selector)
    return False


def legacy_modules(names):
    # This prefix is intentionally NOT test_*: cross modules never enter09.
    return sorted(Path(name).stem for name in names
                  if name.startswith('CyberSecurity-Framework/tests/test_automation_')
                  and name.endswith('.py'))


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


def _run_inline(cases):
    result = unittest.TextTestRunner(verbosity=2, resultclass=RecordedResult).run(
        unittest.TestSuite(cases))
    return {'tests_run': result.testsRun, 'successful': result.wasSuccessful(),
            'records': result.records, 'failures': len(result.failures),
            'errors': len(result.errors), 'skipped': len(result.skipped)}


_CASE_INDEX = 0


def _run(cases):
    """Closed workers: no test setup/run before Landlock; fresh scratch per case."""
    global _CASE_INDEX
    from automation_case_worker import WorkerBlocked, run_case
    results = []
    for case in cases:
        _CASE_INDEX += 1
        try:
            result = run_case(case, case_disposable_allowed(case.id()), _CASE_INDEX)
        except WorkerBlocked as exc:
            result = {'id': case.id(), 'state': 'BLOCKED', 'reason': str(exc)}
        results.append(result)
        if result['state'] == 'BLOCKED':
            break  # unavailable kernel is not a reason to try remaining cases
    blocked = {row['id']: row.get('reason', 'Worker prerequisite blocked')
               for row in results if row['state'] == 'BLOCKED'}
    observed_failure = any(
        row['state'] == 'FAIL' or row.get('failures', 0) > 0 or row.get('errors', 0) > 0 or
        (row['state'] == 'DONE' and row.get('successful') is not True)
        for row in results)
    return {'tests_run': sum(row.get('tests_run', 0) for row in results),
            'successful': not blocked and all(row.get('successful') is True for row in results),
            'observed_failure': observed_failure,
            'blocked': blocked, 'workers': results,
            'failures': sum(row.get('failures', row['state'] == 'FAIL') for row in results),
            'errors': sum(row.get('errors', 0) for row in results),
            'skipped': sum(row.get('skipped', 0) for row in results)}


def selection_outcome(result, label):
    """Real failures dominate later prerequisite blocks; keep both in receipts."""
    if result['observed_failure'] or result['failures'] or result['errors']:
        return 'FAIL', 1, 'Observed ' + label + ' failure; worker/block history retained'
    if result['blocked']:
        return 'BLOCKED', 2, 'Landlock ' + label + ' prerequisite blocked; no fallback'
    if not result['successful']:
        return 'FAIL', 1, 'Inconsistent ' + label + ' aggregate; history retained'
    return None


def run_selection(selector, write_receipt):
    # Recheck genuine controller state; a CLI/env flag is never authority.
    import __main__ as controller
    if (getattr(controller, '__file__', None) != str(HERE / 'automation_sandbox_inside.py') or
            not getattr(controller, 'validated_diagnostic_context', lambda: False)()):
        raise ValueError('BLOCKED: only validated fixed inside controller may discover')
    if selector not in ('--suite', '--races', '--cross-consent'):
        raise ValueError('Unknown closed selection')
    if getattr(controller, 'validated_selection', lambda: None)() != selector:
        raise ValueError('Selection differs from validated controller memory')
    from automation_sandbox_prepare import source_names
    modules = legacy_modules(source_names())
    if not set(UNIT_MODULES) <= set(modules):
        raise ValueError('Missing sandbox unit source')
    # Load Task3 units first; no legacy fixture imported until after their run.
    units = unittest.defaultTestLoader.loadTestsFromNames(UNIT_MODULES)
    unit_result = _run_inline(list(flatten(units)))
    prefix = 'cross-consent-' if selector == '--cross-consent' else ''
    write_receipt('/evidence/' + prefix + 'sandbox-units.json', unit_result)
    if not unit_result['successful']:
        return 'FAIL', 1, 'Sandbox unit contracts failed; legacy selection not started'
    from automation_test_guard import install
    install('/source')  # redundant controller diagnostics, never OS authority
    if selector == '--cross-consent':
        from cross_module_selection import group_cases, group_grants, validate_cases
        names = group_cases(selector)
        cases = list(flatten(unittest.defaultTestLoader.loadTestsFromNames(names)))
        validate_cases(selector, cases)  # includes loader _FailedTest IDs
        if any(not case_disposable_allowed(case.id()) for case in cases):
            raise ValueError('Cross grant unavailable before fork')
        write_receipt('/evidence/cross-consent-selection.json', {
            'version': 1, 'selector': selector, 'eligible': list(names),
            'grants': sorted(group_grants(selector)), 'state': 'WORKER-GATE-REQUIRED'})
        result = _run(cases)
        write_receipt('/evidence/cross-consent.json', result)
        return selection_outcome(result, 'cross-consent') or (
            'PASS', 0, 'All selected cross-consent tests passed')
    legacy = [name for name in modules if name not in UNIT_MODULES]
    cases = list(flatten(unittest.defaultTestLoader.loadTestsFromNames(legacy)))
    allowed, blocked = classify(cases)
    for name, reason in blocked.items():
        print(name + ': ' + reason, file=sys.stderr)
    write_receipt('/evidence/preservation.json', {
        'version': 2, 'state': 'WORKER-GATE-REQUIRED',
        'authorization': preservation_inventory()['authorization'],
        'blocked': blocked, 'eligible': [case.id() for case in allowed]})
    if selector == '--suite':
        result = _run(allowed)
        write_receipt('/evidence/suite.json', result)
        outcome = selection_outcome(result, 'suite')
        if outcome is not None:
            return outcome
    else:
        available = {case.id(): case for case in cases}
        if not set(RACES) <= set(available):
            raise ValueError('Race source contract changed')
        # Fresh instances for each repetition. Blocked names are NEVER run or
        # passed; each requested repetition still has its own explicit receipt.
        for repetition in range(1, 21):
            selected = list(RACES)
            result = _run(list(flatten(unittest.defaultTestLoader.loadTestsFromNames(selected))))
            result['repetition'] = repetition
            write_receipt('/evidence/races-' + str(repetition).zfill(2) + '.json', result)
            outcome = selection_outcome(result, 'race')
            if outcome is not None:
                return outcome
    return 'PASS', 0, 'All selected tests passed'
