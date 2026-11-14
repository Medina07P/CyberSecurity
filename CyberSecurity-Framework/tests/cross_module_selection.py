"""Closed consent-only map; no discovery, universal grant or environment input."""
from pathlib import Path
from automation_sandbox_prepare import load_json

CONSENT_CASES = tuple('test_cross_consent.ConsentTests.' + name for name in (
    'test_cleanup_nonexecution_is_inert',
    'test_cleanup_requires_both_flags',
    'test_cleanup_local_plan_and_partial_failure',
    'test_cleanup_refuses_links',
    'test_burp_open_is_not_network_consent',
    'test_burp_status_has_no_side_effects',
    'test_burp_verify_explicit_url',
    'test_burp_stop_pins_owned_identity',
    'test_menu_cancel_and_coordinator_exclusions'))


def group_cases(selector: str) -> tuple[str, ...]:
    if selector != '--cross-consent':
        raise ValueError('Unknown closed cross selection')
    data = load_json(Path(__file__).with_name('cross_module_cases.json'), {
        'version', 'selector', 'grant', 'scope', 'required_observer',
        'disposable_states', 'case_ids'})
    if data != {
            'version': 1, 'selector': '--cross-consent',
            'grant': 'explicit-user-new-synthetic-disposables-only',
            'scope': 'registered-current-case-fixture-only',
            'required_observer': 'landlock-abi3-current-case-worker',
            'disposable_states': 'new-synthetic-intermediate-states',
            'case_ids': list(CONSENT_CASES)}:
        raise ValueError('Cross inventory differs from exact reviewed nine grants')
    return CONSENT_CASES


def group_grants(selector: str) -> frozenset[str]:
    return frozenset(group_cases(selector))


def validate_cases(selector, cases):
    expected = group_cases(selector)
    ids = tuple(case.id() for case in cases)
    if not ids or len(ids) != len(set(ids)) or set(ids) != set(expected):
        raise ValueError('Cross load failed: missing/changed/duplicate test ID; no case forked')
    if frozenset(ids) != group_grants(selector):
        raise ValueError('Cross grants differ from exact loaded cases')
