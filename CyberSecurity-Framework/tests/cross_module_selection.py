"""Closed per-selection maps; no discovery, grant union or environment input."""
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

WEB_CASES = tuple('test_cross_web.WebTests.' + name for name in (
    'test_pair_composes_locations_and_literals',
    'test_pair_rejects_ambiguity',
    'test_login_req_transmits_each_candidate',
    'test_login_has_no_preconsent_transport',
    'test_rate_has_no_scheme_probe',
    'test_rate_403_and_existing_verdicts',
    'test_web_inputs_and_previous_runs_are_preserved'))
WEB_GRANTS = WEB_CASES[2:]


def _inventory():
    data = load_json(Path(__file__).with_name('cross_module_cases.json'), {
        'version', 'grant', 'scope', 'required_observer', 'disposable_states', 'groups'}, version=2)
    expected = {
        'version': 2,
        'grant': 'explicit-user-new-synthetic-disposables-only',
        'scope': 'registered-current-case-fixture-only',
        'required_observer': 'landlock-abi3-current-case-worker',
        'disposable_states': 'new-synthetic-intermediate-states',
        'groups': {
            '--cross-consent': {'case_ids': list(CONSENT_CASES), 'grant_ids': list(CONSENT_CASES)},
            '--cross-web': {'case_ids': list(WEB_CASES), 'grant_ids': list(WEB_GRANTS)},
        }}
    if data != expected:
        raise ValueError('Cross inventory differs from exact reviewed per-group maps')
    return data['groups']


def group_cases(selector: str) -> tuple[str, ...]:
    if selector not in ('--cross-consent', '--cross-web'):
        raise ValueError('Unknown closed cross selection')
    return tuple(_inventory()[selector]['case_ids'])


def group_grants(selector: str) -> frozenset[str]:
    group_cases(selector)  # validate selector and full closed schema first
    return frozenset(_inventory()[selector]['grant_ids'])


def validate_cases(selector, cases):
    expected = group_cases(selector)
    ids = tuple(case.id() for case in cases)
    if not ids or len(ids) != len(set(ids)) or set(ids) != set(expected):
        raise ValueError('Cross load failed: missing/changed/duplicate test ID; no case forked')
    if not group_grants(selector) <= frozenset(ids):
        raise ValueError('Cross grants outside exact loaded cases')
