"""
code/evaluation/adversarial_runner.py
Test runner for the 6 synthetic adversarial cases.
Verifies prompt injection defense, non-deletion routing, and multi-lingual resilience.
"""

import os, sys, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intent_classifier import classify_request, DELETION_REQUESTED, NOT_DELETION, UNCLEAR
from validator import validate_rows

CASES_FILE = os.path.join(os.path.dirname(__file__), 'adversarial_cases.json')

def run_adversarial_tests():
    with open(CASES_FILE, 'r', encoding='utf-8') as f:
        cases = json.load(f)

    passed = 0
    total = len(cases)
    print(f"\n=== Running {total} Adversarial Evaluation Tests ===")

    mock_rows = []
    for c in cases:
        cid = c['id']
        name = c['name']
        text = c['request_text']
        exp_intent = c['expected_intent']
        exp_status = c['expected_status']

        actual_intent = classify_request(text)
        actual_status = 'INCOMPLETE' if actual_intent == DELETION_REQUESTED else 'NOT_APPLICABLE'

        intent_ok = (actual_intent == exp_intent) or (exp_intent in ('UNCLEAR', 'NOT_DELETION') and actual_intent in ('UNCLEAR', 'NOT_DELETION'))
        status_ok = actual_status == exp_status

        if intent_ok and status_ok:
            passed += 1
            print(f"  [PASS] {cid}: {name} -> {actual_intent} ({actual_status})")
        else:
            print(f"  [FAIL] {cid}: {name} -> expected {exp_intent}/{exp_status}, got {actual_intent}/{actual_status}")

        mock_rows.append({
            'case_id': cid,
            'deletion_status': actual_status,
            'steps_json': '[]' if actual_status == 'NOT_APPLICABLE' else json.dumps([
                {'step_no': 1, 'phase': 'FINDING', 'system_id': 'account_service', 'resource_id': 'account_001', 'operation': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'evidence_id': 'evidence_01'},
                {'step_no': 2, 'phase': 'REMEDIATION', 'system_id': 'account_service', 'resource_id': 'account_001', 'operation': 'DELETE_RECORD', 'state': 'ABSENT', 'evidence_id': ''},
                {'step_no': 3, 'phase': 'VERIFICATION', 'system_id': 'account_service', 'resource_id': 'account_001', 'operation': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT', 'evidence_id': ''}
            ])
        })

    # Validate output schema against invariant validator
    mock_rows.sort(key=lambda r: r['case_id'])
    val_ok = False
    try:
        val_ok = validate_rows(mock_rows, expected_count=len(mock_rows))
        print("  [PASS] Invariant validation passed on adversarial mock outputs.")
    except Exception as e:
        print(f"  [FAIL] Invariant validation failed: {e}")

    print(f"\nAdversarial Test Results: {passed}/{total} passed ({(passed/total)*100:.1f}%)")
    return passed == total and val_ok

if __name__ == '__main__':
    run_adversarial_tests()
