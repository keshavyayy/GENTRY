"""
code/validator.py
Invariant validator run before writing output.csv.
Validates all challenge constraints per AGENTS.md §6.3, §6.4, and §6.7.
"""

import json

ALLOWED_STATUSES = {'COMPLETE', 'INCOMPLETE', 'NOT_APPLICABLE'}
ALLOWED_PHASES = ['FINDING', 'REMEDIATION', 'VERIFICATION']

ALLOWED_OPERATIONS = {
    'FINDING': {
        'REPORT_REMAINING_RECORD': {'PRESENT'},
        'REPORT_EXPOSED_PII': {'PRESENT'},
        'REPORT_ACTIVE_DATA_FLOW': {'ACTIVE'},
        'REPORT_RESTORE_RISK': {'ACTIVE'},
    },
    'REMEDIATION': {
        'DISABLE_DATA_FLOW': {'DISABLED'},
        'BLOCK_RESTORE': {'BLOCKED'},
        'DELETE_RECORD': {'ABSENT'},
        'REDACT_RECORD': {'REDACTED'},
        'ANONYMIZE_RECORD': {'ANONYMIZED'},
    },
    'VERIFICATION': {
        'VERIFY_RECORD_ABSENT': {'ABSENT'},
        'VERIFY_RECORD_PRESENT': {'PRESENT'},
        'VERIFY_RECORD_REDACTED': {'REDACTED'},
        'VERIFY_RECORD_ANONYMIZED': {'ANONYMIZED'},
        'VERIFY_DATA_FLOW_DISABLED': {'DISABLED'},
        'VERIFY_RESTORE_BLOCKED': {'BLOCKED'},
    }
}

REQUIRED_STEP_FIELDS = ('step_no', 'phase', 'system_id', 'resource_id', 'operation', 'state', 'evidence_id')

class InvariantViolation(Exception):
    pass

def validate_rows(rows, expected_count=None):
    """
    Validate all rows before writing output.csv.
    Raises InvariantViolation on any rule breach.
    """
    if expected_count is not None and len(rows) != expected_count:
        raise InvariantViolation(f"Row count mismatch: expected {expected_count}, got {len(rows)}")

    # Invariant: Sorted by case_id
    case_ids = [r['case_id'] for r in rows]
    if case_ids != sorted(case_ids):
        raise InvariantViolation("Rows are not sorted by case_id.")

    seen_cases = set()

    for idx, r in enumerate(rows):
        cid = r.get('case_id')
        if not cid:
            raise InvariantViolation(f"Row {idx} missing case_id.")
        if cid in seen_cases:
            raise InvariantViolation(f"Duplicate case_id {cid} at row {idx}.")
        seen_cases.add(cid)

        status = r.get('deletion_status')
        if status not in ALLOWED_STATUSES:
            raise InvariantViolation(f"Case {cid}: invalid deletion_status '{status}'.")

        steps_str = r.get('steps_json')
        try:
            steps = json.loads(steps_str)
        except Exception as e:
            raise InvariantViolation(f"Case {cid}: invalid JSON in steps_json: {e}")

        if not isinstance(steps, list):
            raise InvariantViolation(f"Case {cid}: steps_json must be a JSON array.")

        # Invariant: NOT_APPLICABLE must have steps_json = []
        if status == 'NOT_APPLICABLE':
            if steps:
                raise InvariantViolation(f"Case {cid}: NOT_APPLICABLE must have empty steps array.")
            continue

        # Invariant: Steps numbered consecutively from 1
        current_phase_idx = -1
        for s_idx, s in enumerate(steps, 1):
            if not isinstance(s, dict):
                raise InvariantViolation(f"Case {cid}: step {s_idx} is not a JSON object.")

            for fld in REQUIRED_STEP_FIELDS:
                if fld not in s:
                    raise InvariantViolation(f"Case {cid}: step {s_idx} missing required field '{fld}'.")

            if s['step_no'] != s_idx:
                raise InvariantViolation(f"Case {cid}: step {s_idx} has incorrect step_no {s['step_no']}.")

            phase = s['phase']
            if phase not in ALLOWED_PHASES:
                raise InvariantViolation(f"Case {cid}: step {s_idx} invalid phase '{phase}'.")

            phase_idx = ALLOWED_PHASES.index(phase)
            if phase_idx < current_phase_idx:
                raise InvariantViolation(f"Case {cid}: step {s_idx} phase '{phase}' violates phase ordering (FINDING -> REMEDIATION -> VERIFICATION).")
            current_phase_idx = phase_idx

            op = s['operation']
            st = s['state']
            allowed_ops = ALLOWED_OPERATIONS[phase]
            if op not in allowed_ops:
                raise InvariantViolation(f"Case {cid}: step {s_idx} invalid operation '{op}' for phase '{phase}'.")
            if st not in allowed_ops[op]:
                raise InvariantViolation(f"Case {cid}: step {s_idx} invalid state '{st}' for operation '{op}'.")

            ev = s['evidence_id']
            if phase == 'FINDING':
                if not ev:
                    raise InvariantViolation(f"Case {cid}: FINDING step {s_idx} must cite non-empty evidence_id.")
            elif phase in ('REMEDIATION',):
                if ev != '':
                    raise InvariantViolation(f"Case {cid}: REMEDIATION step {s_idx} must have empty evidence_id, got '{ev}'.")
            elif phase == 'VERIFICATION':
                if status == 'INCOMPLETE' and ev != '':
                    raise InvariantViolation(f"Case {cid}: post-remediation VERIFICATION step {s_idx} must have empty evidence_id, got '{ev}'.")
                elif status == 'COMPLETE' and not ev:
                    raise InvariantViolation(f"Case {cid}: COMPLETE VERIFICATION step {s_idx} must cite evidence proving compliant state.")

        # Invariant: COMPLETE must have only VERIFICATION steps
        if status == 'COMPLETE':
            for s in steps:
                if s['phase'] != 'VERIFICATION':
                    raise InvariantViolation(f"Case {cid}: COMPLETE case must only contain VERIFICATION phase steps.")

        # Invariant: INCOMPLETE must contain findings
        if status == 'INCOMPLETE':
            phases_present = set(s['phase'] for s in steps)
            if 'FINDING' not in phases_present:
                raise InvariantViolation(f"Case {cid}: INCOMPLETE case must include FINDING steps.")

    return True
