"""
code/main.py
Phase 1 deletion audit pipeline — no LLM calls.

For each request in dataset/deletion_requests.csv:
  1. Classify intent (placeholder: everything is a deletion request for now)
  2. Resolve identity (current + historical emails, user_id, hashes)
  3. Collect evidence observations with captured_at <= audit_at
  4. Pick latest observation per (system_id, resource_id)
  5. Apply deletion_rules.csv to determine required action per record
  6. Determine deletion_status: COMPLETE / INCOMPLETE / NOT_APPLICABLE
  7. Build steps in required order and write output.csv

Run on all 518 requests.  For sample evaluation, pass --sample flag.
"""

import csv, json, os, sys, re, argparse, datetime, time
from collections import defaultdict

# Add code/ to path so imports work from repo root
sys.path.insert(0, os.path.dirname(__file__))
from evidence_parsers import load_all_observations, EvidenceIndex, Observation
from identity import resolve, Identity
from validator import validate_rows
from audit_trace import write_trace_record
from review_queue import generate_review_queue
from intent_classifier import classify_request, verify_requests_batch, generate_usage_report, load_environment, DELETION_REQUESTED, NOT_DELETION, UNCLEAR

# Ensure .env is loaded before pipeline execution
load_environment()


# ── Constants ──────────────────────────────────────────────────────────────────

DATASET_DIR = 'dataset'

PHASE_ORDER = {'FINDING': 0, 'REMEDIATION': 1, 'VERIFICATION': 2}

OP_ORDER = {
    # FINDING
    'REPORT_REMAINING_RECORD': 0,
    'REPORT_EXPOSED_PII':      1,
    'REPORT_ACTIVE_DATA_FLOW': 2,
    'REPORT_RESTORE_RISK':     3,
    # REMEDIATION
    'DISABLE_DATA_FLOW':       0,
    'BLOCK_RESTORE':           1,
    'DELETE_RECORD':           2,
    'REDACT_RECORD':           3,
    'ANONYMIZE_RECORD':        4,
    # VERIFICATION
    'VERIFY_RECORD_ABSENT':    0,
    'VERIFY_RECORD_PRESENT':   1,
    'VERIFY_RECORD_REDACTED':  2,
    'VERIFY_RECORD_ANONYMIZED':3,
    'VERIFY_DATA_FLOW_DISABLED':4,
    'VERIFY_RESTORE_BLOCKED':  5,
}

ACTION_MAP = {
    'USER_PROFILE':       'DELETE',
    'SECONDARY_IDENTIFIER':'DELETE',
    'SEARCH_INDEX_ENTRY': 'DELETE',
    'CACHE_ENTRY':        'DELETE',
    'SUPPORT_MESSAGE':    'REDACT',
    'SUPPORT_ATTACHMENT': 'DELETE',
    'ANALYTICS_PROFILE':  'ANONYMIZE',
    'PRODUCT_TELEMETRY':  'ANONYMIZE',
    'USER_EXPORT':        'DELETE',
    'MARKETING_PROFILE':  'DELETE',
    'EMAIL_DELIVERY_LOG': 'REDACT',
    'SECURITY_AUDIT_LOG': 'RETAIN',
    'LEGAL_HOLD_RECORD':  'RETAIN',
    'BACKUP_ARCHIVE':     'RETAIN',
    'ACCOUNT_TOMBSTONE':  'REDACT',
    'DATA_FLOW':          'DISABLE',
}

COMPLIANT_STATE = {
    'DELETE':   'ABSENT',
    'REDACT':   'REDACTED',
    'ANONYMIZE':'ANONYMIZED',
    'RETAIN':   'PRESENT',
    'DISABLE':  'DISABLED',
    'BLOCK':    'BLOCKED',
}


def classify_intent(request_text: str) -> str:
    # Placeholder intent rule as requested: everything is a deletion request for now
    return 'DELETION'


def obs_matches_identity(obs: Observation, identity: Identity) -> bool:
    ids = obs.identifiers
    if ids.get('email') and ids['email'].lower() in identity.emails:
        return True
    if ids.get('email_hash') and ids['email_hash'].lower() in identity.email_hashes:
        return True
    if ids.get('user_id') and ids['user_id'] == identity.user_id:
        return True
    if obs.resource_id in identity.linked_resource_ids:
        return True
    return False


def audit_case(case, all_obs, identity: Identity, sa_rows=None):
    audit_at = case['audit_at']
    req_at = case['requested_at']
    rep_at = case['reported_at']

    # Step 1: Collect all known resource IDs for this user
    user_rids = set()
    for o in all_obs:
        if obs_matches_identity(o, identity):
            user_rids.add(o.resource_id)
    user_rids.update(identity.linked_resource_ids.keys())

    # Find primary account from grounded evidence or linked identities
    primary_acc = None
    for rid in sorted(user_rids):
        if rid.startswith('account_'):
            primary_acc = rid
            break

    # Step 2: Gather observations available at or before audit_at
    relevant = [
        o for o in all_obs
        if (o.resource_id in user_rids or obs_matches_identity(o, identity))
        and o.captured_at <= audit_at
    ]

    # Step 3: Determine latest state per (system_id, resource_id)
    by_key = defaultdict(list)
    for o in relevant:
        by_key[(o.system_id, o.resource_id)].append(o)

    latest = {}
    for k, o_list in by_key.items():
        max_ts = max(o.captured_at for o in o_list)
        at_max = [o for o in o_list if o.captured_at == max_ts]
        # If any observation at latest timestamp shows ghost data / violation, prioritize it
        violation = [o for o in at_max if o.state in ('PRESENT', 'ACTIVE') and ACTION_MAP.get(o.record_type) not in ('RETAIN',)]
        if violation:
            latest[k] = violation[0]
        else:
            latest[k] = at_max[-1]

    # For account_service, if multiple accounts exist, keep the latest one (lifecycle account)
    acc_keys = [k for k in latest.keys() if k[0] == 'account_service']
    if len(acc_keys) > 1:
        best_acc_key = max(acc_keys, key=lambda k: latest[k].captured_at)
        for k in acc_keys:
            if k != best_acc_key:
                del latest[k]
        primary_acc = best_acc_key[1]
    elif len(acc_keys) == 1:
        primary_acc = acc_keys[0][1]

    findings = []
    remediations = []
    verifications = []
    has_violation = False

    for (svc, rid), obs in sorted(latest.items()):
        rtype  = obs.record_type
        state  = obs.state
        ev_id  = obs.file_id
        action = ACTION_MAP.get(rtype, 'DELETE')

        if rtype in ('UNKNOWN',):
            continue

        if rtype == 'BACKUP_ARCHIVE':
            if state == 'ACTIVE':
                has_violation = True
                findings.append((svc, rid, rtype, state, ev_id, 'REPORT_RESTORE_RISK'))
                remediations.append((svc, rid, rtype, 'BLOCKED', 'BLOCK_RESTORE'))
                verifications.append((svc, rid, rtype, 'BLOCKED', 'VERIFY_RESTORE_BLOCKED'))
            elif state == 'BLOCKED':
                verifications.append((svc, rid, rtype, 'BLOCKED', 'VERIFY_RESTORE_BLOCKED'))
            continue

        if rtype == 'DATA_FLOW':
            if state == 'ACTIVE':
                has_violation = True
                findings.append((svc, rid, rtype, state, ev_id, 'REPORT_ACTIVE_DATA_FLOW'))
                remediations.append((svc, rid, rtype, 'DISABLED', 'DISABLE_DATA_FLOW'))
                verifications.append((svc, rid, rtype, 'DISABLED', 'VERIFY_DATA_FLOW_DISABLED'))
            elif state == 'DISABLED':
                verifications.append((svc, rid, rtype, 'DISABLED', 'VERIFY_DATA_FLOW_DISABLED'))
            continue

        if action == 'RETAIN':
            if state in ('PRESENT', 'ACTIVE'):
                verifications.append((svc, rid, rtype, 'PRESENT', 'VERIFY_RECORD_PRESENT'))
            continue

        if rtype == 'ACCOUNT_TOMBSTONE':
            if state == 'PRESENT':
                has_violation = True
                findings.append((svc, rid, rtype, state, ev_id, 'REPORT_EXPOSED_PII'))
                remediations.append((svc, rid, rtype, 'REDACTED', 'REDACT_RECORD'))
                verifications.append((svc, rid, rtype, 'REDACTED', 'VERIFY_RECORD_REDACTED'))
            elif state == 'REDACTED':
                verifications.append((svc, rid, rtype, 'REDACTED', 'VERIFY_RECORD_REDACTED'))
            continue

        # Check if support record is an attachment (e.g. from PDF origin) -> DELETE
        if rtype == 'SUPPORT_ATTACHMENT' or (rtype == 'SUPPORT_MESSAGE' and ('attachment' in (obs.source_table or '').lower() or 'attachment' in str(obs.raw).lower())):
            action = 'DELETE'

        comp_state = COMPLIANT_STATE.get(action, 'ABSENT')

        if state == comp_state:
            vop = f'VERIFY_RECORD_{comp_state}'
            if comp_state == 'ABSENT': vop = 'VERIFY_RECORD_ABSENT'
            elif comp_state == 'ANONYMIZED': vop = 'VERIFY_RECORD_ANONYMIZED'
            elif comp_state == 'REDACTED': vop = 'VERIFY_RECORD_REDACTED'
            verifications.append((svc, rid, rtype, comp_state, vop))
        elif state == 'ABSENT' and action == 'DELETE':
            verifications.append((svc, rid, rtype, 'ABSENT', 'VERIFY_RECORD_ABSENT'))
        elif state == 'ANONYMIZED' and action == 'ANONYMIZE':
            verifications.append((svc, rid, rtype, 'ANONYMIZED', 'VERIFY_RECORD_ANONYMIZED'))
        elif state == 'REDACTED' and action == 'REDACT':
            verifications.append((svc, rid, rtype, 'REDACTED', 'VERIFY_RECORD_REDACTED'))
        else:
            has_violation = True
            if action in ('REDACT', 'ANONYMIZE'):
                fop = 'REPORT_EXPOSED_PII'
                rop = 'REDACT_RECORD' if action == 'REDACT' else 'ANONYMIZE_RECORD'
                vop = 'VERIFY_RECORD_REDACTED' if action == 'REDACT' else 'VERIFY_RECORD_ANONYMIZED'
                target = comp_state
            else:
                fop = 'REPORT_REMAINING_RECORD'
                rop = 'DELETE_RECORD'
                vop = 'VERIFY_RECORD_ABSENT'
                target = 'ABSENT'
            findings.append((svc, rid, rtype, state, ev_id, fop))
            remediations.append((svc, rid, rtype, target, rop))
            verifications.append((svc, rid, rtype, target, vop))

    # Ensure primary account is in verification if not found remaining
    if primary_acc and not any(f[1] == primary_acc for f in findings):
        if not any(v[1] == primary_acc for v in verifications):
            verifications.append(('account_service', primary_acc, 'USER_PROFILE', 'ABSENT', 'VERIFY_RECORD_ABSENT'))

    deletion_status = 'INCOMPLETE' if has_violation else 'COMPLETE'

    def sort_key(tup):
        op = tup[-1]
        svc, rid = tup[0], tup[1]
        return (OP_ORDER.get(op, 99), svc, rid)

    steps = []
    if deletion_status == 'INCOMPLETE':
        for phase_name, items in [
            ('FINDING',      findings),
            ('REMEDIATION',  remediations),
            ('VERIFICATION', verifications),
        ]:
            for tup in sorted(items, key=sort_key):
                if phase_name == 'FINDING':
                    svc, rid, rtype, st, ev, op = tup
                else:
                    svc, rid, rtype, st, op = tup
                    ev = ''
                steps.append({
                    'phase': phase_name, 'system_id': svc, 'resource_id': rid,
                    'operation': op, 'state': st, 'evidence_id': ev,
                })
    else:
        # COMPLETE: VERIFICATION only, with evidence
        ev_map = {}
        for o in sorted(relevant, key=lambda x: x.captured_at, reverse=True):
            k = (o.system_id, o.resource_id)
            if k not in ev_map and o.file_id:
                ev_map[k] = o.file_id

        # Fallback for primary account if no direct evidence
        if primary_acc and ('account_service', primary_acc) not in ev_map:
            for o in sorted(all_obs, key=lambda x: x.captured_at, reverse=True):
                if o.captured_at <= audit_at and o.system_id == 'account_service' and o.file_id:
                    ev_map[('account_service', primary_acc)] = o.file_id
                    break

        for tup in sorted(verifications, key=sort_key):
            svc, rid, rtype, st, op = tup
            ev = ev_map.get((svc, rid), '')
            steps.append({
                'phase': 'VERIFICATION', 'system_id': svc, 'resource_id': rid,
                'operation': op, 'state': st, 'evidence_id': ev,
            })

    for i, s in enumerate(steps, 1):
        s['step_no'] = i

    return deletion_status, steps, relevant


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sample', action='store_true',
                        help='Run on sample_deletion_requests.csv + evaluate')
    args = parser.parse_args()

    t_start = time.time()
    requests_file = os.path.join(DATASET_DIR,
        'sample_deletion_requests.csv' if args.sample else 'deletion_requests.csv')
    output_file = 'output.csv'

    print(f'Loading evidence observations from {DATASET_DIR}...', flush=True)
    all_obs = load_all_observations(DATASET_DIR, use_cache=True)
    index = EvidenceIndex(all_obs)
    t_parsed = time.time() - t_start
    print(f'  {len(all_obs)} observations loaded and indexed in {t_parsed:.2f}s', flush=True)

    print(f'Loading requests from {requests_file}...', flush=True)
    with open(requests_file, newline='', encoding='utf-8') as f:
        requests = list(csv.DictReader(f))
    print(f'  {len(requests)} requests', flush=True)

    sa_path = os.path.join(DATASET_DIR, 'system_activity.csv')
    sa_rows = list(csv.DictReader(open(sa_path, encoding='utf-8'))) if os.path.exists(sa_path) else []

    # Reset audit trace for clean run
    trace_path = 'audit_trace.jsonl'
    if os.path.exists(trace_path):
        try:
            os.remove(trace_path)
        except Exception:
            pass

    # Optional LLM Verification Pass (runs if key exists; skips offline; never changes status)
    print("Running LLM verification check...", flush=True)
    verifier_map = verify_requests_batch(requests)
    verifier_disagreements = []

    rows = []
    flagged_cases = []

    for req in requests:
        case_id      = req['case_id']
        email        = req['email']
        request_text = req.get('request_text', '')

        intent = classify_request(request_text)

        # Check verifier disagreement if verifier ran
        v_intent = verifier_map.get(case_id)
        if v_intent and v_intent != intent:
            verifier_disagreements.append({
                'case_id': case_id,
                'email': email,
                'rule_intent': intent,
                'verifier_intent': v_intent,
                'request_text': request_text
            })

        if intent != DELETION_REQUESTED:
            identity = resolve(email, DATASET_DIR)
            rows.append({'case_id': case_id, 'deletion_status': 'NOT_APPLICABLE', 'steps_json': '[]'})
            write_trace_record(case_id, req.get('audit_at', ''), 'NOT_APPLICABLE', identity, [], [], trace_path=trace_path)
            continue

        identity = resolve(email, DATASET_DIR)
        deletion_status, steps, relevant_obs = audit_case(req, all_obs, identity, sa_rows=sa_rows)

        rows.append({
            'case_id': case_id,
            'deletion_status': deletion_status,
            'steps_json': json.dumps(steps, separators=(',', ':')),
        })

        write_trace_record(case_id, req.get('audit_at', ''), deletion_status, identity, relevant_obs, steps, trace_path=trace_path)

        # Flag for human review queue if historical email changes or active risks
        has_risk = any(s.get('operation') in ('REPORT_RESTORE_RISK', 'REPORT_ACTIVE_DATA_FLOW') for s in steps)
        if len(identity.emails) > 1 or has_risk:
            reason = 'Historical identifier change' if len(identity.emails) > 1 else 'Active data flow or restore risk'
            flagged_cases.append({
                'case_id': case_id,
                'email': email,
                'status': deletion_status,
                'reason': reason,
                'details': f"{len(steps)} steps evaluated",
            })

    rows.sort(key=lambda r: r['case_id'])

    # Run strict invariant validator before writing
    validate_rows(rows, expected_count=len(requests))

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['case_id', 'deletion_status', 'steps_json'])
        writer.writeheader()
        writer.writerows(rows)

    print(f'Wrote {len(rows)} rows to {output_file}')

    # Generate review queue sidecar with verifier disagreements
    generate_review_queue(flagged_cases, verifier_disagreements=verifier_disagreements, verified_count=len(verifier_map))
    print(f'Wrote {len(flagged_cases)} flagged cases to review_queue.md')
    if verifier_disagreements:
        print(f'  ({len(verifier_disagreements)} verifier disagreements logged to review_queue.md)')
    print(f'Wrote audit provenance trace to {trace_path}')

    # Generate usage report strictly from usage file
    generate_usage_report(total_requests=len(requests))

    from collections import Counter
    status_dist = Counter(r['deletion_status'] for r in rows)
    print(f'Status distribution: {dict(status_dist)}')

    total_runtime = time.time() - t_start
    print(f'Total runtime: {total_runtime:.2f}s\n')

    if args.sample:
        from evaluate import evaluate as eval_fn
        eval_fn('dataset/sample_output.csv', output_file)


if __name__ == '__main__':
    main()
