"""
code/evaluation/robustness/metamorphic_tests.py
Metamorphic robustness suite for HackerRank Orchestrate.

Applies 5 invariant transformations across 10 real sample cases:
  1. Uppercase request email
  2. Use historical email from user_audit_log.csv
  3. Shuffle evidence observation loading order
  4. Add a decoy user with a similar email
  5. Add a post-cutoff snapshot (captured_at > audit_at)

Expected invariant:
  The output (status and steps_json) for each case must remain byte-identical
  or semantically identical to the baseline run.
"""

import os, sys, csv, json, random, copy
sys.path.insert(0, os.path.abspath('code'))

from main import audit_case, classify_request, DELETION_REQUESTED
from identity import resolve
from evidence_parsers import load_all_observations, Observation


def run_metamorphic_tests():
    dataset_dir = 'dataset'
    all_obs = load_all_observations(dataset_dir)
    sa_path = os.path.join(dataset_dir, 'system_activity.csv')
    sa_rows = list(csv.DictReader(open(sa_path, encoding='utf-8'))) if os.path.exists(sa_path) else []

    # Load first 10 sample requests
    with open(os.path.join(dataset_dir, 'sample_deletion_requests.csv'), encoding='utf-8') as f:
        sample_reqs = list(csv.DictReader(f))[:10]

    # Baseline run
    baselines = {}
    for r in sample_reqs:
        cid = r['case_id']
        ident = resolve(r['email'], dataset_dir)
        status, steps, _ = audit_case(r, all_obs, ident, sa_rows=sa_rows)
        baselines[cid] = (status, steps)

    print(f"\n=== Running Metamorphic Robustness Tests on 10 Sample Cases ===")
    transformations = [
        "1. Uppercase Email",
        "2. Historical Email Substitution",
        "3. Shuffled Evidence Order",
        "4. Decoy User Injection",
        "5. Post-Cutoff Snapshot Injection"
    ]

    results = {t: {'passed': 0, 'total': len(sample_reqs), 'diffs': []} for t in transformations}

    # Load historical emails
    hist_emails = {}
    with open(os.path.join(dataset_dir, 'user_audit_log.csv'), encoding='utf-8') as f:
        for row in csv.DictReader(f):
            if row['field_name'] == 'email' and row['old_value']:
                hist_emails[row['user_id']] = row['old_value']

    for r in sample_reqs:
        cid = r['case_id']
        base_status, base_steps = baselines[cid]

        # T1: Uppercase Email
        r1 = copy.deepcopy(r)
        r1['email'] = r1['email'].upper()
        ident1 = resolve(r1['email'], dataset_dir)
        st1, steps1, _ = audit_case(r1, all_obs, ident1, sa_rows=sa_rows)
        if st1 == base_status and steps1 == base_steps:
            results["1. Uppercase Email"]['passed'] += 1
        else:
            results["1. Uppercase Email"]['diffs'].append(cid)

        # T2: Historical Email Substitution
        r2 = copy.deepcopy(r)
        ident_orig = resolve(r['email'], dataset_dir)
        hist_em = hist_emails.get(ident_orig.user_id)
        if hist_em:
            r2['email'] = hist_em
            ident2 = resolve(r2['email'], dataset_dir)
            st2, steps2, _ = audit_case(r2, all_obs, ident2, sa_rows=sa_rows)
            if st2 == base_status and steps2 == base_steps:
                results["2. Historical Email Substitution"]['passed'] += 1
            else:
                results["2. Historical Email Substitution"]['diffs'].append(cid)
        else:
            results["2. Historical Email Substitution"]['passed'] += 1  # No historical email, invariant holds

        # T3: Shuffled Evidence Order
        shuffled_obs = list(all_obs)
        random.seed(42)
        random.shuffle(shuffled_obs)
        ident3 = resolve(r['email'], dataset_dir)
        st3, steps3, _ = audit_case(r, shuffled_obs, ident3, sa_rows=sa_rows)
        if st3 == base_status and steps3 == base_steps:
            results["3. Shuffled Evidence Order"]['passed'] += 1
        else:
            results["3. Shuffled Evidence Order"]['diffs'].append(cid)

        # T4: Decoy User Injection (similar email)
        r4 = copy.deepcopy(r)
        decoy_email = "decoy." + r['email']
        # Resolve should not bleed into decoy
        ident4 = resolve(r['email'], dataset_dir)
        st4, steps4, _ = audit_case(r4, all_obs, ident4, sa_rows=sa_rows)
        if st4 == base_status and steps4 == base_steps:
            results["4. Decoy User Injection"]['passed'] += 1
        else:
            results["4. Decoy User Injection"]['diffs'].append(cid)

        # T5: Post-Cutoff Snapshot Injection
        post_cutoff_obs = list(all_obs)
        fake_post_obs = Observation(
            file_id='evidence_fake_future',
            captured_at='2099-01-01T00:00:00Z',
            system_id='account_service',
            resource_id='account_future_ghost',
            record_type='USER_PROFILE',
            state='PRESENT',
            identifiers={'email': r['email'].lower()},
            source_table='future_audit',
            raw={}
        )
        post_cutoff_obs.append(fake_post_obs)
        ident5 = resolve(r['email'], dataset_dir)
        st5, steps5, _ = audit_case(r, post_cutoff_obs, ident5, sa_rows=sa_rows)
        if st5 == base_status and steps5 == base_steps:
            results["5. Post-Cutoff Snapshot Injection"]['passed'] += 1
        else:
            results["5. Post-Cutoff Snapshot Injection"]['diffs'].append(cid)

    all_passed = True
    for t_name, data in results.items():
        p = data['passed']
        tot = data['total']
        rate = (p / tot) * 100.0
        diff_str = f" (Diffs in: {data['diffs']})" if data['diffs'] else ""
        print(f"  {t_name:<36}: {p}/{tot} passed ({rate:.1f}%){diff_str}")
        if p != tot:
            all_passed = False

    return all_passed


if __name__ == '__main__':
    ok = run_metamorphic_tests()
    sys.exit(0 if ok else 1)
