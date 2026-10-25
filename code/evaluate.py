"""
code/evaluate.py
Score predictions against dataset/sample_output.csv.

Metrics:
  case_status_accuracy   - fraction of cases with correct deletion_status
  step_set_f1            - F1 on unordered set of (system_id, resource_id, operation, state) tuples per case
  field_accuracy         - per-field exact-match across all steps
  sequence_accuracy      - fraction of cases where step ORDER matches exactly (phase→op→sys→rid)

Usage:
  python code/evaluate.py [--pred output.csv] [--gold dataset/sample_output.csv]
"""

import csv, json, sys, argparse
from collections import defaultdict

STEP_KEY_FIELDS = ('system_id', 'resource_id', 'operation', 'state')
STEP_ALL_FIELDS = ('step_no', 'phase', 'system_id', 'resource_id', 'operation', 'state', 'evidence_id')


def load_csv(path):
    with open(path, newline='', encoding='utf-8') as f:
        return {r['case_id']: r for r in csv.DictReader(f)}


def parse_steps(steps_json_str):
    try:
        steps = json.loads(steps_json_str)
        if not isinstance(steps, list): return []
        return steps
    except Exception:
        return []


def step_key(step):
    return tuple(str(step.get(f, '')).strip() for f in STEP_KEY_FIELDS)


def evaluate(gold_path, pred_path, verbose=True):
    gold = load_csv(gold_path)
    pred = load_csv(pred_path)

    case_ids = sorted(gold.keys())
    n = len(case_ids)

    status_correct = 0
    step_set_precision_sum = 0.0
    step_set_recall_sum = 0.0
    step_set_f1_sum = 0.0
    field_hits = defaultdict(int)
    field_total = defaultdict(int)
    seq_correct = 0

    failing_cases = []

    for cid in case_ids:
        g = gold[cid]
        p = pred.get(cid)
        if p is None:
            failing_cases.append({'case_id': cid, 'reason': 'MISSING'})
            continue

        g_status = g['deletion_status']
        p_status = p.get('deletion_status', '')
        status_ok = g_status == p_status
        if status_ok:
            status_correct += 1

        g_steps = parse_steps(g['steps_json'])
        p_steps = parse_steps(p.get('steps_json', '[]'))

        # Step-set F1
        g_keys = [step_key(s) for s in g_steps]
        p_keys = [step_key(s) for s in p_steps]
        g_set = set(g_keys)
        p_set = set(p_keys)
        tp = len(g_set & p_set)
        precision = tp / len(p_set) if p_set else (1.0 if not g_set else 0.0)
        recall    = tp / len(g_set) if g_set else (1.0 if not p_set else 0.0)
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        step_set_precision_sum += precision
        step_set_recall_sum    += recall
        step_set_f1_sum        += f1

        # Field-level accuracy (matched steps only, by step_key)
        g_by_key = {}
        for s in g_steps:
            k = step_key(s)
            if k not in g_by_key: g_by_key[k] = s
        p_by_key = {}
        for s in p_steps:
            k = step_key(s)
            if k not in p_by_key: p_by_key[k] = s
        for k in g_by_key:
            gs = g_by_key[k]
            ps = p_by_key.get(k)
            for fld in STEP_ALL_FIELDS:
                field_total[fld] += 1
                if ps and str(gs.get(fld, '')).strip() == str(ps.get(fld, '')).strip():
                    field_hits[fld] += 1

        # Sequence accuracy: ordered list of step_keys must match exactly
        seq_ok = g_keys == p_keys
        if seq_ok:
            seq_correct += 1

        # Record failures
        if not status_ok or f1 < 1.0:
            missing = sorted(g_set - p_set)
            extra   = sorted(p_set - g_set)
            failing_cases.append({
                'case_id': cid,
                'g_status': g_status, 'p_status': p_status,
                'status_ok': status_ok,
                'step_f1': round(f1, 3),
                'seq_ok': seq_ok,
                'missing_steps': missing,
                'extra_steps': extra,
            })

    results = {
        'n': n,
        'case_status_accuracy': round(status_correct / n, 4),
        'step_set_precision':   round(step_set_precision_sum / n, 4),
        'step_set_recall':      round(step_set_recall_sum / n, 4),
        'step_set_f1':          round(step_set_f1_sum / n, 4),
        'sequence_accuracy':    round(seq_correct / n, 4),
        'field_accuracy': {
            fld: round(field_hits[fld] / field_total[fld], 4) if field_total[fld] else None
            for fld in STEP_ALL_FIELDS
        },
        'failing_cases': failing_cases,
    }

    if verbose:
        print(f'\n=== Evaluation vs {gold_path} ({n} cases) ===')
        print(f'  case_status_accuracy : {results["case_status_accuracy"]:.1%}')
        print(f'  step_set_precision   : {results["step_set_precision"]:.1%}')
        print(f'  step_set_recall      : {results["step_set_recall"]:.1%}')
        print(f'  step_set_f1          : {results["step_set_f1"]:.1%}')
        print(f'  sequence_accuracy    : {results["sequence_accuracy"]:.1%}')
        print(f'  field accuracy:')
        for fld, acc in results['field_accuracy'].items():
            print(f'    {fld:20s}: {acc:.1%}' if acc is not None else f'    {fld:20s}: N/A')
        print(f'\n  Failing cases ({len(failing_cases)}):')
        for fc in failing_cases:
            if fc.get('reason') == 'MISSING':
                print(f'    {fc["case_id"]}: MISSING from prediction')
            else:
                status_str = '' if fc['status_ok'] else f' STATUS:{fc["g_status"]}->{fc["p_status"]}'
                print(f'    {fc["case_id"]}: f1={fc["step_f1"]:.2f} seq={fc["seq_ok"]}{status_str}')
                if fc['missing_steps']:
                    for ms in fc['missing_steps'][:3]:
                        print(f'      MISS: {ms}')
                if fc['extra_steps']:
                    for es in fc['extra_steps'][:3]:
                        print(f'      XTRA: {es}')

    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--pred', default='output.csv')
    parser.add_argument('--gold', default='dataset/sample_output.csv')
    args = parser.parse_args()
    evaluate(args.gold, args.pred)
