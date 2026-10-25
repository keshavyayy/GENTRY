"""
code/audit_trace.py
Provenance sidecar generator for HackerRank Orchestrate Deletion Audit.
Writes structured provenance records for each evaluated request to audit_trace.jsonl.
"""

import json, os, datetime

TRACE_FILE = 'audit_trace.jsonl'

def write_trace_record(case_id, audit_at, deletion_status, identity, relevant_obs, steps, trace_path=TRACE_FILE):
    """Write an audit trace entry to audit_trace.jsonl."""
    files_consulted = sorted(list(set(o.file_id for o in relevant_obs if o.file_id)))
    record = {
        'case_id': case_id,
        'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'audit_at': audit_at,
        'deletion_status': deletion_status,
        'identity': {
            'user_id': identity.user_id,
            'emails': sorted(list(identity.emails)),
            'phones': sorted(list(identity.phones)),
            'email_hashes': sorted(list(identity.email_hashes)),
            'linked_resources': dict(identity.linked_resource_ids),
        },
        'evidence_files_consulted': files_consulted,
        'step_count': len(steps),
        'steps': steps,
    }
    with open(trace_path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(record, separators=(',', ':')) + '\n')
