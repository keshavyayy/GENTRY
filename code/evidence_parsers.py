"""
code/evidence_parsers.py
Parse every evidence file into a flat list of Observation namedtuples.

Observation fields:
  file_id      - from evidence_files.csv
  captured_at  - ISO-8601 string (from file metadata or snapshot_scope)
  system_id    - service name (account_service, search_service, etc.)
  resource_id  - e.g. account_001, search_123
  record_type  - USER_PROFILE, SEARCH_INDEX_ENTRY, ANALYTICS_PROFILE, etc.
  state        - PRESENT / ABSENT / ANONYMIZED / REDACTED / ACTIVE / DISABLED / BLOCKED
  identifiers  - dict: email, phone, email_hash, user_id, name (any subset, lowercased keys)
  source_table - origin table or section name
  raw          - original dict for debugging
"""

import csv, json, os, re, sqlite3, pickle
from collections import namedtuple, defaultdict

Observation = namedtuple('Observation', [
    'file_id', 'captured_at', 'system_id', 'resource_id',
    'record_type', 'state', 'identifiers', 'source_table', 'raw'
])

# ── helpers ───────────────────────────────────────────────────────────────────

EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
HASH_RE  = re.compile(r'\b[0-9a-f]{64}\b')

PIPE_RE = re.compile(r'^(\S+)\s+\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s*(.*)')
SYSLOG_RE = re.compile(r'<\d+>\d\s+\S+\s+(\S+)\s+(\S+)\s+-\s+-\s+(.*)')
CLOUD_RE = re.compile(r'^(\S+)\s+requestId=(\S+)\s+level=(\S+)\s+function=(\S+)\s+message="?(.*?)"?$')

SYSTEM_MAP = {
    'account_service':   ('USER_PROFILE',         'account_service'),
    'search_service':    ('SEARCH_INDEX_ENTRY',    'search_service'),
    'analytics_platform':('ANALYTICS_PROFILE',     'analytics_platform'),
    'support_platform':  ('SUPPORT_MESSAGE',       'support_platform'),
    'export_service':    ('USER_EXPORT',           'export_service'),
    'integration_service':('DATA_FLOW',            'integration_service'),
    'backup_service':    ('BACKUP_ARCHIVE',        'backup_service'),
    'security_service':  ('SECURITY_AUDIT_LOG',    'security_service'),
    'marketing_platform':('MARKETING_PROFILE',     'marketing_platform'),
    'object_storage':    ('SUPPORT_ATTACHMENT',    'object_storage'),
    'identity_service':  ('ACCOUNT_TOMBSTONE',     'identity_service'),
}

PREFIX_RTYPE = {
    'account_':     ('USER_PROFILE',       'account_service'),
    'search_':      ('SEARCH_INDEX_ENTRY', 'search_service'),
    'analytics_':   ('ANALYTICS_PROFILE',  'analytics_platform'),
    'support_':     ('SUPPORT_MESSAGE',    'support_platform'),
    'export_':      ('USER_EXPORT',        'export_service'),
    'data_flow_':   ('DATA_FLOW',          'integration_service'),
    'backup_':      ('BACKUP_ARCHIVE',     'backup_service'),
    'audit_record_':('SECURITY_AUDIT_LOG', 'security_service'),
    'marketing_':   ('MARKETING_PROFILE',  'marketing_platform'),
    'object_':      ('SUPPORT_ATTACHMENT', 'object_storage'),
    'tombstone_':   ('ACCOUNT_TOMBSTONE',  'identity_service'),
}

def rtype_from_rid(resource_id):
    rid = resource_id or ''
    for prefix, (rtype, svc) in PREFIX_RTYPE.items():
        if rid.startswith(prefix):
            return rtype, svc
    return 'UNKNOWN', 'unknown'

def extract_ids(d):
    """Pull email, phone, email_hash, user_id, name from a dict, including nested dicts."""
    ids = {}
    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    walk(v)
                elif isinstance(v, str) and v.strip() and v.strip() != 'null':
                    s = v.strip()
                    m_email = EMAIL_RE.search(s)
                    if m_email and '@' in s:
                        ids['email'] = m_email.group(0).lower()
                    elif s.startswith('user_'):
                        ids['user_id'] = s
                    elif len(s) == 64 and HASH_RE.match(s):
                        ids['email_hash'] = s.lower()
                    elif k in ('phone', 'requester_phone', 'owner_phone'):
                        ids['phone'] = s
                    elif k in ('full_name', 'display_name', 'requester_name', 'name'):
                        ids['name'] = s
        elif isinstance(obj, list):
            for item in obj:
                walk(item)
    walk(d)
    return ids

def infer_state_from_dict(d, record_type):
    """Infer state from structured dict fields."""
    status = str(d.get('account_status', d.get('status', d.get('result', '')))).upper()
    
    # Specific record type logic
    if record_type == 'ACCOUNT_TOMBSTONE':
        has_pii = any(d.get(k) for k in ('email', 'phone', 'name', 'full_name', 'email_hash'))
        if has_pii:
            return 'PRESENT'
        return 'REDACTED'

    if record_type == 'ANALYTICS_PROFILE':
        has_pii = any(d.get(k) for k in ('email', 'phone', 'email_hash'))
        if status in ('ANONYMIZED',):
            return 'ANONYMIZED'
        if has_pii:
            return 'PRESENT'
        return 'ANONYMIZED'

    if record_type == 'SUPPORT_MESSAGE':
        # Check message text for unredacted emails or phone
        msg_text = str(d.get('message_text', d.get('message', '')))
        has_exposed_email = bool(EMAIL_RE.search(msg_text)) and '[REDACTED]' not in msg_text
        has_pii = has_exposed_email or any(d.get(k) for k in ('requester_email', 'requester_phone', 'requester_name', 'email'))
        if status in ('REDACTED',):
            return 'REDACTED'
        if status in ('NOT_FOUND', 'DELETED'):
            return 'ABSENT'
        if has_pii:
            return 'PRESENT'
        if d.get('customer_reference') or d.get('subject_reference') or '[REDACTED]' in msg_text:
            return 'REDACTED'
        return 'PRESENT'

    if record_type == 'BACKUP_ARCHIVE':
        ra = d.get('restore_allowed')
        if ra is not None:
            return 'ACTIVE' if ra else 'BLOCKED'
        if status in ('ACTIVE',): return 'ACTIVE'
        if status in ('BLOCKED',): return 'BLOCKED'
        return 'ACTIVE'

    if record_type == 'DATA_FLOW':
        en = d.get('enabled')
        if en is not None:
            return 'ACTIVE' if en else 'DISABLED'
        if status in ('ACTIVE',): return 'ACTIVE'
        if status in ('DISABLED', 'STOPPED'): return 'DISABLED'
        return 'ACTIVE'

    if status in ('DELETED', 'NOT_FOUND', 'ABSENT'):
        return 'ABSENT'
    if status in ('DELETION_PENDING',):
        return 'PRESENT'
    if status in ('ANONYMIZED',):
        return 'ANONYMIZED'
    if status in ('REDACTED',):
        return 'REDACTED'
    if status in ('FOUND', 'IDENTIFIABLE', 'PRESENT', 'ACTIVE'):
        return 'PRESENT'
    if status in ('BLOCKED',):
        return 'BLOCKED'
    if status in ('DISABLED', 'STOPPED'):
        return 'DISABLED'

    return 'PRESENT'

# ── SQL inventory snapshots ───────────────────────────────────────────────────

TABLE_META = {
    'customer_profiles':          ('account_service',     'USER_PROFILE'),
    'customer_search_documents':  ('search_service',      'SEARCH_INDEX_ENTRY'),
    'customer_analytics_profiles':('analytics_platform',  'ANALYTICS_PROFILE'),
    'support_records':            ('support_platform',    'SUPPORT_MESSAGE'),
    'customer_exports':           ('export_service',      'USER_EXPORT'),
    'connector_subscriptions':    ('integration_service', 'DATA_FLOW'),
    'backup_restore_entries':     ('backup_service',      'BACKUP_ARCHIVE'),
    'security_audit_records':     ('security_service',    'SECURITY_AUDIT_LOG'),
}

def parse_inventory_sql(file_id, sql_path):
    obs = []
    with open(sql_path, encoding='utf-8', errors='replace') as f:
        sql = f.read()
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(sql)
    except Exception:
        conn.close()
        return obs

    captured_ats = {}
    try:
        for r in conn.execute('SELECT origin_system, captured_at FROM snapshot_scope'):
            captured_ats[r['origin_system']] = r['captured_at']
    except Exception:
        pass

    for tbl, (svc, rtype) in TABLE_META.items():
        cap = captured_ats.get(svc, next(iter(captured_ats.values()), ''))
        try:
            cur = conn.execute(f'SELECT * FROM "{tbl}"')
            cols = [d[0] for d in cur.description]
            for row in cur.fetchall():
                d = dict(zip(cols, row))
                rid = d.get('resource_id', '')
                ids = extract_ids(d)
                state = infer_state_from_dict(d, rtype)
                obs.append(Observation(
                    file_id=file_id, captured_at=cap,
                    system_id=svc, resource_id=rid,
                    record_type=rtype, state=state,
                    identifiers=ids, source_table=tbl, raw=d
                ))
        except Exception:
            pass
    conn.close()
    return obs


def parse_replica_sql(file_id, sql_path, file_cap):
    obs = []
    with open(sql_path, encoding='utf-8', errors='replace') as f:
        sql = f.read()
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(sql)
    except Exception:
        conn.close()
        return obs

    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cur.fetchall()]
    primary_tables = [t for t in tables if 'primary' in t.lower()]
    replica_tables  = [t for t in tables if 'primary' not in t.lower()]

    primary_rids = set()
    for pt in primary_tables:
        try:
            for r in conn.execute(f'SELECT resource_id FROM "{pt}"'):
                primary_rids.add(r[0])
        except Exception:
            pass

    for tbl in tables:
        is_replica = tbl not in primary_tables
        try:
            cur2 = conn.execute(f'SELECT * FROM "{tbl}"')
            cols = [d[0] for d in cur2.description]
            for row in cur2.fetchall():
                d = dict(zip(cols, row))
                rid = d.get('resource_id', '')
                rj_str = d.get('record_json', '')
                rj = {}
                if rj_str:
                    try: rj = json.loads(rj_str)
                    except Exception: pass
                merged = {**rj, **{k: v for k, v in d.items() if k != 'record_json'}}
                ids = extract_ids(merged)
                rtype, svc = rtype_from_rid(rid)
                col_name = merged.get('collection_name', '')
                if col_name == 'customer_profiles': rtype, svc = 'USER_PROFILE', 'account_service'
                elif col_name == 'customer_search_documents': rtype, svc = 'SEARCH_INDEX_ENTRY', 'search_service'
                elif col_name == 'customer_analytics_reports': rtype, svc = 'ANALYTICS_PROFILE', 'analytics_platform'
                elif col_name == 'security_audit_events': rtype, svc = 'SECURITY_AUDIT_LOG', 'security_service'
                elif col_name == 'connector_configurations': rtype, svc = 'DATA_FLOW', 'integration_service'
                elif col_name == 'backup_catalog': rtype, svc = 'BACKUP_ARCHIVE', 'backup_service'
                state = infer_state_from_dict(merged, rtype)
                source = f'{tbl}(ghost)' if is_replica and rid not in primary_rids else tbl
                obs.append(Observation(
                    file_id=file_id, captured_at=merged.get('updated_at', file_cap),
                    system_id=svc, resource_id=rid,
                    record_type=rtype, state=state,
                    identifiers=ids, source_table=source, raw=merged
                ))
        except Exception:
            pass
    conn.close()
    return obs


def parse_search_sql(file_id, sql_path, file_cap):
    obs = []
    with open(sql_path, encoding='utf-8', errors='replace') as f:
        sql = f.read()
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(sql)
    except Exception:
        conn.close()
        return obs
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cur.fetchall()]
    for tbl in tables:
        try:
            cur2 = conn.execute(f'SELECT * FROM "{tbl}"')
            cols = [d[0] for d in cur2.description]
            for row in cur2.fetchall():
                d = dict(zip(cols, row))
                rid = d.get('resource_id', '')
                rj = {}
                if d.get('record_json'):
                    try: rj = json.loads(d['record_json'])
                    except: pass
                merged = {**rj, **{k: v for k, v in d.items() if k != 'record_json'}}
                ids = extract_ids(merged)
                doc = merged.get('document', {})
                if doc: ids.update({k: v for k, v in extract_ids(doc).items() if v})
                obs.append(Observation(
                    file_id=file_id, captured_at=file_cap,
                    system_id='search_service', resource_id=rid,
                    record_type='SEARCH_INDEX_ENTRY', state='PRESENT',
                    identifiers=ids, source_table=tbl, raw=merged
                ))
        except Exception:
            pass
    conn.close()
    return obs


# ── JSON records ──────────────────────────────────────────────────────────────

def parse_json_file(file_id, path, file_cap):
    obs = []
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            data = json.load(f)
    except Exception:
        return obs

    if 'snapshots' in data:
        for snap in data['snapshots']:
            cap = snap.get('captured_at', file_cap)
            collection = snap.get('collection', '')
            data_store = snap.get('data_store', '')
            for rec in snap.get('records', []):
                if not isinstance(rec, dict): continue
                rid = rec.get('resource_id', '')
                rtype, svc = rtype_from_rid(rid)
                if data_store: svc = data_store
                if collection == 'deleted_customer_references':
                    rtype = 'ACCOUNT_TOMBSTONE'
                    svc = 'identity_service'
                ids = extract_ids(rec)
                doc = rec.get('document', {})
                if isinstance(doc, dict): ids.update({k: v for k, v in extract_ids(doc).items() if v})
                state = infer_state_from_dict(rec, rtype)
                obs.append(Observation(
                    file_id=file_id, captured_at=cap,
                    system_id=svc, resource_id=rid,
                    record_type=rtype, state=state,
                    identifiers=ids, source_table=collection, raw=rec
                ))
        return obs

    if 'records' in data:
        cap = data.get('exported_at', data.get('captured_at', file_cap))
        collection = data.get('collection', 'records')
        for rec in data['records']:
            if not isinstance(rec, dict): continue
            rid = rec.get('resource_id', '')
            rtype = rec.get('record_type', '') or rtype_from_rid(rid)[0]
            svc = rec.get('system', rtype_from_rid(rid)[1])
            result = str(rec.get('result', '')).upper()
            state_map = {'NOT_FOUND': 'ABSENT', 'FOUND': 'PRESENT', 'IDENTIFIABLE': 'PRESENT',
                         'ANONYMIZED': 'ANONYMIZED', 'REDACTED': 'REDACTED', 'ACTIVE': 'ACTIVE',
                         'BLOCKED': 'BLOCKED', 'DISABLED': 'DISABLED'}
            state = state_map.get(result, infer_state_from_dict(rec, rtype))
            ids = extract_ids(rec)
            obs.append(Observation(
                file_id=file_id, captured_at=cap,
                system_id=svc, resource_id=rid,
                record_type=rtype, state=state,
                identifiers=ids, source_table=collection, raw=rec
            ))
        return obs

    if 'service_exports' in data:
        cap = data.get('exported_at', file_cap)
        for svc, content in data['service_exports'].items():
            if not isinstance(content, dict): continue
            for section, items in content.items():
                if not isinstance(items, list): continue
                for item in items:
                    if not isinstance(item, dict): continue
                    rid = item.get('resource_id', '')
                    profile = item.get('profile') or {}
                    merged = {**item, **profile}
                    ids = extract_ids(merged)
                    sc = item.get('status_code', 0)
                    rtype, default_svc = rtype_from_rid(rid)
                    svc_use = svc
                    if 'analytic' in section: rtype, svc_use = 'ANALYTICS_PROFILE', 'analytics_platform'
                    elif 'search' in section: rtype, svc_use = 'SEARCH_INDEX_ENTRY', 'search_service'
                    elif 'support' in section: rtype, svc_use = 'SUPPORT_MESSAGE', 'support_platform'
                    elif 'export' in section: rtype, svc_use = 'USER_EXPORT', 'export_service'
                    elif 'backup' in section or 'restore' in section: rtype, svc_use = 'BACKUP_ARCHIVE', 'backup_service'
                    elif 'connector' in section or 'data_flow' in section: rtype, svc_use = 'DATA_FLOW', 'integration_service'
                    elif 'audit' in section: rtype, svc_use = 'SECURITY_AUDIT_LOG', 'security_service'

                    if sc == 404: state = 'ABSENT'
                    elif sc == 200:
                        state = 'PRESENT' if (profile and any(v for v in profile.values() if v)) else 'REDACTED'
                    else:
                        state = infer_state_from_dict(merged, rtype)

                    obs.append(Observation(
                        file_id=file_id, captured_at=cap,
                        system_id=svc_use, resource_id=rid,
                        record_type=rtype, state=state,
                        identifiers=ids, source_table=section, raw=merged
                    ))
        return obs

    return obs


# ── LOG files ─────────────────────────────────────────────────────────────────

LOG_TS = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)')
BRACKET_RE = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\s+\[([A-Z]+)\]\s+\[([a-zA-Z0-9_\-]+)\]\s+\[([a-zA-Z0-9_\-]+)\]\s+([a-zA-Z0-9_\-]+):')
LOG_KV = re.compile(r'(\w+)=(?:"([^"]*?)"|([^\s"]+))')

def parse_log_file(file_id, path, file_cap):
    with open(path, encoding='utf-8', errors='replace') as f:
        lines = [l.strip() for l in f if l.strip()]

    all_trace_keys = defaultdict(dict)
    all_trace_rids = defaultdict(set)
    parsed_lines = []

    for line in lines:
        ts_m = LOG_TS.match(line)
        ts = ts_m.group(1) if ts_m else file_cap

        d = {}
        # 1. JSON line
        json_start = line.find('{')
        if json_start != -1 and line.endswith('}'):
            try: d = json.loads(line[json_start:])
            except: pass

        # 2. Pipe line
        if not d:
            m = PIPE_RE.match(line)
            if m:
                _, level, service, trace, event, rest = m.groups()
                d = {'level': level, 'service': service, 'trace_id': trace, 'event': event}
                for k, v1, v2 in LOG_KV.findall(rest):
                    d[k] = v1 if v1 != '' else v2

        # 3. Cloud runtime line
        if not d:
            m = CLOUD_RE.match(line)
            if m:
                _, req_id, level, fn, msg = m.groups()
                d = {'request_id': req_id, 'level': level, 'function': fn}
                msg_clean = msg.replace(r'\"', '"')
                for k, v1, v2 in LOG_KV.findall(msg_clean):
                    d[k] = v1 if v1 != '' else v2

        # 4. Syslog line
        if not d:
            m = SYSLOG_RE.search(line)
            if m:
                service, trace, rest = m.groups()
                d = {'service': service, 'trace_id': trace}
                for k, v1, v2 in LOG_KV.findall(rest):
                    d[k] = v1 if v1 != '' else v2

        # 5. Bracket line
        if not d:
            b_m = BRACKET_RE.match(line)
            if b_m:
                level, service, trace_id, event = b_m.groups()
                d = {'level': level, 'service': service, 'trace_id': trace_id, 'event': event}
            for k, v1, v2 in LOG_KV.findall(line):
                d[k] = v1 if v1 != '' else v2

        if not d: continue

        tr = d.get('trace_id')
        line_ids = {}
        for fld in ('lookup_key', 'match_key', 'subject_key', 'correlation_key', 'matched_value', 'email', 'customer_email', 'requester_email'):
            v = d.get(fld, '')
            if v and isinstance(v, str):
                if '@' in v: line_ids['email'] = v.lower()
                elif v.startswith('user_'): line_ids['user_id'] = v
                elif len(v) == 64 and HASH_RE.match(v): line_ids['email_hash'] = v.lower()
        for fld in ('subject_reference', 'subject_ref', 'user_id', 'customer_reference'):
            v = d.get(fld, '')
            if v and isinstance(v, str):
                if v.startswith('user_'): line_ids['user_id'] = v
                elif '@' in v: line_ids['email'] = v.lower()

        rid = d.get('resource_id', '')
        if tr:
            all_trace_keys[tr].update(line_ids)
            if rid: all_trace_rids[tr].add(rid)

        parsed_lines.append((ts, d, line_ids))

    obs = []
    for ts, d, line_ids in parsed_lines:
        rid = d.get('resource_id', '')
        tr = d.get('trace_id', '')

        merged_ids = dict(line_ids)
        if tr and tr in all_trace_keys:
            merged_ids.update(all_trace_keys[tr])

        if not rid:
            rids = all_trace_rids.get(tr, set())
            if len(rids) == 1:
                rid = next(iter(rids))
            else:
                continue

        event = str(d.get('event', '')).strip('"')
        svc = str(d.get('service', '')).strip('"')
        rtype, inferred_svc = rtype_from_rid(rid)
        if svc in ('unknown', '', 'log_router', 'support_replica'):
            svc = inferred_svc

        # Skip start events when we have a completed event for the same trace
        if event.endswith('_started') and any(p[1].get('trace_id') == tr and str(p[1].get('event','')).endswith('_completed') for p in parsed_lines):
            continue

        # Check marketing profile in analytics platform
        if event == 'contact_lookup_completed' or d.get('email_opt_in') in ('true', True):
            rtype = 'MARKETING_PROFILE'

        # Check support attachment in replica/storage check
        if rid.startswith('support_') and (d.get('marker_found') is not None or 'replica' in svc):
            rtype = 'SUPPORT_ATTACHMENT'

        rows = str(d.get('rows', ''))
        http = str(d.get('http_status', ''))
        result = str(d.get('result', '')).lower()
        direct_ids = str(d.get('direct_identifiers', ''))
        deletion_block = str(d.get('deletion_block', '')).lower()
        eligible = str(d.get('eligible', '')).lower()
        enabled = str(d.get('enabled', '')).lower()
        restore_allowed = str(d.get('restore_allowed', '')).lower()

        state = 'PRESENT'
        if rtype == 'BACKUP_ARCHIVE':
            if deletion_block == 'false' or eligible == 'true' or restore_allowed == 'true':
                state = 'ACTIVE'
            elif deletion_block == 'true' or restore_allowed == 'false':
                state = 'BLOCKED'
            else:
                state = 'ACTIVE'
        elif rtype == 'DATA_FLOW':
            if enabled == 'true':
                state = 'ACTIVE'
            elif enabled == 'false':
                state = 'DISABLED'
            else:
                state = 'ACTIVE'
        elif http == '404' or rows == '0' or result == 'miss':
            state = 'ABSENT'
        elif direct_ids == '0':
            state = 'ANONYMIZED'
        elif rtype in ('ANALYTICS_PROFILE', 'PRODUCT_TELEMETRY'):
            em = d.get('email')
            if em == 'null' or em is None or direct_ids == '0':
                state = 'ANONYMIZED'
            else:
                state = 'PRESENT'
        elif rtype in ('SUPPORT_MESSAGE', 'ACCOUNT_TOMBSTONE'):
            if d.get('requester_email') or d.get('email') or d.get('matched_value') or d.get('detector') or d.get('marker_found') == 'false' or rows == '1':
                state = 'PRESENT'
            else:
                state = 'REDACTED'
        elif rows == '1' or result == 'hit':
            state = 'PRESENT'

        obs.append(Observation(
            file_id=file_id, captured_at=ts,
            system_id=svc, resource_id=rid,
            record_type=rtype, state=state,
            identifiers=merged_ids, source_table='log', raw=d
        ))

    return obs


# ── TXT files ─────────────────────────────────────────────────────────────────

TXT_LINE = re.compile(
    r'^(?:[-*•]\s*)?(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s*\|\s*(\S+)\s*\|\s*(\S+)\s*\|\s*(\S+)\s*\|\s*(\S+)\s*(?:\|\s*(.+))?'
)

TXT_STATE_MAP = {
    'NOT_FOUND': 'ABSENT', 'FOUND': 'PRESENT', 'IDENTIFIABLE': 'PRESENT',
    'ANONYMIZED': 'ANONYMIZED', 'REDACTED': 'REDACTED',
    'ACTIVE': 'ACTIVE', 'BLOCKED': 'BLOCKED', 'DISABLED': 'DISABLED',
}

def parse_txt_file(file_id, path, file_cap):
    obs = []
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except Exception:
        return obs
    for line in lines:
        m = TXT_LINE.match(line.strip())
        if not m: continue
        ts, svc, rid, rtype, status, identifier = m.groups()
        state = TXT_STATE_MAP.get(status.upper(), 'PRESENT')
        ids = {}
        ident = (identifier or '').strip()
        if '@' in ident:
            ids['email'] = ident.lower()
        elif ident.startswith('user_'):
            ids['user_id'] = ident
        obs.append(Observation(
            file_id=file_id, captured_at=ts,
            system_id=svc, resource_id=rid,
            record_type=rtype, state=state,
            identifiers=ids, source_table='txt', raw={'line': line.strip()}
        ))
    return obs


# ── PDF files ─────────────────────────────────────────────────────────────────

def parse_pdf_file(file_id, path, file_cap):
    obs = []
    try:
        import pypdf
        reader = pypdf.PdfReader(path)
        full_text = '\n'.join(page.extract_text() or '' for page in reader.pages)
    except Exception:
        return obs

    emails = [e.lower() for e in EMAIL_RE.findall(full_text)]
    user_ids = re.findall(r'\buser_\d+\b', full_text)
    resource_ids = re.findall(r'\b(?:account|search|analytics|support|export|data_flow|backup|audit_record|marketing|object|tombstone)_\w+\b', full_text)

    ids = {}
    if emails: ids['email'] = emails[0]
    if user_ids: ids['user_id'] = user_ids[0]

    seen = set()
    for rid in resource_ids:
        if rid in seen: continue
        seen.add(rid)
        rtype, svc = rtype_from_rid(rid)
        if rid.startswith('support_'):
            rtype = 'SUPPORT_ATTACHMENT'
        obs.append(Observation(
            file_id=file_id, captured_at=file_cap,
            system_id=svc, resource_id=rid,
            record_type=rtype, state='PRESENT',
            identifiers=dict(ids),
            source_table='pdf', raw={'text_excerpt': full_text[:200]}
        ))
    return obs


# ── Index & Cache ─────────────────────────────────────────────────────────────

class EvidenceIndex:
    """Fast in-memory multi-key index over parsed Observations."""
    def __init__(self, observations):
        self.observations = observations
        self.by_email = defaultdict(list)
        self.by_user_id = defaultdict(list)
        self.by_email_hash = defaultdict(list)
        self.by_phone = defaultdict(list)
        self.by_resource_id = defaultdict(list)

        for o in observations:
            if o.resource_id:
                self.by_resource_id[o.resource_id].append(o)
            ids = o.identifiers or {}
            if ids.get('email'):
                self.by_email[ids['email'].lower()].append(o)
            if ids.get('user_id'):
                self.by_user_id[ids['user_id']].append(o)
            if ids.get('email_hash'):
                self.by_email_hash[ids['email_hash'].lower()].append(o)
            if ids.get('phone'):
                self.by_phone[ids['phone']].append(o)

    def get_user_resource_ids(self, identity):
        """Retrieve all known resource IDs grounded to this identity."""
        rids = set()
        for em in identity.emails:
            for o in self.by_email.get(em, []):
                rids.add(o.resource_id)
        if identity.user_id:
            for o in self.by_user_id.get(identity.user_id, []):
                rids.add(o.resource_id)
        for eh in identity.email_hashes:
            for o in self.by_email_hash.get(eh, []):
                rids.add(o.resource_id)
        for ph in identity.phones:
            for o in self.by_phone.get(ph, []):
                rids.add(o.resource_id)
        rids.update(identity.linked_resource_ids.keys())
        return rids

    def get_relevant(self, identity, extra_rids=None, audit_at=None):
        """Retrieve all observations matching identity or resource IDs, optionally filtered by audit_at."""
        res_set = set()
        for em in identity.emails:
            res_set.update(self.by_email.get(em, []))
        if identity.user_id:
            res_set.update(self.by_user_id.get(identity.user_id, []))
        for eh in identity.email_hashes:
            res_set.update(self.by_email_hash.get(eh, []))
        for ph in identity.phones:
            res_set.update(self.by_phone.get(ph, []))
        for rid in identity.linked_resource_ids:
            res_set.update(self.by_resource_id.get(rid, []))
        if extra_rids:
            for rid in extra_rids:
                res_set.update(self.by_resource_id.get(rid, []))

        if audit_at:
            return [o for o in res_set if o.captured_at <= audit_at]
        return list(res_set)


# ── Main loader ───────────────────────────────────────────────────────────────

def load_all_observations(dataset_dir='dataset', use_cache=True):
    cache_path = os.path.join(dataset_dir, '.evidence_cache.pkl')
    if use_cache and os.path.exists(cache_path):
        try:
            with open(cache_path, 'rb') as f:
                return pickle.load(f)
        except Exception:
            pass

    ef_path = os.path.join(dataset_dir, 'evidence_files.csv')
    with open(ef_path, newline='', encoding='utf-8') as f:
        ef_rows = list(csv.DictReader(f))

    all_obs = []
    for row in ef_rows:
        file_id = row['file_id']
        rel_path = row['file_path']
        file_cap = row['captured_at']
        path = os.path.join(dataset_dir, rel_path)
        if not os.path.exists(path):
            continue
        ext = os.path.splitext(path)[1].lower()
        fname = os.path.basename(path)

        if ext == '.sql':
            if 'inventory' in fname:
                obs = parse_inventory_sql(file_id, path)
            elif fname.startswith('customer_search_'):
                obs = parse_search_sql(file_id, path, file_cap)
            else:
                obs = parse_replica_sql(file_id, path, file_cap)
        elif ext == '.json':
            obs = parse_json_file(file_id, path, file_cap)
        elif ext == '.log':
            obs = parse_log_file(file_id, path, file_cap)
        elif ext == '.txt':
            obs = parse_txt_file(file_id, path, file_cap)
        elif ext == '.pdf':
            obs = parse_pdf_file(file_id, path, file_cap)
        else:
            obs = []

        all_obs.extend(obs)

    if use_cache:
        try:
            with open(cache_path, 'wb') as f:
                pickle.dump(all_obs, f, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception:
            pass

    return all_obs
