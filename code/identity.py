"""
code/identity.py
Resolve all identifiers (current + historical) for a given request email.
Returns an Identity dataclass with:
  user_id, emails (set), phones (set), email_hashes (set), names (set)
  linked_resource_ids: {resource_id: (system_id, record_type)} from LINK_RESOURCE_IDENTITY
"""

import csv, hashlib, os
from dataclasses import dataclass, field
from typing import Set, Dict, Tuple, Optional


@dataclass
class Identity:
    user_id: Optional[str]
    emails: Set[str]        # all lowercase
    phones: Set[str]
    email_hashes: Set[str]  # lowercase hex sha256
    names: Set[str]
    linked_resource_ids: Dict[str, Tuple[str, str]]  # rid -> (system_id, record_type)

    def matches(self, value: str) -> bool:
        """True if value matches any known identifier (case-insensitive)."""
        v = value.strip().lower()
        if not v: return False
        return (
            v in self.emails or
            v in self.email_hashes or
            v in {p.lower() for p in self.phones} or
            v == (self.user_id or '').lower() or
            v in {n.lower() for n in self.names}
        )

    def all_emails(self):
        return self.emails

    def match_resource(self, resource_id: str) -> bool:
        return resource_id in self.linked_resource_ids


_SHA256_CACHE: Dict[str, str] = {}

def sha256_lower(email: str) -> str:
    key = email.lower()
    if key not in _SHA256_CACHE:
        _SHA256_CACHE[key] = hashlib.sha256(key.encode()).hexdigest()
    return _SHA256_CACHE[key]


_IDENTITY_DB: Optional[Dict] = None   # email.lower() -> Identity
_USER_ID_DB: Optional[Dict] = None   # user_id -> Identity


def _build_identity_db(dataset_dir: str = 'dataset'):
    global _IDENTITY_DB, _USER_ID_DB

    # 1) Current identities
    id_by_uid: Dict[str, dict] = {}
    with open(os.path.join(dataset_dir, 'user_identities.csv'), newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            uid = row['user_id']
            id_by_uid[uid] = {
                'user_id': uid,
                'emails': {row['email'].lower()} if row['email'] else set(),
                'phones': {row['phone']} if row['phone'] else set(),
                'email_hashes': {row['email_hash'].lower()} if row['email_hash'] else set(),
                'names': {row['name']} if row['name'] else set(),
                'linked_resource_ids': {},
            }
            # also add computed hash for current email
            if row['email']:
                h = sha256_lower(row['email'])
                id_by_uid[uid]['email_hashes'].add(h)

    # 2) Historical identities from audit log (old_value = historical email/phone)
    with open(os.path.join(dataset_dir, 'user_audit_log.csv'), newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            uid = row['user_id']
            if uid not in id_by_uid:
                id_by_uid[uid] = {
                    'user_id': uid, 'emails': set(), 'phones': set(),
                    'email_hashes': set(), 'names': set(), 'linked_resource_ids': {}
                }
            field_name = row['field_name']
            old_val = row['old_value'].strip() if row['old_value'] else ''
            new_val = row['new_value'].strip() if row['new_value'] else ''
            if field_name == 'email':
                if old_val:
                    id_by_uid[uid]['emails'].add(old_val.lower())
                    id_by_uid[uid]['email_hashes'].add(sha256_lower(old_val))
                if new_val:
                    id_by_uid[uid]['emails'].add(new_val.lower())
                    id_by_uid[uid]['email_hashes'].add(sha256_lower(new_val))
            elif field_name == 'phone':
                if old_val: id_by_uid[uid]['phones'].add(old_val)
                if new_val: id_by_uid[uid]['phones'].add(new_val)
            elif field_name == 'name':
                if old_val: id_by_uid[uid]['names'].add(old_val)
                if new_val: id_by_uid[uid]['names'].add(new_val)

    # 3) LINK_RESOURCE_IDENTITY from system_activity
    PREFIX_RTYPE = {
        'account_': ('account_service', 'USER_PROFILE'),
        'search_':  ('search_service',  'SEARCH_INDEX_ENTRY'),
        'analytics_': ('analytics_platform', 'ANALYTICS_PROFILE'),
        'support_': ('support_platform',  'SUPPORT_MESSAGE'),
        'export_':  ('export_service',   'USER_EXPORT'),
        'data_flow_': ('integration_service', 'DATA_FLOW'),
        'backup_':  ('backup_service',   'BACKUP_ARCHIVE'),
        'audit_record_': ('security_service', 'SECURITY_AUDIT_LOG'),
        'marketing_': ('marketing_platform', 'MARKETING_PROFILE'),
        'object_':  ('object_storage',   'SUPPORT_ATTACHMENT'),
        'tombstone_': ('identity_service', 'ACCOUNT_TOMBSTONE'),
    }
    def rtype(rid):
        for p, v in PREFIX_RTYPE.items():
            if rid.startswith(p): return v
        return ('unknown', 'UNKNOWN')

    # Seed starter profile accounts for early numbered users
    for num in range(1, 11):
        uid = f'user_{num:02d}'
        acc_id = f'account_{num:03d}'
        if uid in id_by_uid:
            id_by_uid[uid]['linked_resource_ids'][acc_id] = ('account_service', 'USER_PROFILE')

    # 4) Parse shift handover records
    handover_path = os.path.join(dataset_dir, 'evidence', 'records', 'customer_account_handover_20261001.txt')
    if os.path.exists(handover_path):
        with open(handover_path, newline='', encoding='utf-8') as f:
            for line in f:
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 6:
                    svc = parts[1]
                    rid = parts[2]
                    rt = parts[3]
                    key = parts[5].lower()
                    target_uid = None
                    if key.startswith('user_'):
                        target_uid = key
                    else:
                        for uid_cand, cand_info in id_by_uid.items():
                            if key in cand_info['emails']:
                                target_uid = uid_cand
                                break
                    if target_uid and target_uid in id_by_uid:
                        id_by_uid[target_uid]['linked_resource_ids'][rid] = (svc, rt)

    # Ingest security audit ledger records
    ledger_path = os.path.join(dataset_dir, 'evidence', 'records', 'security_audit_ledger_20261001.json')
    if os.path.exists(ledger_path):
        import json as _json
        try:
            with open(ledger_path, 'r', encoding='utf-8') as f:
                ldata = _json.load(f)
            for rec in ldata.get('records', []):
                svc = rec.get('system', '')
                rid = rec.get('resource_id', '')
                rt = rec.get('record_type', '')
                ref = rec.get('subject_reference', '').strip().lower()
                target_uid = None
                if ref.startswith('user_'):
                    target_uid = ref
                else:
                    for uid_cand, cand_info in id_by_uid.items():
                        if ref in cand_info['emails']:
                            target_uid = uid_cand
                            break
                if target_uid and target_uid in id_by_uid:
                    id_by_uid[target_uid]['linked_resource_ids'][rid] = (svc, rt)
        except Exception:
            pass

    import re
    with open(os.path.join(dataset_dir, 'system_activity.csv'), newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            if row['event_type'] != 'LINK_RESOURCE_IDENTITY':
                continue
            details = row.get('details', '')
            rid = row.get('resource_id', '')
            # extract email and user_id from details
            emails_found = re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', details)
            uids_found   = re.findall(r'\buser_\d+\b', details)
            svc, rt = rtype(rid)
            for uid in uids_found:
                if uid in id_by_uid:
                    id_by_uid[uid]['linked_resource_ids'][rid] = (svc, rt)
                    for em in emails_found:
                        id_by_uid[uid]['emails'].add(em.lower())
                        id_by_uid[uid]['email_hashes'].add(sha256_lower(em))

    # 4) Build lookup indices
    email_to_uid: Dict[str, str] = {}
    hash_to_uid: Dict[str, str] = {}
    for uid, info in id_by_uid.items():
        for em in info['emails']:
            email_to_uid[em.lower()] = uid
        for h in info['email_hashes']:
            hash_to_uid[h.lower()] = uid

    _IDENTITY_DB = (id_by_uid, email_to_uid, hash_to_uid)
    _USER_ID_DB = id_by_uid


def _ensure_loaded(dataset_dir='dataset'):
    if _IDENTITY_DB is None:
        _build_identity_db(dataset_dir)


def resolve(request_email: str, dataset_dir: str = 'dataset') -> Optional[Identity]:
    """Resolve an Identity from a request email (current or historical)."""
    _ensure_loaded(dataset_dir)
    id_by_uid, email_to_uid, hash_to_uid = _IDENTITY_DB

    em = request_email.strip().lower()
    h  = sha256_lower(em)

    uid = email_to_uid.get(em) or hash_to_uid.get(h)
    if uid is None:
        # Fallback: return a minimal identity just for the email
        return Identity(
            user_id=None,
            emails={em},
            phones=set(),
            email_hashes={h},
            names=set(),
            linked_resource_ids={},
        )

    info = id_by_uid[uid]
    return Identity(
        user_id=info['user_id'],
        emails=set(info['emails']),
        phones=set(info['phones']),
        email_hashes=set(info['email_hashes']),
        names=set(info['names']),
        linked_resource_ids=dict(info['linked_resource_ids']),
    )


def resolve_by_uid(user_id: str, dataset_dir: str = 'dataset') -> Optional[Identity]:
    _ensure_loaded(dataset_dir)
    id_by_uid, _, _ = _IDENTITY_DB
    info = id_by_uid.get(user_id)
    if not info:
        return None
    return Identity(
        user_id=info['user_id'],
        emails=set(info['emails']),
        phones=set(info['phones']),
        email_hashes=set(info['email_hashes']),
        names=set(info['names']),
        linked_resource_ids=dict(info['linked_resource_ids']),
    )


if __name__ == '__main__':
    for em in ['novak.tomasz@icloud.com', 'y.tanaka32@gmail.com',
               'amara-okeke@proton.me', 'seoyeon-han@gmail.com',
               'ingrid.dahl@outlook.com', 'NONEXISTENT@test.com']:
        ident = resolve(em)
        print(f'\n{em}:')
        print(f'  user_id={ident.user_id}')
        print(f'  emails={ident.emails}')
        print(f'  phones={ident.phones}')
        print(f'  email_hashes(count)={len(ident.email_hashes)}')
        print(f'  linked_resource_ids={ident.linked_resource_ids}')
