"""
code/evaluation/robustness/synthetic_ground_truth_test.py
Seeded truth-first generator creating 8 fictional users with verifiable ground truth.

Test Cases:
  1. syn_01: Standard clean deletion -> COMPLETE
  2. syn_02: Ghost search index record remaining -> INCOMPLETE
  3. syn_03: Account tombstone preserved with stable user_id -> COMPLETE
  4. syn_04: Active data flow connector enabled -> INCOMPLETE
  5. syn_05: Backup restore access enabled -> INCOMPLETE
  6. syn_06: Historical email change in audit log -> COMPLETE
  7. syn_07: Support message with exposed PII -> INCOMPLETE
  8. syn_08: Non-deletion data export request -> NOT_APPLICABLE
"""

import os, sys, csv, json, tempfile, shutil
sys.path.insert(0, os.path.abspath('code'))

from main import audit_case, classify_request, DELETION_REQUESTED
from identity import _build_identity_db, resolve
from evidence_parsers import load_all_observations, Observation
from validator import validate_rows


def generate_synthetic_benchmark():
    temp_dir = tempfile.mkdtemp(prefix='synth_bench_')

    try:
        # Create subdirectories
        ev_dir = os.path.join(temp_dir, 'evidence')
        records_dir = os.path.join(ev_dir, 'records')
        dbs_dir = os.path.join(ev_dir, 'databases')
        os.makedirs(records_dir, exist_ok=True)
        os.makedirs(dbs_dir, exist_ok=True)

        # 1. deletion_rules.csv
        rules_csv = os.path.join(temp_dir, 'deletion_rules.csv')
        shutil.copy('dataset/deletion_rules.csv', rules_csv)

        # 2. user_identities.csv
        identities = [
            {'user_id': 'user_s01', 'name': 'Alice Smith', 'email': 'alice.s01@example.com', 'phone': '+1 555 0101', 'email_hash': 'hash_s01', 'snapshot_at': '2026-09-01T12:00:00Z'},
            {'user_id': 'user_s02', 'name': 'Bob Jones', 'email': 'bob.s02@example.com', 'phone': '+1 555 0102', 'email_hash': 'hash_s02', 'snapshot_at': '2026-09-01T12:00:00Z'},
            {'user_id': 'user_s03', 'name': 'Charlie Lee', 'email': 'charlie.s03@example.com', 'phone': '+1 555 0103', 'email_hash': 'hash_s03', 'snapshot_at': '2026-09-01T12:00:00Z'},
            {'user_id': 'user_s04', 'name': 'Dana White', 'email': 'dana.s04@example.com', 'phone': '+1 555 0104', 'email_hash': 'hash_s04', 'snapshot_at': '2026-09-01T12:00:00Z'},
            {'user_id': 'user_s05', 'name': 'Evan Brown', 'email': 'evan.s05@example.com', 'phone': '+1 555 0105', 'email_hash': 'hash_s05', 'snapshot_at': '2026-09-01T12:00:00Z'},
            {'user_id': 'user_s06', 'name': 'Fiona Clark', 'email': 'fiona.new@example.com', 'phone': '+1 555 0106', 'email_hash': 'hash_s06_new', 'snapshot_at': '2026-09-01T12:00:00Z'},
            {'user_id': 'user_s07', 'name': 'George Davis', 'email': 'george.s07@example.com', 'phone': '+1 555 0107', 'email_hash': 'hash_s07', 'snapshot_at': '2026-09-01T12:00:00Z'},
            {'user_id': 'user_s08', 'name': 'Hannah Evans', 'email': 'hannah.s08@example.com', 'phone': '+1 555 0108', 'email_hash': 'hash_s08', 'snapshot_at': '2026-09-01T12:00:00Z'},
        ]
        with open(os.path.join(temp_dir, 'user_identities.csv'), 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['user_id', 'name', 'email', 'phone', 'email_hash', 'snapshot_at'])
            writer.writeheader()
            writer.writerows(identities)

        # 3. user_audit_log.csv
        audit_logs = [
            {'user_id': 'user_s06', 'field_name': 'email', 'old_value': 'fiona.old@example.com', 'new_value': 'fiona.new@example.com', 'changed_at': '2026-08-01T10:00:00Z'}
        ]
        with open(os.path.join(temp_dir, 'user_audit_log.csv'), 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['user_id', 'field_name', 'old_value', 'new_value', 'changed_at'])
            writer.writeheader()
            writer.writerows(audit_logs)

        # 4. deletion_requests.csv
        requests = [
            {'case_id': 'syn_01', 'email': 'alice.s01@example.com', 'requested_at': '2026-09-01T10:00:00Z', 'reported_status': 'COMPLETE', 'reported_at': '2026-09-02T10:00:00Z', 'audit_at': '2026-09-03T12:00:00Z', 'request_text': 'Please delete my account and all data.'},
            {'case_id': 'syn_02', 'email': 'bob.s02@example.com', 'requested_at': '2026-09-01T10:00:00Z', 'reported_status': 'COMPLETE', 'reported_at': '2026-09-02T10:00:00Z', 'audit_at': '2026-09-03T12:00:00Z', 'request_text': 'Please permanently erase my account.'},
            {'case_id': 'syn_03', 'email': 'charlie.s03@example.com', 'requested_at': '2026-09-01T10:00:00Z', 'reported_status': 'COMPLETE', 'reported_at': '2026-09-02T10:00:00Z', 'audit_at': '2026-09-03T12:00:00Z', 'request_text': 'Please process account tombstone deletion.'},
            {'case_id': 'syn_04', 'email': 'dana.s04@example.com', 'requested_at': '2026-09-01T10:00:00Z', 'reported_status': 'COMPLETE', 'reported_at': '2026-09-02T10:00:00Z', 'audit_at': '2026-09-03T12:00:00Z', 'request_text': 'Please delete all account integrations and data.'},
            {'case_id': 'syn_05', 'email': 'evan.s05@example.com', 'requested_at': '2026-09-01T10:00:00Z', 'reported_status': 'COMPLETE', 'reported_at': '2026-09-02T10:00:00Z', 'audit_at': '2026-09-03T12:00:00Z', 'request_text': 'Please delete my account and purge backup references.'},
            {'case_id': 'syn_06', 'email': 'fiona.old@example.com', 'requested_at': '2026-09-01T10:00:00Z', 'reported_status': 'COMPLETE', 'reported_at': '2026-09-02T10:00:00Z', 'audit_at': '2026-09-03T12:00:00Z', 'request_text': 'Please erase my account associated with this old email.'},
            {'case_id': 'syn_07', 'email': 'george.s07@example.com', 'requested_at': '2026-09-01T10:00:00Z', 'reported_status': 'COMPLETE', 'reported_at': '2026-09-02T10:00:00Z', 'audit_at': '2026-09-03T12:00:00Z', 'request_text': 'Please remove my account and support history.'},
            {'case_id': 'syn_08', 'email': 'hannah.s08@example.com', 'requested_at': '2026-09-01T10:00:00Z', 'reported_status': 'COMPLETE', 'reported_at': '2026-09-02T10:00:00Z', 'audit_at': '2026-09-03T12:00:00Z', 'request_text': 'I need an export of my account data. Do not close or delete the account.'},
        ]
        with open(os.path.join(temp_dir, 'deletion_requests.csv'), 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['case_id', 'email', 'requested_at', 'reported_status', 'reported_at', 'audit_at', 'request_text'])
            writer.writeheader()
            writer.writerows(requests)

        # 5. system_activity.csv
        activities = [
            {'activity_id': 'act_s01', 'event_time': '2026-09-02T08:00:00Z', 'event_type': 'LINK_RESOURCE_IDENTITY', 'source_system': 'catalog', 'target_system': 'catalog', 'resource_id': 'account_s01', 'reported_result': 'SUCCESS', 'details': 'Linked account_s01 to alice.s01@example.com and user_s01.'},
            {'activity_id': 'act_s02', 'event_time': '2026-09-02T08:00:00Z', 'event_type': 'LINK_RESOURCE_IDENTITY', 'source_system': 'catalog', 'target_system': 'catalog', 'resource_id': 'search_s02', 'reported_result': 'SUCCESS', 'details': 'Linked search_s02 to bob.s02@example.com and user_s02.'},
            {'activity_id': 'act_s03', 'event_time': '2026-09-02T08:00:00Z', 'event_type': 'LINK_RESOURCE_IDENTITY', 'source_system': 'catalog', 'target_system': 'catalog', 'resource_id': 'tombstone_s03', 'reported_result': 'SUCCESS', 'details': 'Linked tombstone_s03 to charlie.s03@example.com and user_s03.'},
            {'activity_id': 'act_s04', 'event_time': '2026-09-02T08:00:00Z', 'event_type': 'LINK_RESOURCE_IDENTITY', 'source_system': 'catalog', 'target_system': 'catalog', 'resource_id': 'data_flow_s04', 'reported_result': 'SUCCESS', 'details': 'Linked data_flow_s04 to dana.s04@example.com and user_s04.'},
            {'activity_id': 'act_s05', 'event_time': '2026-09-02T08:00:00Z', 'event_type': 'LINK_RESOURCE_IDENTITY', 'source_system': 'catalog', 'target_system': 'catalog', 'resource_id': 'backup_s05', 'reported_result': 'SUCCESS', 'details': 'Linked backup_s05 to evan.s05@example.com and user_s05.'},
            {'activity_id': 'act_s06', 'event_time': '2026-09-02T08:00:00Z', 'event_type': 'LINK_RESOURCE_IDENTITY', 'source_system': 'catalog', 'target_system': 'catalog', 'resource_id': 'account_s06', 'reported_result': 'SUCCESS', 'details': 'Linked account_s06 to fiona.new@example.com and user_s06.'},
            {'activity_id': 'act_s07', 'event_time': '2026-09-02T08:00:00Z', 'event_type': 'LINK_RESOURCE_IDENTITY', 'source_system': 'catalog', 'target_system': 'catalog', 'resource_id': 'support_s07', 'reported_result': 'SUCCESS', 'details': 'Linked support_s07 to george.s07@example.com and user_s07.'},
            {'activity_id': 'act_s08', 'event_time': '2026-09-02T08:00:00Z', 'event_type': 'CLASSIFY_REQUEST', 'source_system': 'privacy_intake', 'target_system': 'privacy_case_management', 'resource_id': 'account_s08', 'reported_result': 'SUCCESS', 'details': 'Privacy intake classified request for account_s08 as non-deletion; no destructive action was authorized.'},
        ]
        with open(os.path.join(temp_dir, 'system_activity.csv'), 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['activity_id', 'event_time', 'event_type', 'source_system', 'target_system', 'resource_id', 'reported_result', 'details'])
            writer.writeheader()
            writer.writerows(activities)

        # 6. evidence_files.csv
        ev_manifest = [
            {'file_id': 'ev_s01', 'file_path': 'evidence/records/audit_records.json', 'origin': 'security_audit', 'captured_at': '2026-09-02T12:00:00Z'},
            {'file_id': 'ev_s02', 'file_path': 'evidence/records/search_records.json', 'origin': 'search_index', 'captured_at': '2026-09-02T12:00:00Z'},
            {'file_id': 'ev_s03', 'file_path': 'evidence/records/support_records.json', 'origin': 'support_messages', 'captured_at': '2026-09-02T12:00:00Z'},
            {'file_id': 'ev_s04', 'file_path': 'evidence/records/integration_records.json', 'origin': 'integration_service', 'captured_at': '2026-09-02T12:00:00Z'},
            {'file_id': 'ev_s05', 'file_path': 'evidence/records/backup_records.json', 'origin': 'backup_service', 'captured_at': '2026-09-02T12:00:00Z'},
        ]
        with open(os.path.join(temp_dir, 'evidence_files.csv'), 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['file_id', 'file_path', 'origin', 'captured_at'])
            writer.writeheader()
            writer.writerows(ev_manifest)

        # Evidence files:
        # ev_s01: security audit log and tombstones
        ev_s01_data = {
            'records': [
                {'system': 'security_service', 'resource_id': 'audit_record_s01', 'record_type': 'SECURITY_AUDIT_LOG', 'result': 'FOUND', 'subject_reference': 'user_s01'},
                {'system': 'identity_service', 'resource_id': 'tombstone_s03', 'record_type': 'ACCOUNT_TOMBSTONE', 'result': 'REDACTED', 'subject_reference': 'user_s03'},
                {'system': 'security_service', 'resource_id': 'audit_record_s06', 'record_type': 'SECURITY_AUDIT_LOG', 'result': 'FOUND', 'subject_reference': 'user_s06'},
            ]
        }
        with open(os.path.join(temp_dir, 'evidence', 'records', 'audit_records.json'), 'w', encoding='utf-8') as f:
            json.dump(ev_s01_data, f)

        # ev_s02: ghost search index entry for user_s02
        ev_s02_data = {
            'records': [
                {'system': 'search_service', 'resource_id': 'search_s02', 'record_type': 'SEARCH_INDEX_ENTRY', 'result': 'FOUND', 'subject_reference': 'bob.s02@example.com'}
            ]
        }
        with open(os.path.join(temp_dir, 'evidence', 'records', 'search_records.json'), 'w', encoding='utf-8') as f:
            json.dump(ev_s02_data, f)

        # ev_s03: unredacted support ticket for user_s07
        ev_s03_data = {
            'records': [
                {'system': 'support_platform', 'resource_id': 'support_s07', 'record_type': 'SUPPORT_MESSAGE', 'result': 'FOUND', 'subject_reference': 'george.s07@example.com', 'message': 'Customer george.s07@example.com requested invoice copy.'}
            ]
        }
        with open(os.path.join(temp_dir, 'evidence', 'records', 'support_records.json'), 'w', encoding='utf-8') as f:
            json.dump(ev_s03_data, f)

        # ev_s04: active data flow connector for user_s04
        ev_s04_data = {
            'records': [
                {'system': 'integration_service', 'resource_id': 'data_flow_s04', 'record_type': 'DATA_FLOW', 'result': 'ACTIVE', 'subject_reference': 'user_s04'}
            ]
        }
        with open(os.path.join(temp_dir, 'evidence', 'records', 'integration_records.json'), 'w', encoding='utf-8') as f:
            json.dump(ev_s04_data, f)

        # ev_s05: active backup archive restore risk for user_s05
        ev_s05_data = {
            'records': [
                {'system': 'backup_service', 'resource_id': 'backup_s05', 'record_type': 'BACKUP_ARCHIVE', 'result': 'ACTIVE', 'subject_reference': 'user_s05'}
            ]
        }
        with open(os.path.join(temp_dir, 'evidence', 'records', 'backup_records.json'), 'w', encoding='utf-8') as f:
            json.dump(ev_s05_data, f)

        # Expected Ground Truth
        expected = {
            'syn_01': 'COMPLETE',       # Clean audit log present
            'syn_02': 'INCOMPLETE',     # Ghost search record remaining
            'syn_03': 'COMPLETE',       # Tombstone verified present per policy
            'syn_04': 'INCOMPLETE',     # Active data flow connector
            'syn_05': 'INCOMPLETE',     # Active restore access
            'syn_06': 'COMPLETE',       # Historical email resolved to user_s06 audit log
            'syn_07': 'INCOMPLETE',     # Unredacted support message PII
            'syn_08': 'NOT_APPLICABLE'  # Non-deletion export request
        }

        print("\n=== Running Seeded Truth-First Synthetic Benchmark (8 Cases) ===")
        all_obs = load_all_observations(temp_dir, use_cache=False)
        sa_rows = activities

        passed = 0
        total = len(requests)

        for req in requests:
            cid = req['case_id']
            email = req['email']
            text = req['request_text']
            exp_status = expected[cid]

            ident = resolve(email, temp_dir)
            intent = classify_request(text, has_classify_activity=(cid == 'syn_08'))

            if intent != DELETION_REQUESTED:
                act_status = 'NOT_APPLICABLE'
                steps = []
            else:
                act_status, steps, _ = audit_case(req, all_obs, ident, sa_rows=sa_rows)

            match = (act_status == exp_status)
            if match:
                passed += 1
                print(f"  [PASS] {cid}: expected {exp_status} -> got {act_status} ({len(steps)} steps)")
            else:
                print(f"  [FAIL] {cid}: expected {exp_status} -> got {act_status} ({len(steps)} steps)")

        print(f"\nSynthetic Benchmark Accuracy: {passed}/{total} ({(passed/total)*100:.1f}%)")
        return passed == total

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == '__main__':
    ok = generate_synthetic_benchmark()
    sys.exit(0 if ok else 1)
