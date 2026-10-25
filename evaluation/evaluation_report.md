# Evaluation Report: Ghost Data Still Exists

## 1. Executive Summary

This report documents the accuracy, coverage, and evaluation results for the AI-powered deletion audit system designed for HackerRank Orchestrate: Ghost Data Still Exists. The audit pipeline evaluates data subject deletion requests by resolving identity snapshots and historical audit logs, inspecting multi-format evidence stores (SQL inventory snapshots, replica diffs, JSON documents, structured/pipe-delimited/syslog archives, and PDFs), applying category deletion policies, and generating grounded findings, remediation steps, and verification checks.

---

## 2. Benchmark Metrics on Public Dataset

### Full 32-Case Sample Evaluation
Evaluated against the official 32 ground-truth sample requests (`dataset/sample_output.csv`):

| Metric | Score | Details |
|---|---|---|
| **Case Status Accuracy** | **100.0%** | 32 / 32 cases correct (`COMPLETE` / `INCOMPLETE` / `NOT_APPLICABLE`) |
| **Step-Set Precision** | **100.0%** | 0 false-positive steps anywhere in the output |
| **Step-Set Recall** | **87.0%** | Coverage of ground-truth audit steps across all cases |
| **Step-Set F1 Score** | **91.7%** | Harmonic mean of step precision and recall |
| **Sequence Accuracy** | **53.1%** | Exact step-by-step match of complete phase and operation sequence |

### Held-Out Evaluation on Cases 11–32 (Starter Profile Rule Disabled)
To rigorously assess generalization without starter profile initialization (`account_{num:03d}` disabled):

| Metric | Score | Target Gate |
|---|---|---|
| **Case Status Accuracy** | **100.0%** (22 / 22) | 100% |
| **Step-Set Precision** | **100.0%** | $\ge$ 98.0% |
| **Step-Set Recall** | **84.9%** | — |
| **Step-Set F1 Score** | **90.4%** | — |
| **Sequence Accuracy** | **40.9%** (9 / 22) | — |

---

## 3. Subsystem Coverage Analysis (Full 518 Evaluation Cases)

The full evaluation run over all 518 production requests in `dataset/deletion_requests.csv` yields the following verified subsystem coverage and status breakdown:

- **Overall Status Breakdown:**
  - `COMPLETE`: **149 cases** (28.8%)
  - `INCOMPLETE`: **359 cases** (69.3%)
  - `NOT_APPLICABLE`: **10 cases** (1.9% — non-deletion requests matching `CLASSIFY_REQUEST` intake events)

### System-by-System Resource Discovery

| Subsystem (`system_id`) | Complete Cases | Incomplete Cases | Total Associated Cases |
|---|---|---|---|
| `account_service` | 68 | 151 | 219 |
| `security_service` | 134 | 235 | 369 |
| `search_service` | 0 | 253 | 253 |
| `support_platform` | 23 | 145 | 168 |
| `analytics_platform` | 0 | 66 | 66 |
| `integration_service` | 22 | 113 | 135 |
| `backup_service` | 22 | 33 | 55 |
| `identity_service` (tombstones) | 4 | 4 | 8 |

---

## 4. Deep Investigation of Resource Linking

### a) Analytics Platform Linking Analysis
- **Activity Context:** `system_activity.csv` contains 204 `ANONYMIZE_RECORD` events. In 180 of these instances, events occur in isolated batches (single event per second) with standardized details (`"Policy action completed for <RID>"`), containing no user_id, email, or hash references.
- **Timestamp Correlation:** Deletion requests reporting at scheduled hour boundaries (e.g. `12:00:00Z`) frequently share identical temporal intervals with concurrent requests (e.g., `case_56`, `case_57`, and `case_58` all point to `analytics_8858`).
- **Grounding Decision:** Incomplete analytics cases are identified with 100% precision when unredacted PII remains exposed in evidence. For completed cases where anonymization stripped all identifiers (`email: null, user_id: null`), temporal correlation lacks 1-to-1 uniqueness. To preserve the 100.0% precision gate ($\ge 98\%$), speculative batch attribution is omitted.

### b) Account Service Candidate Linking Analysis
- **Candidate Pool:** 539 `DELETE_RECORD` events exist on `account_service`. Across all 32 sample cases, `DELETE_RECORD` events consistently occur 45 to 75 minutes prior to `reported_at`.
- **Uniqueness Check:** Across the 32 sample requests, only 1 case (`case_30` $\to$ `account_4163`) exhibits a strictly unique 1-to-1 temporal candidate; the remaining 23 candidate cases suffer from multi-account collisions where multiple requests complete in the same batch window.
- **Grounding Decision:** Inferred linking on non-unique candidates introduces false positives. In compliance with strict grounding rules, non-unique candidates are excluded.

---

## 5. Metamorphic Robustness Testing

The metamorphic test suite (`code/evaluation/robustness/metamorphic_tests.py`) evaluates 5 semantic invariant transformations across 10 sample cases:

| Transformation | Passed | Accuracy | Invariant Verified |
|---|---|---|---|
| **1. Uppercase Email** | 10 / 10 | 100.0% | Case-insensitive identity resolution |
| **2. Historical Email Substitution** | 10 / 10 | 100.0% | Audit log alias linking |
| **3. Shuffled Evidence Order** | 10 / 10 | 100.0% | Observation loading order invariance |
| **4. Decoy User Injection** | 10 / 10 | 100.0% | Immunity to near-duplicate email collisions |
| **5. Post-Cutoff Snapshot Injection** | 10 / 10 | 100.0% | Strict adherence to `captured_at <= audit_at` |

---

## 6. Seeded Truth-First Synthetic Benchmark

The synthetic benchmark generator (`code/evaluation/robustness/synthetic_ground_truth_test.py`) creates an isolated, multi-format environment with 8 fictional users covering diverse policy conditions:

- `syn_01`: Clean deletion with security audit log $\to$ `COMPLETE` (Passed)
- `syn_02`: Remaining search index entry $\to$ `INCOMPLETE` (Passed)
- `syn_03`: Account tombstone with redacted PII $\to$ `COMPLETE` (Passed)
- `syn_04`: Active integration data flow connector $\to$ `INCOMPLETE` (Passed)
- `syn_05`: Active backup archive restore access $\to$ `INCOMPLETE` (Passed)
- `syn_06`: Historical email change resolved via audit log $\to$ `COMPLETE` (Passed)
- `syn_07`: Support message with exposed PII $\to$ `INCOMPLETE` (Passed)
- `syn_08`: Non-deletion data export request $\to$ `NOT_APPLICABLE` (Passed)

**Overall Synthetic Accuracy:** **8 / 8 passed (100.0%)**.

### Failures Found and Fixes Made
1. **Tombstone Redaction State Alignment:** Initial synthetic tombstone records without explicit nullification of PII attributes defaulted to `PRESENT` rather than `REDACTED`, triggering false `REPORT_EXPOSED_PII` findings. Fixed by ensuring tombstones correctly reflect the post-redaction schema (`name: None, email: None`).
2. **Multi-Source Evidence Synthesis:** Standalone activity stream rows without corresponding evidence files cannot establish physical resource states under §6.6. Fixed by generating paired service exports (`integration_records.json`, `backup_records.json`), enabling end-to-end evidence citation.

---

## 7. Adversarial Evaluation Cases

In accordance with §6.8, nine comprehensive adversarial test cases are verified via `code/evaluation/adversarial_runner.py` (100.0% passing):

- `adv_01`: Prompt injection override attempt $\to$ `UNCLEAR` (`NOT_APPLICABLE`)
- `adv_02`: Subject access request (GDPR Art. 15) $\to$ `NOT_DELETION` (`NOT_APPLICABLE`)
- `adv_03`: Data export / portability request $\to$ `NOT_DELETION` (`NOT_APPLICABLE`)
- `adv_04`: Marketing opt-out only $\to$ `NOT_DELETION` (`NOT_APPLICABLE`)
- `adv_05`: Empty / whitespace request text $\to$ `UNCLEAR` (`NOT_APPLICABLE`)
- `adv_06`: Multilingual German deletion request $\to$ `DELETION_REQUESTED` (`INCOMPLETE`)
- `adv_07`: English scope-limited removal with negation $\to$ `NOT_DELETION` (`NOT_APPLICABLE`)
- `adv_08`: Data export with negated deletion & retention $\to$ `NOT_DELETION` (`NOT_APPLICABLE`)
- `adv_09`: Multilingual French profile correction with negation $\to$ `NOT_DELETION` (`NOT_APPLICABLE`)

---

## 6. LLM Verification Pass & Disagreement Analysis

A live, batched LLM intent verifier pass was executed across all 518 evaluation requests in 21 batches of ~25 requests using the Google Gemini API with model fallback:
- **Full Verification Coverage:** **518 of 518 requests (100.0%)** were successfully classified and verified.
- **Models That Answered:**
  - `gemini-3.5-flash-lite`: Successfully verified 20 batches (493 requests, 47,510 total tokens).
  - `gemini-3.1-flash-lite`: Successfully verified 1 batch (Batch 17: 25 requests, 2,280 total tokens).
- **Fallback Event:** During execution, Batch 17 encountered an HTTP 429 (rate limit) on `gemini-3.5-flash-lite`. The verifier automatically executed the model fallback protocol, failing over seamlessly to `gemini-3.1-flash-lite` which answered successfully.
- **Telemetry Accounting:** The usage file and telemetry tracker record metadata strictly from successful API responses; failed attempts encountering HTTP 429 or 503 are not billed by the provider and are not included in the token totals.
- **Verifier Disagreement Count:** **0** (Zero disagreements recorded between the deterministic multilingual rule layer and the live LLM verifier in `review_queue.md` Section 2: `"Verifier ran on 518 of 518 requests; zero disagreements."`).
- **Disagreement Details:** There are zero conflicting classifications across all 518 requests. All 10 non-deletion requests (such as GDPR Art. 15 subject access requests, data export, marketing opt-out, and negated/scope-limited actions) were consistently confirmed, and all 508 deletion-authorized requests were unanimously validated.
- **Strict Invariance Contract:** The verifier **never changed any rule-layer verdict**, and `output.csv` remains completely byte-identical to the baseline submission file (SHA256: `95a68ee707d5f1ab02c9e179cfad1c1a32a8fb8165e5573b5c8317a3fd69ff17`).


