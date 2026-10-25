"""
code/review_queue.py
Generates review_queue.md for flagging cases requiring human review:
- Ambiguous identities (multiple accounts, historical email changes)
- Evidence replication drift (e.g. replica present while primary deleted)
- Active restore / data flow risks
- Intent classifier verifier disagreements
"""

import os, datetime

REVIEW_QUEUE_FILE = 'review_queue.md'

def generate_review_queue(cases_flagged, verifier_disagreements=None, verified_count=0, output_path=REVIEW_QUEUE_FILE):
    """Write review_queue.md documenting flagged cases and LLM verifier disagreements."""
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    lines = [
        "# Deletion Audit Review Queue",
        "",
        f"**Generated:** {now}",
        f"**Flagged Structural Cases:** {len(cases_flagged)}",
        f"**Verifier Disagreements:** {len(verifier_disagreements or [])}",
        "",
        "This queue documents audit cases with potential identity ambiguities, replication drift,",
        "multi-source conflicts, or rule-vs-LLM verifier divergences that warrant human auditor verification.",
        "",
        "## 1. Structural and Replication Review Cases",
        "",
        "| Case ID | Email | Status | Flag Reason | Details |",
        "|---|---|---|---|---|",
    ]
    for c in cases_flagged:
        lines.append(f"| `{c['case_id']}` | `{c['email']}` | `{c['status']}` | {c['reason']} | {c['details']} |")

    lines.append("")
    lines.append("## 2. LLM Intent Verifier Disagreements")
    lines.append("")
    if verifier_disagreements:
        lines.append("| Case ID | Email | Rule Verdict | Verifier Verdict | Request Text |")
        lines.append("|---|---|---|---|---|")
        for d in verifier_disagreements:
            clean_txt = (d.get('request_text', '') or '').replace('|', '\\|').replace('\n', ' ')
            lines.append(f"| `{d['case_id']}` | `{d['email']}` | `{d['rule_intent']}` | `{d['verifier_intent']}` | \"{clean_txt}\" |")
    elif verified_count > 0:
        lines.append(f"Verifier ran on {verified_count} of 518 requests; zero disagreements.")
    else:
        lines.append("Verifier skipped; no disagreement data.")

    lines.append("")
    lines.append("## Auditor Guidance")
    lines.append("- For **Replication Drift**, confirm whether the regional or read replica has caught up past the case `audit_at`.")
    lines.append("- For **Historical Identifier**, verify that identity change events in `user_audit_log.csv` were propagated across all downstream systems.")
    lines.append("- For **Active Data Flows**, ensure connectors and restore policies are blocked prior to record deletion.")
    lines.append("- For **Verifier Disagreements**, compare human intent authorization against GDPR Art. 17 right-to-erasure criteria.")
    lines.append("")

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
