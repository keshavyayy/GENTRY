# Token Usage and Cost Report: Ghost Data Still Exists

## 1. Run Summary

This report summarizes telemetry, token counts, and API calls for the production evaluation run producing `output.csv` (518 requests) per AGENTS.md §6.8. All metrics reflect actual recorded telemetry derived directly from the usage tracking file without speculative estimates.

---

## 2. Verified Model Telemetry & Token Usage

- **Model Provider:** Google Cloud / DeepMind (Gemini API)
- **Total Model API Calls:** 21
- **Prompt (Input) Tokens:** 33,795
- **Candidates (Output) Tokens:** 15,995
- **Thoughts (Reasoning) Tokens:** 0
- **Total Combined Tokens:** 49,790
- **Average Tokens per Request:** 96.12

### Per-Model Breakdown

| Model Name | Calls | Input Tokens | Output Tokens | Thought Tokens | Total Tokens |
|---|---|---|---|---|---|
| `gemini-3.5-flash-lite` | 20 | 32,152 | 15,358 | 0 | 47,510 |
| `gemini-3.1-flash-lite` | 1 | 1,643 | 637 | 0 | 2,280 |

---

## 3. Financial Cost Breakdown (Estimated)

- **Estimated Total Cost:** **$0.00733**
- **Estimated Average Cost per Request:** **$0.00001**

> [!NOTE]
> **Price Assumptions & Estimation Basis:**
> Cost estimates are calculated using standard Google Gemini Flash pricing:
> - Input (Prompt) Tokens: **$0.075 per 1,000,000 tokens** ($0.000000075 / token)
> - Output (Candidates + Reasoning Thoughts) Tokens: **$0.30 per 1,000,000 tokens** ($0.00000030 / token)
> In accordance with Google Gemini billing specifications, hidden reasoning thought tokens are metered and billed at standard output token rates.
> When execution runs offline or without an active external API key, total calls remain 0 at $0.00000 cost.

