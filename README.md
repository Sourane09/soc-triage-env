markdown---
title: SOC Triage Environment
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 8000
---

# SOC Alert Triage Environment (OpenEnv)

A real-world cybersecurity environment where AI agents act as Level 2 SOC Analysts. Agents investigate ambiguous security alerts using threat intel tools, then classify, prioritize, and route each alert to the correct response team.

## Why this matters

A typical Security Operations Center processes tens of thousands of alerts per day. Level 1 analysts can handle maybe 30–50 in a shift. The majority of alerts are false positives, but the cost of misclassifying a real threat — especially a ransomware precursor or data exfiltration — is catastrophic. Training AI agents on this workflow has direct operational value: a reliable triage agent can extend analyst capacity by an order of magnitude without replacing the humans who handle the ambiguous edge cases.

The key design choice in this environment is **forced investigation**. Alert payloads are intentionally ambiguous — the same surface signature can be malware or a legitimate admin action depending on hidden evidence. An agent that skips the investigation tools and guesses from the payload alone is explicitly penalized: their final score is multiplied by `0.5 + 0.5 × (investigated / required)`, capping blind guessers at 0.5× the score of a thorough analyst. This mirrors how real SOCs evaluate their L1/L2 workflow.

## Architecture
┌─────────────────────────────────────────────────────────────┐
│                    SOCTriageEnvironment                     │
│                   (extends MCPEnvironment)                  │
├─────────────────────────────────────────────────────────────┤
│  Alert Queue (5/8/12 alerts per task, seeded generator)     │
│         ↓                                                   │
│  ┌──────────────────────────────────────────────────┐       │
│  │  MCP Tools                                       │       │
│  │  • query_ip_reputation(ip)                       │       │
│  │  • search_internal_logs(host)                    │       │
│  │  • check_file_hash(hash)                         │       │
│  │  • triage_alert(category, priority, route, ...)  │       │
│  └──────────────────────────────────────────────────┘       │
│         ↓                                                   │
│  Task-specific grader + investigation multiplier            │
│         ↓                                                   │
│  Reward ∈ (0, 1) per step, final score ∈ (0, 1)            │
└─────────────────────────────────────────────────────────────┘

## Action Space

The agent interacts via MCP tool calls:

| Tool | Parameters | Purpose |
|------|-----------|---------|
| `query_ip_reputation` | `ip_address: str` | Query threat intel feeds for an IP |
| `search_internal_logs` | `host_name: str` | Search SIEM logs for host anomalies |
| `check_file_hash` | `file_hash: str` | Check hash against malware databases |
| `triage_alert` | `category, priority, route_to, response_draft, flag` | Submit final triage decision, advance to next alert |

**Categories:** `malware`, `phishing`, `ddos`, `exfiltration`, `false_alarm`, `compliance`
**Priorities:** `low`, `medium`, `high`, `critical`
**Routing:** `tier1`, `networking`, `incident_response`, `legal`, `false_positive`

## Observation Space

Each observation contains (Pydantic-validated):
- `current_alert`: dict with `signature`, `source_ip`, `host_name`, `file_hash`, `payload`, `timestamp`, `severity_sensor`, `is_critical_infrastructure`, `is_recurring`, `event_count`
- `queue_summary`: `{total, processed, remaining}`
- `task_description`: text describing the current task objective
- `available_categories`, `available_priorities`, `available_departments`: valid enum values

Ground-truth fields (`true_category`, `true_priority`, `true_department`, `malicious`) are stored on the server and never exposed to the agent.

## Tasks

| Task | Difficulty | Alerts | Grading Focus |
|------|-----------|--------|---------------|
| `single_categorize` | Easy | 5 | Category accuracy × investigation multiplier |
| `full_triage` | Medium | 8 | Category (40%) + Priority (30%) + Routing (30%), all × investigation |
| `executive_inbox` | Hard | 12 | Category (30%) + Priority (25%) + Routing (25%) + Response quality (20%), × investigation × completeness |

Alert counts are small intentionally — each alert is multi-step (query, search, check, triage) so 12 alerts become 48+ tool calls. A full `executive_inbox` episode is a realistic "1 hour of an L2 analyst's shift" in compute terms.

## Reward Design

### Per-step reward
Every `triage_alert` call immediately returns a reward computed by the same task grader it would use at the end, scoped to that single alert. This gives the agent dense feedback during the episode.

### Final score
Computed by averaging per-alert grades across the episode, with an `ExecutiveInbox`-specific completeness bonus rewarding agents who process all alerts instead of stopping early.

### Investigation multiplier
multiplier = 0.5 + 0.5 × (tools_used / tools_required)
An agent that investigates everything gets `×1.0`. An agent that skips all investigation gets `×0.5`. This multiplier is applied to every alert's base score, making it impossible to achieve a high final score by guessing.

### Partial credit
Priority scoring uses a distance-based scheme: exact match = 1.0, off-by-one (e.g. predicted `high` when true is `medium`) = 0.4, off-by-two = 0.1. This prevents the all-or-nothing cliff that would otherwise punish reasonable near-misses.

### Score clamping
All grader outputs, per-step rewards, and the final episode score are strictly clamped inside `(0, 1)` — never exactly 0.0 or 1.0. This is enforced at every return path including early-exit guards and exception handlers.

## Quick Start

```bash
# Install
pip install -e .

# Run the environment server
uv run server &

# Run the baseline inference script
export HF_TOKEN="your_hf_token"
export API_BASE_URL="https://router.huggingface.co/v1"
export MODEL_NAME="Qwen/Qwen2.5-72B-Instruct"
export ENV_BASE_URL="http://localhost:8000"
python inference.py
```

## Baseline Scores

Baseline agent: `Qwen/Qwen2.5-72B-Instruct` via Hugging Face Router, with `tool_choice="required"` and system prompt guiding the investigate-then-triage workflow.

| Task | Alerts | Final Score | Notes |
|------|--------|-------------|-------|
| `single_categorize` | 5 | ~0.40 | Easy categorization, agent often correct |
| `full_triage` | 8 | ~0.36 | Multi-dimensional scoring pulls score down |
| `executive_inbox` | 12 | ~0.27 | Hardest task, biased toward false alarms |

Baseline scores are moderate by design — the environment is hard to game. An agent that uses all investigation tools and carefully maps evidence to category should land in the 0.6–0.8 range. These scores leave clear headroom for RL fine-tuning to demonstrate improvement.

## Design Decisions

**Why template-based alerts instead of LLM-generated?** Templates give reproducible grading across seeds. Every evaluation run with the same seed produces the same alerts in the same order, so score comparisons between agents are apples-to-apples. LLM-generated alerts would introduce variance that swamps small improvements in agent capability.

**Why the investigation penalty?** Without it, a pattern-matching agent can hit 0.7+ on `single_categorize` just by reading the payload string. The penalty makes investigation cost-free (no reward loss for calling tools) and mandatory (big reward loss for skipping them). This mirrors real SOC procedures where "look it up before you escalate" is the first rule.

**Why three tasks of increasing difficulty?** `single_categorize` validates the agent can use tools at all. `full_triage` tests multi-dimensional reasoning (category + priority + routing). `executive_inbox` adds a natural-language response draft and critical-infrastructure bias. This progression is how a real SOC onboards new analysts.

## Known Limitations

1. **Template pool size** — 15 base templates across 6 categories. Could be memorized by a model trained extensively on this environment. Future work: expand to 50+ templates and add per-episode randomization of descriptor text.
2. **Binary investigation responses** — tool responses are "malicious" or "benign" with deterministic text. Real threat intel returns confidence scores, ASN data, temporal context. Future work: return structured JSON with confidence and metadata.
3. **Stateless per-alert** — alerts in an episode are independent. Real SOC workflows involve correlation across alerts (same IP appearing twice). Future work: add a correlation dimension to the grader.

## Repository Layout
soc_triage_env/
├── README.md              (this file)
├── openenv.yaml           (OpenEnv metadata)
├── pyproject.toml         (package config)
├── inference.py           (baseline agent)
├── init.py            (exports SOCTriageEnv, SOCTriageAction, SOCTriageObservation)
├── client.py              (MCP client wrapper)
├── models.py              (Pydantic types: SecurityAlert, SOCTriageAction, ...)
├── server/
│   ├── app.py             (FastAPI app factory)
│   ├── Dockerfile         (container definition)
│   ├── soc_environment.py (SOCTriageEnvironment class)
│   ├── alert_generator.py (synthetic alert templates)
│   └── graders.py         (task-specific graders)
└── test_compliance.py     (spec compliance tests)

## Team

Built for the Meta PyTorch OpenEnv Hackathon × Scaler School of Technology 2026.

- **Adarsh Kumar Dwivedi** (Team Lead) — adarshdwivedi626@gmail.com
- **Madhukar Vaibhav** — madhukarkty@gmail.com

## License

MIT