---
title: SOC Triage Environment
emoji: 🚀
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 8000
---
# SOC Alert Triage Environment (OpenEnv)

An interactive cybersecurity environment where AI agents act as Level 2 SOC Analysts.
Agents must use investigation tools to query IP reputation databases, SIEM logs, and malware hash databases before making a final routing decision.

## Motivation

Security Operations Centers process thousands of alerts daily. Analysts must quickly categorize threats, assess priority, and route to the correct team. This environment trains and evaluates AI agents on that exact workflow — with a twist: alerts are intentionally ambiguous, forcing agents to actively investigate before deciding.

## Action Space

The agent interacts via MCP tool calls:

| Tool | Parameters | Description |
|------|-----------|-------------|
| `query_ip_reputation` | `ip_address: str` | Query threat intel feeds for an IP |
| `search_internal_logs` | `host_name: str` | Search SIEM logs for host anomalies |
| `check_file_hash` | `file_hash: str` | Check hash against malware databases |
| `triage_alert` | `category, priority, route_to` | Submit final triage decision |

**Categories:** `malware`, `phishing`, `ddos`, `exfiltration`, `false_alarm`, `compliance`
**Priorities:** `low`, `medium`, `high`, `critical`
**Routing:** `tier1`, `networking`, `incident_response`, `legal`, `false_positive`

## Observation Space

Each observation contains:
- `current_alert`: dict with `signature`, `source_ip`, `host_name`, `file_hash`, `payload`, `timestamp`, `severity_sensor`, `is_critical_infrastructure`, `is_recurring`, `event_count`
- `queue_summary`: `{total, processed, remaining}`
- `task_description`: text describing the current task objective
- `available_categories`, `available_priorities`, `available_departments`: valid enum values

## Tasks

| Task | Difficulty | Alerts | Grading Focus |
|------|-----------|--------|---------------|
| `single_categorize` | Easy | 5 | Category accuracy only (weighted by investigation) |
| `full_triage` | Medium | 8 | Category (40%) + Priority (30%) + Routing (30%) |
| `executive_inbox` | Hard | 12 | Category + Priority + Routing + Response quality + Completeness |

All graders return scores in the range `0.0 – 1.0`. Agents that skip investigation tools are penalized by up to 50%.

## Reward Design

- **Investigation multiplier**: If an alert has indicators (IP, host, hash), the agent must call the corresponding tool. Skipping investigation reduces the score by `0.5 + 0.5 * (investigated / required)`.
- **Partial credit**: Priority scores give 0.4 for off-by-one errors, 0.1 for off-by-two.
- **Per-step rewards**: Each `triage_alert` call returns an immediate reward. Investigation tools return `reward=0.0` (informational only).

## Setup

```bash
pip install -e .
uv run server &
```

## Running Inference

```bash
export API_BASE_URL="https://router.huggingface.co/v1"
export MODEL_NAME="Qwen/Qwen2.5-72B-Instruct"
export HF_TOKEN="your_token"
export ENV_BASE_URL="https://madhukar09-soc-triage-env.hf.space"

python inference.py
```

## Baseline Scores

Model: `meta-llama/Llama-3.3-70B-Instruct`

| Task | Steps | Rewards | Notes |
|------|-------|---------|-------|
| `single_categorize` | 9 | 0.00, 0.00, 0.75, 1.00, 0.00 | Perfect 1.0 on DDoS alert |
| `full_triage` | 10 | 0.00, 0.00, 0.50, 0.00, 0.01, 0.06, 0.09, 0.32 | Multi-field scoring |
| `executive_inbox` | 13 | 0.10, 0.46, 0.10, 0.36, 0.11, 0.14, 0.36, 0.46, 0.10, 0.36, 0.46, 0.46 | High-volume triage |
