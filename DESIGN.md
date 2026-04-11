# Design Document — SOC Alert Triage Environment

*Meta PyTorch OpenEnv Hackathon × Scaler School of Technology, Round 1 — April 2026*

## Problem framing

Every large enterprise runs a Security Operations Center. Every SOC drowns in alerts. Typical tier-1 analysts handle 30–50 alerts per shift; modern SIEMs generate tens of thousands per day. The gap between signal volume and human capacity is the core operational problem of defensive cybersecurity.

Inside that gap sits a recognizable, repeatable workflow:

1. Receive an alert with some surface signature
2. Check the IP against threat intel
3. Check the host against SIEM logs
4. Check any file hashes against malware databases
5. Classify, prioritize, route

That workflow is a tool-use RL problem in disguise. An agent that learns to execute it reliably becomes a force multiplier for the humans who handle the ambiguous 5% of cases — not a replacement, but an extender of capacity. That is the real-world utility this environment exists to unlock.

## Design goals

We set four goals at the start and optimized every design choice against them.

1. **Reward investigation, punish guessing.** A pattern-matching agent should not be able to win. The agent must call investigation tools to have any chance of a high score.
2. **Reproducible grading.** The same seed should produce the same alerts in the same order. No grader nondeterminism. Score comparisons between agents must be apples-to-apples.
3. **Multi-dimensional scoring.** A real SOC decision involves four axes (category, priority, routing, response quality). The graders reflect that, with partial credit for near-misses on ordinal fields like priority.
4. **Strict interval rewards.** Every grader output lands strictly inside `(0, 1)` on every code path, including early exits and exception handlers. No `0.0`, no `1.0`, no `NaN`.

## Key design decisions

### Forced investigation via reward shaping

The single most important decision. Every alert has a set of "needed" investigation tools (IP, host, hash — depending on the alert's evidence). The agent's final score is multiplied by:


investigation_multiplier = 0.5 + 0.5 * (tools_used / tools_required)



An agent that investigates everything gets `×1.0`. An agent that skips everything gets `×0.5`, hard-capping their ceiling at half the score of a thorough analyst. Investigation is free (calling a tool costs nothing) but mandatory.

This design choice is why we expect the environment to be **ungameable by pattern-matching baselines**. A model that reads only the payload string and guesses from keywords cannot beat an agent that actually checks the tools, because the multiplier dominates every task grade.

### Template-based alerts (not LLM-generated)

We considered using an LLM to generate alert text for variety. We rejected it. Reproducibility matters more: judges need to run two different agents against the same environment and compare scores meaningfully. LLM-generated content introduces variance that swamps small-but-real improvements in agent capability.

Templates give us a fixed alert pool per seed. Every run with `seed=42` produces the exact same alerts in the exact same order. That is the property a benchmark needs.

The trade-off: templates can be memorized if an adversary trains an agent extensively against this exact environment. We mitigate that two ways. First, we currently ship 26 templates across 6 categories, not the 3-per-category bare minimum. Second, templates are rotated per episode based on the seed — two different seeds produce two different sequences. Full anti-memorization (50+ templates + per-episode text randomization) is future work.

### Structured tool responses over free text

An earlier prototype returned plain English from the investigation tools ("IP X is on threat feeds"). We replaced every tool response with structured JSON containing:

- A confidence score
- Concrete indicators (threat categories, anomaly counts, detection ratios, ASN)
- Temporal metadata (first seen, last seen)
- Explanatory notes

This does two things for agent behavior. It forces the agent to integrate multiple fields to make a decision (not just match a single keyword), and it makes the environment look like real threat intel APIs do. A model that learns this environment learns transferable skills, not toy-benchmark tricks.

### System prompt contains workflow, not answers

The first version of the system prompt listed signature-to-category mappings and gave the agent explicit keyword hints ("'malicious' → real threat"). This was a leak — the agent could skip investigation and pattern-match. We removed it.

The current system prompt describes the workflow and explains how to *interpret* investigation results (confidence scores, notes, indicators), but never tells the agent what words to match. The agent has to reason about evidence.

### Three tasks with increasing grader complexity

| Task | Grader focus | Why it exists |
|------|-------------|---------------|
| `single_categorize` | Category × investigation | Validates basic tool use. If an agent fails this, it cannot use tools at all. |
| `full_triage` | Category + priority + routing, each weighted | Tests multi-dimensional reasoning across a full triage decision. |
| `executive_inbox` | Adds response_draft quality and completeness bonus | Tests natural language output plus completeness (agent must process every alert, not stop early). |

This is how real SOCs onboard new analysts — start with categorization, add priority and routing, add incident writeups. Agents that learn this progression learn a transferable skill, not a task-specific trick.

### Strict `(0, 1)` score contract

Every grader return path is wrapped in `_clamp_score()` which guarantees the output lands inside `(0.01, 0.99)`. This includes:

- Main return paths
- Early-exit guards (empty actions, empty alerts)
- Exception handlers
- Per-step rewards emitted from `triage_alert`
- The episode `final_score`

The `inference.py` baseline additionally emits a `score=<value>` field on the `[END]` line with strict clamping, so downstream consumers that parse stdout never encounter forbidden edge values. This contract is enforced by `test_compliance.py`.

## What we deliberately did not build

Listing these to show honest scope boundaries, not to pre-apologize.

- **Alert correlation across episodes.** Real SOCs correlate alerts that reference the same IP or host over time. Adding this dimension would strengthen the environment significantly but requires a stateful episode design we did not have time to validate.
- **Adversarial LLM-generated alerts.** A future version could use a small LLM to paraphrase template text each episode, defeating memorization. We have the seeded-rng hook points for this but did not ship it.
- **A second reward signal for false-positive rate.** Right now the grader rewards correct classification. A production SOC also cares about *overclassification* (flagging benign things as threats, wasting analyst time). A reward term penalizing false positives on the `false_alarm` category would be more operationally realistic.
- **Multi-agent / shift-handoff tasks.** SOCs involve analyst handoffs between shifts. A multi-agent version where agent A investigates and agent B makes the decision would be a strong RL research target. Out of scope for Round 1.

## How to judge this environment

If you are a judge evaluating this submission, the three things most worth looking at:

1. **Run the baseline against the deployed HF Space** to see that it actually works end-to-end: `python inference.py` with `HF_TOKEN` set. Expected task scores for the stock Qwen 2.5 baseline: roughly 0.4 / 0.36 / 0.27 across easy / medium / hard. The moderate numbers are by design — the environment has real headroom for better agents.
2. **Read `server/graders.py`** to see how investigation penalty, priority partial credit, and weight clamping compose. The math is small and readable.
3. **Run `python test_compliance.py`** from inside `soc_triage_env/`. This validates scoring contract, routing, task outputs, and output format regex. Five tests, all should pass.

## Team

Built for the Meta PyTorch × Hugging Face × Scaler OpenEnv Hackathon, Round 1.

- Adarsh Kumar Dwivedi — adarshdwivedi626@gmail.com (Team Lead)
- Madhukar Vaibhav — madhukarkty@gmail.com

## License

MIT