"""Compliance test - run from soc_triage_env/ with: .venv/Scripts/python test_compliance.py"""
import sys
import re

from soc_triage_env.server.soc_environment import SOCTriageEnvironment
from soc_triage_env.server.alert_generator import AlertGenerator
from soc_triage_env.server.graders import TASK_GRADERS, _clamp_score, _investigation_score
from soc_triage_env.models import SecurityAlert

errors = []

print("TEST 1: Score clamping - never 0.0 or 1.0")
for v in [0.0, 1.0, -1.0, 2.0, 0.5, 0.001, 0.999]:
    s = _clamp_score(v)
    if not (0.0 < s < 1.0):
        errors.append(f"clamp({v})={s}")
    print(f"  clamp({v}) = {s}")
s = _clamp_score(None)
print(f"  clamp(None) = {s}")
if not (0.0 < s < 1.0):
    errors.append(f"clamp(None)={s}")

print("\nTEST 2: Routing matches system prompt")
expected = {
    "malware": "incident_response",
    "phishing": "tier1",
    "ddos": "networking",
    "exfiltration": "incident_response",
    "false_alarm": "false_positive",
    "compliance": "legal",
}
gen = AlertGenerator(seed=42)
for cat, dept in expected.items():
    r1 = gen._get_department_mapping(cat, "high", False)
    r2 = gen._get_department_mapping(cat, "critical", True)
    if r1 != dept:
        errors.append(f"{cat}+normal={r1}, expected {dept}")
    if r2 != dept:
        errors.append(f"{cat}+critical={r2}, expected {dept}")
    print(f"  {cat} -> {r1} (with critical: {r2})")

print("\nTEST 3: All 3 tasks produce valid scores in (0,1)")
for task in ["single_categorize", "full_triage", "executive_inbox"]:
    env = SOCTriageEnvironment()
    env.reset(task=task, seed=42)
    step_rewards = []
    while not env._done:
        alert = env._alerts[env._current_index]
        if alert.source_ip:
            env._tool_query_ip(alert.source_ip)
        if alert.host_name:
            env._tool_search_logs(alert.host_name)
        if alert.file_hash:
            env._tool_check_hash(alert.file_hash)
        result = env._process_triage(
            alert.true_category, alert.true_priority,
            alert.true_department, "test response", False,
        )
        r = result["reward"]
        step_rewards.append(r)
        if not (0.0 < r < 1.0):
            errors.append(f"{task} step reward={r}")

    grader = TASK_GRADERS[task]
    final = grader.grade(env._actions_taken, env._alerts, env._investigation_states)
    if not (0.0 < final < 1.0):
        errors.append(f"{task} final={final}")
    rstr = ",".join(f"{r:.2f}" for r in step_rewards)
    print(f"  {task}: final={final:.4f}, alerts={len(env._alerts)}, rewards=[{rstr}]")

print("\nTEST 4: Output format regex compliance")
start_line = "[START] task=single_categorize env=soc_triage_env model=Qwen/Qwen2.5-72B-Instruct"
if not re.match(r"^\[START\] task=\S+ env=\S+ model=\S+$", start_line):
    errors.append("START format")
print(f"  [START]: {start_line}")

step_line = '[STEP] step=1 action=triage_alert({{"category":"malware"}}) reward=0.50 done=false error=null'
if not re.match(r"^\[STEP\] step=\d+ action=.+ reward=\d+\.\d{2} done=(true|false) error=.+$", step_line):
    errors.append("STEP format")
print(f"  [STEP]: {step_line}")

rewards = [0.001, 0.50, 0.001, 0.75]
rs = ",".join(f"{r:.2f}" for r in rewards)
end_line = f"[END] success=true steps=4 rewards={rs}"
if not re.match(r"^\[END\] success=(true|false) steps=\d+ rewards=[\d.,]+$", end_line):
    errors.append("END format")
if "score=" in end_line:
    errors.append("END contains score=")
print(f"  [END]: {end_line}")

print("\nTEST 5: Investigation score logic")
a1 = SecurityAlert(needs_ip_investigation=True, needs_host_investigation=True, needs_hash_investigation=True)
a2 = SecurityAlert(needs_ip_investigation=False, needs_host_investigation=False, needs_hash_investigation=False)
s_none_needed = _investigation_score({}, a2)
s_all_needed_none_done = _investigation_score({}, a1)
s_all_done = _investigation_score({"ip": True, "host": True, "hash": True}, a1)
print(f"  No investigation needed: {s_none_needed}")
print(f"  All needed, none done: {s_all_needed_none_done}")
print(f"  All needed, all done: {s_all_done}")
print(f"  Perfect score after clamp: {_clamp_score(1.0)}")

print("\n" + "=" * 60)
if errors:
    print(f"FAILURES ({len(errors)}):")
    for e in errors:
        print(f"  ❌ {e}")
    sys.exit(1)
else:
    print("✅ ALL TESTS PASSED")
    sys.exit(0)
