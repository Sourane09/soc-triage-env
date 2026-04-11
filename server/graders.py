from typing import Dict, List, Tuple
from ..models import SecurityAlert, SOCTriageAction


def _clamp_score(score) -> float:
    """Clamp score strictly within (0.01, 0.99) -- never exactly 0.0 or 1.0, NaN-safe."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return 0.5
    if s != s:  # NaN check
        return 0.5
    if s <= 0.01:
        return 0.01
    if s >= 0.99:
        return 0.99
    return round(s, 4)


def _category_score(predicted: str, true: str) -> float:
    return 1.0 if predicted.lower().strip() == true.lower().strip() else 0.0


def _priority_score(predicted: str, true: str) -> float:
    priority_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    p_val = priority_levels.get(predicted.lower().strip(), -1)
    t_val = priority_levels.get(true.lower().strip(), -1)

    if p_val == -1 or t_val == -1:
        return 0.0

    diff = abs(p_val - t_val)
    if diff == 0:
        return 1.0
    elif diff == 1:
        return 0.4
    elif diff == 2:
        return 0.1
    return 0.0


def _routing_score(predicted: str, true: str) -> float:
    return 1.0 if predicted.lower().strip() == true.lower().strip() else 0.0


def _response_quality_score(response: str, alert: SecurityAlert) -> float:
    if not response or not response.strip():
        return 0.0

    response_lower = response.lower()
    subject_words = set(alert.signature.lower().split())

    if any(word in response_lower for word in subject_words if len(word) > 3):
        return 1.0
    return 0.5


def _investigation_score(state_tracker: dict, alert: SecurityAlert) -> float:
    needed = 0
    done = 0

    if alert.needs_ip_investigation:
        needed += 1
        if state_tracker.get("ip"):
            done += 1
    if alert.needs_host_investigation:
        needed += 1
        if state_tracker.get("host"):
            done += 1
    if alert.needs_hash_investigation:
        needed += 1
        if state_tracker.get("hash"):
            done += 1

    if needed == 0:
        return 1.0  # No investigation needed, full multiplier

    return 0.5 + (0.5 * (done / needed))  # Range: 0.5 to 1.0


class SingleCategorizeGrader:
    def grade(
        self,
        actions: List[SOCTriageAction],
        alerts: List[SecurityAlert],
        investigative_states: List[dict] = None,
    ) -> float:
        if not actions or not alerts:
            return _clamp_score(0.0)

        if not investigative_states:
            investigative_states = [{} for _ in alerts]

        n = min(len(actions), len(alerts))
        if n == 0:
            return _clamp_score(0.0)

        total = 0.0
        for i in range(n):
            base_score = _category_score(actions[i].category, alerts[i].true_category)
            inv_multiplier = _investigation_score(investigative_states[i], alerts[i])
            total += base_score * inv_multiplier

        return _clamp_score(total / n)


class FullTriageGrader:
    def grade(
        self,
        actions: List[SOCTriageAction],
        alerts: List[SecurityAlert],
        investigative_states: List[dict] = None,
    ) -> float:
        if not actions or not alerts:
            return _clamp_score(0.0)

        if not investigative_states:
            investigative_states = [{} for _ in alerts]

        n = min(len(actions), len(alerts))
        if n == 0:
            return _clamp_score(0.0)

        total = 0.0
        for i in range(n):
            cat = _category_score(actions[i].category, alerts[i].true_category)
            pri = _priority_score(actions[i].priority, alerts[i].true_priority)
            route = _routing_score(actions[i].route_to, alerts[i].true_department)

            base_score = (0.40 * cat) + (0.30 * pri) + (0.30 * route)
            inv_multiplier = _investigation_score(investigative_states[i], alerts[i])

            total += base_score * inv_multiplier

        return _clamp_score(total / n)


class ExecutiveInboxGrader:
    def grade(
        self,
        actions: List[SOCTriageAction],
        alerts: List[SecurityAlert],
        investigative_states: List[dict] = None,
        per_step: bool = False,
    ) -> float:
        if not alerts:
            return _clamp_score(0.0)

        if not investigative_states:
            investigative_states = [{} for _ in alerts]

        n_alerts = len(alerts)
        n_processed = min(len(actions), n_alerts)

        if n_processed == 0:
            return _clamp_score(0.0)

        total = 0.0
        for i in range(n_processed):
            cat = _category_score(actions[i].category, alerts[i].true_category)
            pri = _priority_score(actions[i].priority, alerts[i].true_priority)
            route = _routing_score(actions[i].route_to, alerts[i].true_department)
            resp = _response_quality_score(actions[i].response_draft, alerts[i])

            base_score = (0.30 * cat) + (0.25 * pri) + (0.25 * route) + (0.20 * resp)
            inv_multiplier = _investigation_score(investigative_states[i], alerts[i])

            total += base_score * inv_multiplier

        avg_quality = total / n_processed

        if per_step:
            return _clamp_score(avg_quality)

        completeness = n_processed / n_alerts
        final = (0.90 * avg_quality) + (0.10 * completeness)
        return _clamp_score(final)


TASK_GRADERS = {
    "single_categorize": SingleCategorizeGrader(),
    "full_triage": FullTriageGrader(),
    "executive_inbox": ExecutiveInboxGrader(),
}

TASK_DESCRIPTIONS = {
    "single_categorize": (
        "EASY TASK: Categorize each security alert into the correct category. "
        "Available categories: malware, phishing, ddos, exfiltration, false_alarm, compliance. "
    ),
    "full_triage": (
        "MEDIUM TASK: Perform full triage on each security alert. "
        "For each alert, you must: (1) investigate hidden context using investigation tools, "
        "(2) categorize it, (3) set the priority level, and (4) route it to the correct department. "
    ),
    "executive_inbox": (
        "HARD TASK: Manage high-volume, complex SOC alerts. "
        "IMPORTANT: You MUST investigate IP addresses, file hashes, and hostnames before making your final `triage_alert` decision. "
        "Failure to investigate REDUCES your score."
    ),
}

TASK_ALERT_COUNTS = {
    "single_categorize": 5,
    "full_triage": 8,
    "executive_inbox": 12,
}