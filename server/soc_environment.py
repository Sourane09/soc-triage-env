from typing import Any, Dict, List, Optional
from uuid import uuid4

from openenv.core.env_server.mcp_environment import MCPEnvironment
from openenv.core.env_server.types import Action, Observation, State

from fastmcp import FastMCP

from .alert_generator import (
    CATEGORIES,
    DEPARTMENTS,
    PRIORITIES,
    AlertGenerator,
    alert_to_dict,
)
from .graders import (
    TASK_DESCRIPTIONS,
    TASK_ALERT_COUNTS,
    TASK_GRADERS,
)
from ..models import SecurityAlert, SOCTriageAction, SOCTriageState


def _safe_clamp(value, default: float = 0.001) -> float:
    """Defensive clamp: never returns 0.0, never returns 1.0, never returns NaN/None."""
    try:
        s = float(value) if value is not None else default
    except (TypeError, ValueError):
        return default
    if s != s:  # NaN
        return default
    if s <= 0.0:
        return 0.001
    if s >= 1.0:
        return 0.999
    return s


class SOCTriageEnvironment(MCPEnvironment):
    def __init__(self):
        mcp = FastMCP("soc_triage_env")
        env_ref = self

        @mcp.tool
        def query_ip_reputation(ip_address: str) -> dict:
            return env_ref._tool_query_ip(ip_address)

        @mcp.tool
        def search_internal_logs(host_name: str) -> dict:
            return env_ref._tool_search_logs(host_name)

        @mcp.tool
        def check_file_hash(file_hash: str) -> dict:
            return env_ref._tool_check_hash(file_hash)

        @mcp.tool
        def triage_alert(
            category: str = "false_alarm",
            priority: str = "medium",
            route_to: str = "tier1",
            response_draft: str = "",
            flag: bool = False,
        ) -> dict:
            return env_ref._process_triage(
                category=category,
                priority=priority,
                route_to=route_to,
                response_draft=response_draft,
                flag=flag,
            )

        @mcp.tool
        def get_current_alert() -> dict:
            return env_ref._get_current_alert()

        @mcp.tool
        def get_queue_status() -> dict:
            return env_ref._get_queue_status()

        @mcp.tool
        def get_task_info() -> dict:
            return {
                "task_name": env_ref._task_name,
                "description": TASK_DESCRIPTIONS.get(env_ref._task_name, ""),
                "available_categories": CATEGORIES,
                "available_priorities": PRIORITIES,
                "available_departments": DEPARTMENTS,
                "total_alerts": env_ref._total_alerts,
                "processed": env_ref._processed_count,
            }

        super().__init__(mcp)
        self._state = State(episode_id=str(uuid4()), step_count=0)
        self._task_name = "single_categorize"
        self._alerts: List[SecurityAlert] = []
        self._current_index = 0
        self._total_alerts = 0
        self._processed_count = 0
        self._actions_taken: List[SOCTriageAction] = []
        self._investigation_states: List[dict] = []

        # Track active investigation state for the current alert
        self._current_investigated_ip = False
        self._current_investigated_host = False
        self._current_investigated_hash = False

        self._rewards: List[float] = []
        self._cumulative_reward = 0.0
        self._done = False
        self._last_error: Optional[str] = None
        self._seed = 42

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        task: Optional[str] = None,
        **kwargs: Any,
    ) -> Observation:
        if task is None:
            task = kwargs.get("task", "single_categorize")

        if task not in TASK_GRADERS:
            task = "single_categorize"

        self._task_name = task
        self._seed = seed if seed is not None else 42
        self._state = State(
            episode_id=episode_id or str(uuid4()),
            step_count=0,
        )

        generator = AlertGenerator(seed=self._seed)
        self._total_alerts = TASK_ALERT_COUNTS.get(task, 5)

        if task == "single_categorize":
            self._alerts = generator.generate_easy_alerts(self._total_alerts)
        elif task == "full_triage":
            self._alerts = generator.generate_medium_alerts(self._total_alerts)
        elif task == "executive_inbox":
            self._alerts = generator.generate_hard_alerts(self._total_alerts)

        self._current_index = 0
        self._processed_count = 0
        self._actions_taken = []
        self._investigation_states = []

        self._current_investigated_ip = False
        self._current_investigated_host = False
        self._current_investigated_hash = False

        self._rewards = []
        self._cumulative_reward = 0.0
        self._done = False
        self._last_error = None

        first_alert = alert_to_dict(self._alerts[0]) if self._alerts else {}

        return Observation(
            done=False,
            reward=0.001,
            metadata={
                "status": "ready",
                "task_name": self._task_name,
                "task_description": TASK_DESCRIPTIONS.get(self._task_name, ""),
                "current_alert": first_alert,
                "queue_summary": {
                    "total": self._total_alerts,
                    "processed": 0,
                    "remaining": self._total_alerts,
                },
                "available_categories": CATEGORIES,
                "available_priorities": PRIORITIES,
                "available_departments": DEPARTMENTS,
                "message": (
                    f"SOC triage environment ready. You have {self._total_alerts} alerts to process.\n"
                    "IMPORTANT: Investigate IP, Host, and Hash evidence before calling triage_alert() "
                    "or you will suffer massive penalties."
                ),
            },
        )

    # --- Investigation Tools (DO NOT END TURN) ---
    def _tool_query_ip(self, ip_address: str) -> dict:
        if self._done or self._current_index >= len(self._alerts):
            return {"error": "Episode is done.", "reward": 0.001, "done": True}
        alert = self._alerts[self._current_index]
        self._current_investigated_ip = True

        if ip_address == alert.source_ip:
            if alert.malicious:
                return {
                    "result": f"IP {ip_address} is listed on multiple Threat Intelligence Feeds as a known malicious node.",
                    "reward": 0.001,
                    "done": False,
                }
            else:
                return {
                    "result": f"IP {ip_address} originates from an authorized Corporate VPN endpoint.",
                    "reward": 0.001,
                    "done": False,
                }
        return {
            "result": f"IP {ip_address} not found in current alert context or is benign.",
            "reward": 0.001,
            "done": False,
        }

    def _tool_search_logs(self, host_name: str) -> dict:
        if self._done or self._current_index >= len(self._alerts):
            return {"error": "Episode is done.", "reward": 0.001, "done": True}
        alert = self._alerts[self._current_index]
        self._current_investigated_host = True

        if host_name == alert.host_name:
            if alert.malicious:
                return {
                    "result": f"Host {host_name} logs indicate rapid file encryption and outbound connections. Compromise is highly likely.",
                    "reward": 0.001,
                    "done": False,
                }
            else:
                return {
                    "result": f"Host {host_name} logs indicate normal approved behavior matching scheduled maintenance windows.",
                    "reward": 0.001,
                    "done": False,
                }
        return {
            "result": f"Host {host_name} has no abnormal logs.",
            "reward": 0.001,
            "done": False,
        }

    def _tool_check_hash(self, file_hash: str) -> dict:
        if self._done or self._current_index >= len(self._alerts):
            return {"error": "Episode is done.", "reward": 0.001, "done": True}
        alert = self._alerts[self._current_index]
        self._current_investigated_hash = True

        if file_hash == alert.file_hash:
            if alert.malicious:
                return {
                    "result": f"Hash {file_hash} matches a known zero-day payload family (Confidence: 99%).",
                    "reward": 0.001,
                    "done": False,
                }
            else:
                return {
                    "result": f"Hash {file_hash} is digitally signed by Microsoft Corporation. Valid updater.",
                    "reward": 0.001,
                    "done": False,
                }
        return {
            "result": f"Hash {file_hash} not found in threat database.",
            "reward": 0.001,
            "done": False,
        }

    # --- Core Actions ---
    def _get_current_alert(self) -> dict:
        if self._done:
            return {"error": "Episode is done.", "done": True}
        if self._current_index < len(self._alerts):
            return alert_to_dict(self._alerts[self._current_index])
        return {"error": "No more alerts to process.", "done": True}

    def _get_queue_status(self) -> dict:
        return {
            "total": self._total_alerts,
            "processed": self._processed_count,
            "remaining": self._total_alerts - self._processed_count,
            "cumulative_reward": _safe_clamp(self._cumulative_reward / max(self._processed_count, 1)),
            "done": self._done,
        }

    def _process_triage(
        self,
        category: str,
        priority: str,
        route_to: str,
        response_draft: str = "",
        flag: bool = False,
    ) -> dict:
        if self._done or self._current_index >= len(self._alerts):
            return {
                "error": "Episode is done.",
                "done": True,
                "reward": 0.001,
                "final_score": _safe_clamp(self._cumulative_reward / max(self._processed_count, 1)),
            }

        errors = []
        if category.lower().strip() not in CATEGORIES:
            errors.append(f"Invalid category '{category}'.")
        if priority.lower().strip() not in PRIORITIES:
            errors.append(f"Invalid priority '{priority}'.")
        if route_to.lower().strip() not in DEPARTMENTS:
            errors.append(f"Invalid department '{route_to}'.")

        if errors:
            self._last_error = "; ".join(errors)
            return {
                "error": self._last_error,
                "done": False,
                "reward": 0.001,
                "hint": "Fix the errors and try again. Turn not ended.",
            }

        action = SOCTriageAction(
            category=category.lower().strip(),
            priority=priority.lower().strip(),
            route_to=route_to.lower().strip(),
            response_draft=response_draft,
            flag=flag,
        )

        current_alert = self._alerts[self._current_index]
        inv_state = {
            "ip": self._current_investigated_ip,
            "host": self._current_investigated_host,
            "hash": self._current_investigated_hash,
        }
        self._investigation_states.append(inv_state)

        # Calculate intermediate step reward identical to final grading
        grader = TASK_GRADERS[self._task_name]
        try:
            reward = grader.grade([action], [current_alert], [inv_state])
        except Exception:
            reward = 0.001

        self._actions_taken.append(action)
        self._rewards.append(reward)
        self._cumulative_reward += reward
        self._processed_count += 1
        self._current_index += 1

        # Reset investigation state for next alert
        self._current_investigated_ip = False
        self._current_investigated_host = False
        self._current_investigated_hash = False
        self._last_error = None

        is_done = self._current_index >= len(self._alerts)
        self._done = is_done

        clamped_reward = _safe_clamp(reward)

        result = {
            "reward": clamped_reward,
            "done": is_done,
            "processed": self._processed_count,
            "remaining": self._total_alerts - self._processed_count,
        }

        if not is_done:
            result["next_alert"] = alert_to_dict(self._alerts[self._current_index])
        else:
            try:
                raw_final = grader.grade(self._actions_taken, self._alerts, self._investigation_states)
            except Exception:
                raw_final = 0.5
            final_score = _safe_clamp(raw_final, default=0.5)
            result["final_score"] = final_score
            result["message"] = f"Episode complete! Final graded score: {final_score:.4f}"

        return result

    def _step_impl(
        self,
        action: Action,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> Observation:
        return Observation(
            done=self._done,
            reward=0.001,
            metadata={"error": "Use MCP tools."},
        )

    def step(self, action: Action, timeout_s: Optional[float] = None, **kwargs: Any) -> Observation:
        self._state.step_count += 1
        return super().step(action, timeout_s=timeout_s, **kwargs)

    async def step_async(self, action: Action, timeout_s: Optional[float] = None, **kwargs: Any) -> Observation:
        self._state.step_count += 1
        return await super().step_async(action, timeout_s=timeout_s, **kwargs)

    @property
    def state(self) -> State:
        return self._state