from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from openenv.core.env_server.types import Action, Observation, State

@dataclass
class SecurityAlert:
    id: str = ""
    source_ip: str = ""
    host_name: str = ""
    file_hash: str = ""
    signature: str = ""
    payload: str = ""
    timestamp: str = ""
    is_recurring: bool = False
    event_count: int = 1
    severity_sensor: int = 0
    is_critical_infrastructure: bool = False
    
    # Ground Truth Validation (hidden)
    true_category: str = ""
    true_priority: str = ""
    true_department: str = ""
    needs_ip_investigation: bool = False
    needs_host_investigation: bool = False
    needs_hash_investigation: bool = False
    malicious: bool = False

class SOCTriageAction(Action):
    """
    Agent's final triage action.
    """
    category: str = Field(default="false_alarm")
    priority: str = Field(default="medium")
    route_to: str = Field(default="tier1")
    response_draft: str = Field(default="")
    flag: bool = Field(default=False)

class SOCTriageObservation(Observation):
    alert: Dict[str, Any] = Field(default_factory=dict)
    queue_summary: Dict[str, Any] = Field(default_factory=dict)
    available_departments: List[str] = Field(default_factory=list)
    available_categories: List[str] = Field(default_factory=list)
    available_priorities: List[str] = Field(default_factory=list)
    last_action_error: Optional[str] = Field(default=None)
    task_description: str = Field(default="")
    task_name: str = Field(default="")

    # Add dynamic investigation state fields
    investigation_results: Dict[str, Any] = Field(default_factory=dict)

class SOCTriageState(State):
    current_alert_index: int = Field(default=0)
    total_alerts: int = Field(default=0)
    score: float = Field(default=0.0)
    processed_alerts: int = Field(default=0)
    task_name: str = Field(default="")
    rewards_history: List[float] = Field(default_factory=list)
    
    # Tracking investigation actions per alert
    current_alert_investigated_ip: bool = Field(default=False)
    current_alert_investigated_host: bool = Field(default=False)
    current_alert_investigated_hash: bool = Field(default=False)
