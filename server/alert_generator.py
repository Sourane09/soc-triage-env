import random
import uuid
from datetime import datetime, timedelta
from typing import List, Optional

from ..models import SecurityAlert

# Payloads are intentionally ambiguous to force agents to use investigation tools
MALWARE_TEMPLATES = [
    {
        "signature": "Suspicious Process Execution",
        "payload": "Process powershell.exe executed with heavily obfuscated command line. File hash provided.",
        "priority": "high",
        "needs_hash": True,
        "needs_host": False,
        "needs_ip": False,
        "malicious": True,
    },
    {
        "signature": "Ransomware.Behavior.Detected",
        "payload": "vssadmin.exe called to delete shadows. Subsequent high-volume file writes.",
        "priority": "critical",
        "needs_hash": True,
        "needs_host": True,
        "needs_ip": False,
        "malicious": True,
    },
    {
        "signature": "High CPU Allocation",
        "payload": "CPU utilization hit 99% for 4 hours. Executable svc_host32.exe detected running from Temp.",
        "priority": "medium",
        "needs_hash": True,
        "needs_host": False,
        "needs_ip": True,
        "malicious": True,
    },
]

PHISHING_TEMPLATES = [
    {
        "signature": "Impossible Travel Logon",
        "payload": "Successful authentication from foreign IP. Previous login from local IP 2 hours ago.",
        "priority": "critical",
        "needs_hash": False,
        "needs_host": False,
        "needs_ip": True,
        "malicious": True,
    },
    {
        "signature": "Reported Suspicious Email",
        "payload": "User reported email with a suspicious attachment. File hash extracted from quarantine.",
        "priority": "high",
        "needs_hash": True,
        "needs_host": False,
        "needs_ip": True,
        "malicious": True,
    },
]

DDOS_TEMPLATES = [
    {
        "signature": "Traffic Volatility Alert",
        "payload": "Ingress connection rate exceeded baselines by 500x targeting edge nodes.",
        "priority": "critical",
        "needs_hash": False,
        "needs_host": False,
        "needs_ip": True,
        "malicious": True,
    },
]

EXFILTRATION_TEMPLATES = [
    {
        "signature": "Abnormal Data Transfer",
        "payload": "Large outbound HTTPS session transferring 50GB to an unclassified external IP.",
        "priority": "critical",
        "needs_hash": False,
        "needs_host": True,
        "needs_ip": True,
        "malicious": True,
    },
]

FALSE_ALARM_TEMPLATES = [
    {
        "signature": "Vulnerability Scan Activity",
        "payload": "High volume of invalid payload requests hitting WAF from internal IP. Investigate host intent.",
        "priority": "low",
        "needs_hash": False,
        "needs_host": True,
        "needs_ip": True,
        "malicious": False,
    },
    {
        "signature": "Admin Access - Unrecognized Source",
        "payload": "Root login detected on infrastructure from an unknown external IP address.",
        "priority": "low",
        "needs_hash": False,
        "needs_host": False,
        "needs_ip": True,
        "malicious": False, # IP resolves to corporate VPN
    },
    {
        "signature": "Suspicious Process Execution",
        "payload": "Executable script running with elevated permissions from C:\\Windows\\Temp.",
        "priority": "low",
        "needs_hash": True,
        "needs_host": False,
        "needs_ip": False,
        "malicious": False, # Hash turns out to be legitimate vendor updater
    },
]

COMPLIANCE_TEMPLATES = [
    {
        "signature": "Insecure Protocol Usage",
        "payload": "Telnet/FTP traffic detected over unencrypted management VLAN.",
        "priority": "medium",
        "needs_hash": False,
        "needs_host": True,
        "needs_ip": False,
        "malicious": False,
    },
]

CATEGORY_TEMPLATES = {
    "malware": MALWARE_TEMPLATES,
    "phishing": PHISHING_TEMPLATES,
    "ddos": DDOS_TEMPLATES,
    "exfiltration": EXFILTRATION_TEMPLATES,
    "false_alarm": FALSE_ALARM_TEMPLATES,
    "compliance": COMPLIANCE_TEMPLATES,
}

HOSTS = [
    "WKSTN-8921", "WKSTN-4192", "DB-PROD-01", "DB-PROD-02", "WEB-FRONTEND-A",
    "MAIL-GW-01", "HR-FILE-SHARE", "DEV-STAGING", "VPN-GATEWAY", "CEO-LAPTOP"
]

CRITICAL_INFRASTRUCTURE = [
    "DB-PROD-01", "DB-PROD-02", "WEB-FRONTEND-A", "VPN-GATEWAY", "CEO-LAPTOP"
]

DEPARTMENTS = ["tier1", "networking", "incident_response", "legal", "false_positive"]
CATEGORIES = ["malware", "phishing", "ddos", "exfiltration", "false_alarm", "compliance"]
PRIORITIES = ["low", "medium", "high", "critical"]

class AlertGenerator:
    def __init__(self, seed: Optional[int] = None):
        self.rng = random.Random(seed)
        self._alert_counter = 0

    def _generate_alert_id(self) -> str:
        self._alert_counter += 1
        return f"ALRT-{self._alert_counter:04d}"

    def _generate_timestamp(self, base_time: Optional[datetime] = None) -> str:
        if base_time is None:
            base_time = datetime(2026, 4, 1, 0, 0, 0)
        offset_minutes = self.rng.randint(0, 1440)
        ts = base_time + timedelta(minutes=offset_minutes)
        return ts.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _generate_ip(self) -> str:
        return f"{self.rng.randint(10,250)}.{self.rng.randint(1,254)}.{self.rng.randint(1,254)}.{self.rng.randint(1,254)}"

    def _generate_hash(self) -> str:
        res = ""
        for _ in range(32):
            res += self.rng.choice("0123456789abcdef")
        return res

    def _pick_host(self, is_critical: bool = False) -> str:
        if is_critical:
            return self.rng.choice(CRITICAL_INFRASTRUCTURE)
        else:
            return self.rng.choice(HOSTS)

    def _get_department_mapping(self, category: str, priority: str, is_critical: bool) -> str:
        """Route based on category alone — matches the system prompt exactly."""
        routing = {
            "false_alarm": "false_positive",
            "malware": "incident_response",
            "phishing": "tier1",
            "ddos": "networking",
            "exfiltration": "incident_response",
            "compliance": "legal",
        }
        return routing.get(category, "tier1")

    def _build_alert(self, cat: str, template: dict, is_critical: bool) -> SecurityAlert:
        host = self._pick_host(is_critical=is_critical)
        priority = template["priority"]
        if is_critical and priority in ("low", "medium"):
            priority = "high"
        if "Ransomware" in template["signature"] or "Exfiltration" in template["signature"]:
            priority = "critical"

        return SecurityAlert(
            id=self._generate_alert_id(),
            source_ip=self._generate_ip() if template["needs_ip"] else "",
            host_name=host if template["needs_host"] else "",
            file_hash=self._generate_hash() if template["needs_hash"] else "",
            signature=template["signature"],
            payload=template["payload"],
            timestamp=self._generate_timestamp(),
            is_recurring=self.rng.random() > 0.5,
            event_count=self.rng.randint(1, 100),
            severity_sensor=self.rng.randint(3, 10),
            is_critical_infrastructure=is_critical,
            true_category=cat,
            true_priority=priority,
            true_department=self._get_department_mapping(cat, priority, is_critical),
            needs_ip_investigation=template["needs_ip"],
            needs_host_investigation=template["needs_host"],
            needs_hash_investigation=template["needs_hash"],
            malicious=template["malicious"]
        )

    def generate_easy_alerts(self, count: int = 5) -> List[SecurityAlert]:
        alerts = []
        easy_categories = ["malware", "phishing", "false_alarm", "ddos"]
        for i in range(count):
            cat = easy_categories[i % len(easy_categories)]
            template = self.rng.choice(CATEGORY_TEMPLATES[cat])
            alerts.append(self._build_alert(cat, template, False))
        return alerts

    def generate_medium_alerts(self, count: int = 8) -> List[SecurityAlert]:
        alerts = []
        all_cats = list(CATEGORY_TEMPLATES.keys())
        for i in range(count):
            cat = all_cats[i % len(all_cats)]
            template = self.rng.choice(CATEGORY_TEMPLATES[cat])
            is_critical = self.rng.random() > 0.8
            alerts.append(self._build_alert(cat, template, is_critical))

        self.rng.shuffle(alerts)
        return alerts

    def generate_hard_alerts(self, count: int = 12) -> List[SecurityAlert]:
        alerts = []
        all_cats = list(CATEGORY_TEMPLATES.keys())
        for i in range(count):
            # Heavily bias towards false alarms and ambiguous contexts
            cat = "false_alarm" if i % 3 == 0 else self.rng.choice(all_cats)
            template = self.rng.choice(CATEGORY_TEMPLATES[cat])
            is_critical = self.rng.random() > 0.6
            alerts.append(self._build_alert(cat, template, is_critical))

        self.rng.shuffle(alerts)
        return alerts

def alert_to_dict(alert: SecurityAlert) -> dict:
    return {
        "id": alert.id,
        "source_ip": alert.source_ip,
        "host_name": alert.host_name,
        "file_hash": alert.file_hash,
        "signature": alert.signature,
        "payload": alert.payload,
        "timestamp": alert.timestamp,
        "is_recurring": alert.is_recurring,
        "event_count": alert.event_count,
        "severity_sensor": alert.severity_sensor,
        "is_critical_infrastructure": alert.is_critical_infrastructure,
    }
