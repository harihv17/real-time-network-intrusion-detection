"""Alert structures and explainability models for intrusion detection."""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, Dict, Any
import time
import uuid


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectionMethod(str, Enum):
    RULE_BASED = "Rule-Based"
    ADAPTIVE_BASELINE = "Adaptive Baseline"
    COMBINED_EXPLAINABLE = "Combined Explainable"


@dataclass
class Explanation:
    """Structured breakdown explaining why an alert was triggered across 7 core forensic questions."""
    rule_or_condition: str
    observed_value: Any
    threshold_or_baseline: Any
    entity: str
    reason: str
    feature_name: str = "general"
    z_score: Optional[float] = None

    # 7-question forensic explainability fields for academic and SOC review
    what_happened: str = ""
    evidence_summary: str = ""
    expected_baseline: str = ""
    trigger_comparison: str = ""
    detector_source: str = ""
    severity_rationale: str = ""
    operational_limitations: str = ""

    def __post_init__(self):
        # Auto-populate 7-question fields from primary fields if not explicitly provided
        if not self.what_happened:
            self.what_happened = self.reason
        if not self.evidence_summary:
            self.evidence_summary = f"Observed {self.feature_name}: {self.observed_value}"
        if not self.expected_baseline:
            self.expected_baseline = f"Expected threshold / normal baseline: {self.threshold_or_baseline}"
        if not self.trigger_comparison:
            self.trigger_comparison = f"Observed [{self.observed_value}] crossed configured rule condition [{self.threshold_or_baseline}]"
        if not self.detector_source:
            self.detector_source = self.rule_or_condition
        if not self.severity_rationale:
            self.severity_rationale = "Severity scored according to threat confidence and impact weighting."
        if not self.operational_limitations:
            self.operational_limitations = (
                "Automated detection identifies suspicious traffic anomaly patterns; "
                "benign bursts (e.g. software updates or rapid browser tabs) may resemble attack signatures."
            )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Alert:
    """Security alert emitted by any detection module."""
    alert_id: str = field(default_factory=lambda: f"ALT-{str(uuid.uuid4())[:6].upper()}")
    timestamp: float = field(default_factory=time.time)
    src_ip: str = "0.0.0.0"
    dst_ip: Optional[str] = None
    method: DetectionMethod = DetectionMethod.RULE_BASED
    severity: Severity = Severity.MEDIUM
    risk_score: float = 50.0
    explanation: Optional[Explanation] = None
    status: str = "Active"
    attack_type: str = "unknown"
    event_id: Optional[str] = None
    ground_truth_malicious: Optional[bool] = None
    data_source: str = "Live Capture"  # "Live Capture" or "Simulation"

    def to_dict(self) -> dict:
        data = asdict(self)
        data["method"] = self.method.value if isinstance(self.method, DetectionMethod) else self.method
        data["severity"] = self.severity.value if isinstance(self.severity, Severity) else self.severity
        if self.explanation:
            data["explanation"] = self.explanation.to_dict()
        return data
