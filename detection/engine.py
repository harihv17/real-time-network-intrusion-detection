"""Unified detection pipeline orchestrator."""

from collections import deque
from typing import List, Dict, Optional, Any
from simulator.models import PacketEvent
from detection.models import Alert, DetectionMethod, Severity
from detection.rule_based import RuleBasedDetector
from detection.adaptive_baseline import AdaptiveBaselineDetector
from detection.combined_detector import CombinedExplainableDetector
from utils.config import DEFAULT_CONFIG, SystemConfig


class DetectionPipeline:
    """Manages the parallel execution of all detectors and centralizes alert records."""

    def __init__(self, config: Optional[SystemConfig] = None):
        self.config = config or DEFAULT_CONFIG
        self.rule_detector = RuleBasedDetector(self.config.rules)
        self.adaptive_detector = AdaptiveBaselineDetector(self.config.adaptive)
        self.combined_detector = CombinedExplainableDetector(
            rule_detector=self.rule_detector,
            adaptive_detector=self.adaptive_detector,
            config=self.config.risk,
        )

        # Central alert repositories bounded to avoid unbounded memory usage
        self.alerts_history: deque[Alert] = deque(maxlen=self.config.simulator.max_alerts_history)

        # Counters
        self.total_alerts_count: int = 0
        self.alerts_by_severity: Dict[str, int] = {s.value: 0 for s in Severity}
        self.alerts_by_method: Dict[str, int] = {m.value: 0 for m in DetectionMethod}

    def reset(self) -> None:
        """Resets all detectors and clears alert memory."""
        self.rule_detector.reset()
        self.adaptive_detector.reset()
        self.combined_detector.reset()
        self.alerts_history.clear()
        self.total_alerts_count = 0
        for s in Severity:
            self.alerts_by_severity[s.value] = 0
        for m in DetectionMethod:
            self.alerts_by_method[m.value] = 0

    def process_event(self, event: PacketEvent, active_method: DetectionMethod = DetectionMethod.COMBINED_EXPLAINABLE) -> List[Alert]:
        """Routes event through detectors and stores emitted alerts."""
        emitted_alerts: List[Alert] = []

        if active_method == DetectionMethod.RULE_BASED:
            emitted_alerts = self.rule_detector.process_event(event)
        elif active_method == DetectionMethod.ADAPTIVE_BASELINE:
            emitted_alerts = self.adaptive_detector.process_event(event)
        else:
            # COMBINED_EXPLAINABLE: processes both and emits explainable fused alerts
            emitted_alerts = self.combined_detector.process_event(event)

        for alert in emitted_alerts:
            self.alerts_history.append(alert)
            self.total_alerts_count += 1
            sev_key = alert.severity.value if isinstance(alert.severity, Severity) else alert.severity
            meth_key = alert.method.value if isinstance(alert.method, DetectionMethod) else alert.method
            self.alerts_by_severity[sev_key] = self.alerts_by_severity.get(sev_key, 0) + 1
            self.alerts_by_method[meth_key] = self.alerts_by_method.get(meth_key, 0) + 1

        return emitted_alerts

    def get_recent_alerts(
        self,
        limit: int = 100,
        severity_filter: Optional[str] = None,
        method_filter: Optional[str] = None,
    ) -> List[Alert]:
        """Retrieves and optionally filters historical alerts."""
        alerts = list(self.alerts_history)
        if severity_filter and severity_filter != "ALL":
            alerts = [a for a in alerts if (a.severity.value if isinstance(a.severity, Severity) else a.severity) == severity_filter]
        if method_filter and method_filter != "ALL":
            alerts = [a for a in alerts if (a.method.value if isinstance(a.method, DetectionMethod) else a.method) == method_filter]
        return alerts[-limit:] if limit > 0 else alerts

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Provides alert counts and distribution statistics."""
        return {
            "total_alerts": self.total_alerts_count,
            "critical_count": self.alerts_by_severity.get(Severity.CRITICAL.value, 0),
            "high_count": self.alerts_by_severity.get(Severity.HIGH.value, 0),
            "medium_count": self.alerts_by_severity.get(Severity.MEDIUM.value, 0),
            "low_count": self.alerts_by_severity.get(Severity.LOW.value, 0),
            "by_severity": dict(self.alerts_by_severity),
            "by_method": dict(self.alerts_by_method),
            "baseline_stats": self.adaptive_detector.get_baseline_status(),
        }
