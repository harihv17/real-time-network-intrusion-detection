"""Combined explainable intrusion detector.

Fuses signature-based heuristics and statistical baseline anomaly scores into
a unified, interpretable risk assessment with full forensic breakdowns.
"""

from typing import List, Optional, Tuple
import time
from simulator.models import PacketEvent
from detection.models import Alert, Severity, DetectionMethod, Explanation
from detection.rule_based import RuleBasedDetector
from detection.adaptive_baseline import AdaptiveBaselineDetector
from utils.config import RiskScoringConfig, DEFAULT_CONFIG


class CombinedExplainableDetector:
    """Orchestrates rule and adaptive detectors to emit unified, explainable alerts."""

    def __init__(
        self,
        rule_detector: Optional[RuleBasedDetector] = None,
        adaptive_detector: Optional[AdaptiveBaselineDetector] = None,
        config: Optional[RiskScoringConfig] = None,
    ):
        self.config = config or DEFAULT_CONFIG.risk
        self.rule_detector = rule_detector or RuleBasedDetector()
        self.adaptive_detector = adaptive_detector or AdaptiveBaselineDetector()

    def reset(self) -> None:
        """Resets both underlying detection engines."""
        self.rule_detector.reset()
        self.adaptive_detector.reset()

    def process_event(self, event: PacketEvent) -> List[Alert]:
        """Runs both detectors on an event and fuses findings into explainable combined alerts."""
        rule_alerts = self.rule_detector.process_event(event)
        adaptive_alerts = self.adaptive_detector.process_event(event)

        if not rule_alerts and not adaptive_alerts:
            return []

        # Case 1: Both detectors flagged suspicious activity simultaneously (high-confidence alert)
        if rule_alerts and adaptive_alerts:
            return self._fuse_dual_alerts(rule_alerts, adaptive_alerts, event)

        # Case 2: Only Rule-based alerts triggered
        if rule_alerts:
            return self._wrap_rule_alerts(rule_alerts, event)

        # Case 3: Only Adaptive anomaly alerts triggered
        return self._wrap_adaptive_alerts(adaptive_alerts, event)

    def _fuse_dual_alerts(
        self, rule_alerts: List[Alert], adaptive_alerts: List[Alert], event: PacketEvent
    ) -> List[Alert]:
        """Fuses rule and anomaly alerts into a high-severity correlated alert."""
        fused_alerts: List[Alert] = []
        is_sim = "Simulated" in getattr(event, "scenario", "") or getattr(event, "scenario", "") != "Live Network Traffic"
        data_source = "Simulation" if is_sim else "Live Capture"

        for r_alert in rule_alerts:
            a_alert = adaptive_alerts[0]  # Take primary anomaly context

            # Calculate fused risk score: weighted combination + 15-point cross-validation bonus
            base_score = (
                self.config.rule_weight * r_alert.risk_score
                + self.config.anomaly_weight * a_alert.risk_score
            )
            fused_score = min(100.0, round(base_score + 15.0, 1))

            severity = Severity.CRITICAL if fused_score >= self.config.critical_threshold else Severity.HIGH

            combined_explanation = Explanation(
                rule_or_condition=f"{r_alert.explanation.rule_or_condition} + {a_alert.explanation.rule_or_condition}",
                observed_value=(
                    f"Signature: {r_alert.explanation.observed_value} | "
                    f"Traffic Volume: {a_alert.explanation.observed_value}"
                ),
                threshold_or_baseline=(
                    f"Rule: {r_alert.explanation.threshold_or_baseline} | "
                    f"Baseline: {a_alert.explanation.threshold_or_baseline}"
                ),
                entity=r_alert.src_ip,
                reason=(
                    f"High-confidence intrusion: Both heuristic rule ({r_alert.explanation.rule_or_condition}) "
                    f"and statistical deviation ({a_alert.explanation.rule_or_condition}) triggered concurrently."
                ),
                feature_name=f"{r_alert.explanation.feature_name}+{a_alert.explanation.feature_name}",
                z_score=a_alert.explanation.z_score,
                what_happened=(
                    f"Dual-corroborated intrusion detected: Host {r_alert.src_ip} triggered heuristic rule "
                    f"[{r_alert.attack_type}] while traffic rate simultaneously surged anomalously."
                ),
                evidence_summary=(
                    f"Signature Evidence: {r_alert.explanation.evidence_summary} | "
                    f"Statistical Evidence: {a_alert.explanation.evidence_summary}"
                ),
                expected_baseline=(
                    f"Rule Ceiling: [{r_alert.explanation.expected_baseline}] | "
                    f"Statistical Baseline: [{a_alert.explanation.expected_baseline}]"
                ),
                trigger_comparison=(
                    f"Dual-threshold breach: [{r_alert.explanation.trigger_comparison}] and "
                    f"[{a_alert.explanation.trigger_comparison}]"
                ),
                detector_source="Combined Explainable Correlator (Heuristic Signature + Adaptive EWMA Baseline Fusion)",
                severity_rationale=(
                    f"Composite risk score {fused_score}/100.0 ({self.config.rule_weight:.0%} Rule [{r_alert.risk_score}] + "
                    f"{self.config.anomaly_weight:.0%} Anomaly [{a_alert.risk_score}] + 15pt cross-verification bonus) -> {severity.value}."
                ),
                operational_limitations=(
                    "Dual-engine agreement offers the lowest false-positive probability. "
                    "However, high-volume legitimate stress tests or pen-testing suites also trigger dual alerts."
                ),
            )

            fused_alerts.append(Alert(
                timestamp=event.timestamp,
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                method=DetectionMethod.COMBINED_EXPLAINABLE,
                severity=severity,
                risk_score=fused_score,
                attack_type=r_alert.attack_type,
                event_id=event.event_id,
                ground_truth_malicious=event.is_malicious,
                data_source=data_source,
                explanation=combined_explanation,
            ))

        return fused_alerts

    def _wrap_rule_alerts(self, rule_alerts: List[Alert], event: PacketEvent) -> List[Alert]:
        """Translates rule alerts into the combined scoring format with baseline context."""
        fused: List[Alert] = []
        baseline_stats = self.adaptive_detector.get_baseline_status()
        is_sim = "Simulated" in getattr(event, "scenario", "") or getattr(event, "scenario", "") != "Live Network Traffic"
        data_source = "Simulation" if is_sim else "Live Capture"

        for r in rule_alerts:
            # Score adjusted by rule weight
            score = round(r.risk_score * (0.8 + 0.2 * self.config.rule_weight), 1)
            severity = self._map_score_to_severity(score)

            exp = r.explanation
            exp_text = (
                f"{exp.reason} (Note: Adaptive baseline observed rate = "
                f"{baseline_stats['last_observed_rate']} pkts/s vs mean {baseline_stats['mean_rate']} pkts/s)."
            )

            fused.append(Alert(
                timestamp=r.timestamp,
                src_ip=r.src_ip,
                dst_ip=r.dst_ip,
                method=DetectionMethod.COMBINED_EXPLAINABLE,
                severity=severity,
                risk_score=score,
                attack_type=r.attack_type,
                event_id=event.event_id,
                ground_truth_malicious=event.is_malicious,
                data_source=data_source,
                explanation=Explanation(
                    rule_or_condition=exp.rule_or_condition,
                    observed_value=exp.observed_value,
                    threshold_or_baseline=exp.threshold_or_baseline,
                    entity=exp.entity,
                    reason=exp_text,
                    feature_name=exp.feature_name,
                    z_score=baseline_stats.get("last_z_score"),
                    what_happened=exp.what_happened,
                    evidence_summary=f"{exp.evidence_summary} (Baseline context: mean={baseline_stats['mean_rate']:.1f} pkts/s)",
                    expected_baseline=exp.expected_baseline,
                    trigger_comparison=exp.trigger_comparison,
                    detector_source=f"Combined Correlator [Triggered via {exp.detector_source}]",
                    severity_rationale=f"Risk score {score}/100.0 mapped to {severity.value} based on heuristic rule confidence.",
                    operational_limitations=exp.operational_limitations,
                ),
            ))
        return fused

    def _wrap_adaptive_alerts(self, adaptive_alerts: List[Alert], event: PacketEvent) -> List[Alert]:
        """Translates purely statistical alerts into the combined scoring format."""
        fused: List[Alert] = []
        is_sim = "Simulated" in getattr(event, "scenario", "") or getattr(event, "scenario", "") != "Live Network Traffic"
        data_source = "Simulation" if is_sim else "Live Capture"

        for a in adaptive_alerts:
            score = round(a.risk_score * (0.8 + 0.2 * self.config.anomaly_weight), 1)
            severity = self._map_score_to_severity(score)

            exp = a.explanation
            fused.append(Alert(
                timestamp=a.timestamp,
                src_ip=a.src_ip,
                dst_ip=a.dst_ip,
                method=DetectionMethod.COMBINED_EXPLAINABLE,
                severity=severity,
                risk_score=score,
                attack_type=a.attack_type,
                event_id=event.event_id,
                ground_truth_malicious=event.is_malicious,
                data_source=data_source,
                explanation=Explanation(
                    rule_or_condition=exp.rule_or_condition,
                    observed_value=exp.observed_value,
                    threshold_or_baseline=exp.threshold_or_baseline,
                    entity=exp.entity,
                    reason=exp.reason,
                    feature_name=exp.feature_name,
                    z_score=exp.z_score,
                    what_happened=exp.what_happened,
                    evidence_summary=exp.evidence_summary,
                    expected_baseline=exp.expected_baseline,
                    trigger_comparison=exp.trigger_comparison,
                    detector_source=f"Combined Correlator [Triggered via {exp.detector_source}]",
                    severity_rationale=f"Risk score {score}/100.0 mapped to {severity.value} based on EWMA deviation magnitude.",
                    operational_limitations=exp.operational_limitations,
                ),
            ))
        return fused

    def _map_score_to_severity(self, score: float) -> Severity:
        """Categorizes raw risk score into standardized SOC severity."""
        if score >= self.config.critical_threshold:
            return Severity.CRITICAL
        elif score >= self.config.high_threshold:
            return Severity.HIGH
        elif score >= self.config.medium_threshold:
            return Severity.MEDIUM
        return Severity.LOW
