"""Unit tests for combined explainable intrusion detector."""

import pytest
from simulator.models import PacketEvent, Protocol
from detection.combined_detector import CombinedExplainableDetector
from detection.models import Severity, DetectionMethod
from utils.config import RiskScoringConfig


def test_combined_detector_scoring_and_explanation():
    cfg = RiskScoringConfig(
        rule_weight=0.6,
        anomaly_weight=0.4,
        critical_threshold=90.0,
    )
    detector = CombinedExplainableDetector(config=cfg)

    # Establish baseline in adaptive detector
    for i in range(30):
        ev = PacketEvent(timestamp=100.0 + i * 0.1, is_malicious=False)
        detector.adaptive_detector.process_event(ev)
    detector.adaptive_detector.flush_window(current_time=105.0)

    # Now generate a series of SYN flood events that exceed both rule and surge rate
    alerts = []
    clock = 110.0
    for i in range(15):
        clock += 0.05
        ev = PacketEvent(
            timestamp=clock,
            src_ip="192.168.1.205",
            dst_ip="192.168.1.10",
            src_port=2000 + i,
            dst_port=80,
            protocol=Protocol.TCP.value,
            tcp_flags="SYN",
            is_malicious=True,
            attack_type="syn_flood",
        )
        alerts.extend(detector.process_event(ev))

    # We should have emitted combined alerts
    assert len(alerts) >= 1
    comb_alert = alerts[0]
    assert comb_alert.method == DetectionMethod.COMBINED_EXPLAINABLE
    assert comb_alert.risk_score > 0
    assert comb_alert.explanation is not None
    assert comb_alert.explanation.reason != ""
    assert comb_alert.explanation.observed_value != ""
    assert comb_alert.explanation.threshold_or_baseline != ""


def test_severity_mapping():
    detector = CombinedExplainableDetector()
    assert detector._map_score_to_severity(95.0) == Severity.CRITICAL
    assert detector._map_score_to_severity(80.0) == Severity.HIGH
    assert detector._map_score_to_severity(60.0) == Severity.MEDIUM
    assert detector._map_score_to_severity(20.0) == Severity.LOW
