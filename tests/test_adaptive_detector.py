"""Unit tests for adaptive statistical baseline anomaly detector."""

import pytest
from simulator.models import PacketEvent
from detection.adaptive_baseline import AdaptiveBaselineDetector
from utils.config import AdaptiveDetectorConfig


def test_adaptive_warmup_and_zero_variance_safety():
    cfg = AdaptiveDetectorConfig(
        warmup_samples=5,
        window_interval_seconds=1.0,
        z_score_threshold=2.5,
        min_std_floor=1.0,
    )
    detector = AdaptiveBaselineDetector(config=cfg)

    assert not detector.is_warmed_up
    assert detector.std_rate >= 1.0  # Safe floor prevents zero-division

    # Feed 5 windows of steady normal traffic (10 pkts each)
    clock = 100.0
    for w in range(5):
        for p in range(10):
            ev = PacketEvent(timestamp=clock + p * 0.08, packet_size=500, is_malicious=False)
            detector.process_event(ev)
        clock += 1.0

    # Trigger window evaluation
    detector.flush_window(current_time=clock)

    assert detector.is_warmed_up
    status = detector.get_baseline_status()
    assert status["is_warmed_up"] is True
    assert status["sample_count"] >= 5
    assert status["mean_rate"] > 0


def test_adaptive_anomaly_detection_on_traffic_surge():
    cfg = AdaptiveDetectorConfig(
        warmup_samples=4,
        window_interval_seconds=1.0,
        z_score_threshold=2.0,
        min_std_floor=1.0,
    )
    detector = AdaptiveBaselineDetector(config=cfg)

    # 1. Warm-up with normal rate of 5 packets/sec
    clock = 100.0
    for w in range(5):
        for p in range(5):
            ev = PacketEvent(timestamp=clock + p * 0.15, packet_size=200, is_malicious=False)
            detector.process_event(ev)
        clock += 1.0

    detector.flush_window(current_time=clock)
    assert detector.is_warmed_up

    # 2. Inject massive sudden traffic spike (50 packets in 1 second)
    surge_alerts = []
    clock += 1.0
    for p in range(50):
        ev = PacketEvent(timestamp=clock + p * 0.015, packet_size=1400, is_malicious=True)
        alerts = detector.process_event(ev)
        surge_alerts.extend(alerts)

    # Flush window to capture the spike
    clock += 1.0
    surge_alerts.extend(detector.flush_window(current_time=clock))

    assert len(surge_alerts) >= 1
    alert = surge_alerts[0]
    assert alert.method.value == "Adaptive Baseline"
    assert alert.explanation.z_score is not None
    assert alert.explanation.z_score >= 2.0


def test_baseline_contamination_prevention():
    cfg = AdaptiveDetectorConfig(
        warmup_samples=3,
        window_interval_seconds=1.0,
    )
    detector = AdaptiveBaselineDetector(config=cfg)

    # If traffic during warm-up is flagged as malicious (e.g. simulated attack traffic),
    # it must NOT be absorbed into the normal baseline!
    clock = 100.0
    for p in range(20):
        ev = PacketEvent(timestamp=clock + p * 0.04, packet_size=1500, is_malicious=True)
        detector.process_event(ev)

    clock += 1.1
    detector.flush_window(current_time=clock)

    # The sample count should still be 0 because malicious traffic was excluded from baseline training
    assert detector.sample_count == 0
    assert detector.mean_rate == 0.0
