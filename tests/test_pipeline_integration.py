"""Integration test running simulation engine and detection pipeline end-to-end."""

import pytest
from simulator.engine import SimulationEngine
from simulator.models import ScenarioType
from detection.engine import DetectionPipeline
from detection.models import DetectionMethod, Severity


def test_end_to_end_pipeline():
    engine = SimulationEngine()
    pipeline = DetectionPipeline()

    # Step 1: Run normal traffic
    engine.set_scenario(ScenarioType.NORMAL)
    normal_events = engine.step(num_events=30, use_real_timestamp=False)
    for ev in normal_events:
        pipeline.process_event(ev, active_method=DetectionMethod.COMBINED_EXPLAINABLE)

    # Verify no high/critical alerts on normal traffic
    alerts = pipeline.get_recent_alerts(limit=50)
    critical_alerts = [a for a in alerts if a.severity in (Severity.HIGH, Severity.CRITICAL)]
    assert len(critical_alerts) == 0

    # Step 2: Switch to port scan scenario and step
    engine.set_scenario(ScenarioType.PORT_SCAN)
    attack_events = engine.step(num_events=20, use_real_timestamp=False)
    for ev in attack_events:
        pipeline.process_event(ev, active_method=DetectionMethod.COMBINED_EXPLAINABLE)

    # Verify that alerts are generated
    all_alerts = pipeline.get_recent_alerts(limit=50)
    assert len(all_alerts) > 0

    # Verify pipeline metrics summary
    summary = pipeline.get_metrics_summary()
    assert summary["total_alerts"] > 0
    assert "baseline_stats" in summary
