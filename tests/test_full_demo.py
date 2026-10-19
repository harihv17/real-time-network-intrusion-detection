"""Full 5-minute faculty demonstration script test.

Validates the complete demonstration workflow:
1. Normal traffic streaming
2. Port-scan scenario & rule-based alert generation
3. Traffic surge & adaptive detector baseline vs threshold
4. Combined alert explainability inspection
5. Controlled benchmark evaluation comparing Rule, Adaptive, and Combined
6. CSV export of packet events and security alerts
"""

import pytest
from simulator.engine import SimulationEngine
from simulator.models import ScenarioType
from detection.engine import DetectionPipeline
from detection.models import DetectionMethod, Severity
from analytics.experiment_runner import ExperimentRunner
from utils.export import export_events_to_csv, export_alerts_to_csv


def test_five_minute_faculty_demo_flow():
    engine = SimulationEngine()
    pipeline = DetectionPipeline()

    # Step 1: Normal traffic streaming
    engine.set_scenario(ScenarioType.NORMAL)
    normal_events = engine.step(num_events=30, use_real_timestamp=False)
    for ev in normal_events:
        pipeline.process_event(ev, active_method=DetectionMethod.COMBINED_EXPLAINABLE)

    base_status = pipeline.adaptive_detector.get_baseline_status()
    assert base_status["sample_count"] >= 0
    alerts_stage1 = pipeline.get_recent_alerts(limit=50)
    # Under pure normal traffic, no critical alerts should occur
    assert sum(1 for a in alerts_stage1 if a.severity == Severity.CRITICAL) == 0

    # Step 2: Activate Port-Scan scenario
    engine.set_scenario(ScenarioType.PORT_SCAN)
    scan_events = engine.step(num_events=25, use_real_timestamp=False)
    for ev in scan_events:
        pipeline.process_event(ev, active_method=DetectionMethod.COMBINED_EXPLAINABLE)

    alerts_stage2 = pipeline.get_recent_alerts(limit=50)
    port_scan_alerts = [a for a in alerts_stage2 if a.attack_type == "port_scan"]
    assert len(port_scan_alerts) > 0, "Port scan scenario must trigger detection alerts"

    # Step 3: Trigger Traffic Spike / High Rate
    engine.set_scenario(ScenarioType.HIGH_RATE)
    rate_events = engine.step(num_events=40, use_real_timestamp=False)
    for ev in rate_events:
        pipeline.process_event(ev, active_method=DetectionMethod.COMBINED_EXPLAINABLE)

    alerts_stage3 = pipeline.get_recent_alerts(limit=100)
    high_rate_alerts = [a for a in alerts_stage3 if a.attack_type in ("high_traffic_rate", "statistical_anomaly")]
    assert len(high_rate_alerts) > 0

    # Step 4: Validate Alert Explainability Structure
    for a in alerts_stage3:
        assert a.explanation is not None
        assert len(a.explanation.rule_or_condition) > 0
        assert len(str(a.explanation.observed_value)) > 0
        assert len(str(a.explanation.threshold_or_baseline)) > 0
        assert len(a.explanation.reason) > 0
        assert a.risk_score >= 0.0

    # Step 5: Run Controlled Benchmark Experiment
    runner = ExperimentRunner(pipeline.config)
    result = runner.run_benchmark(
        scenario=ScenarioType.PORT_SCAN,
        total_events=100,
        warmup_events=30,
        random_seed=42,
    )
    assert len(result.reports) == 3
    r_rep = result.reports["Rule-Based Detector"]
    a_rep = result.reports["Adaptive Baseline Detector"]
    c_rep = result.reports["Combined Explainable Detector"]

    assert r_rep.confusion_matrix.total == 100
    assert a_rep.confusion_matrix.total == 100
    assert c_rep.confusion_matrix.total == 100

    # Step 6: CSV Export Generation
    events_csv = export_events_to_csv(list(engine.event_buffer))
    alerts_csv = export_alerts_to_csv(list(pipeline.alerts_history))

    assert len(events_csv) > 100
    assert "src_ip,dst_ip" in events_csv
    assert len(alerts_csv) > 50
    assert "alert_id,timestamp" in alerts_csv
