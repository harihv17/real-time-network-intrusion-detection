"""Unit and integration tests for explainability questions, capture pause/resume, and export fields."""

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from simulator.models import PacketEvent, Protocol
from capture.engine import LiveCaptureEngine, CaptureState
from detection.models import Alert, Severity, DetectionMethod, Explanation
from detection.rule_based import RuleBasedDetector
from detection.adaptive_baseline import AdaptiveBaselineDetector
from detection.combined_detector import CombinedExplainableDetector
from detection.engine import DetectionPipeline
from utils.export import export_alerts_to_dataframe, export_events_to_dataframe, export_alerts_to_csv


def test_seven_question_explainability_in_rule_alerts():
    """Validates that rule-based alerts contain answers to all 7 academic forensic questions."""
    detector = RuleBasedDetector()
    attacker = "192.168.1.199"
    scan_ports = [21, 22, 23, 25, 80, 443, 8080, 3306, 5432]

    alerts = []
    for port in scan_ports:
        ev = PacketEvent(
            timestamp=1000.0,
            src_ip=attacker,
            dst_ip="192.168.1.1",
            src_port=40000,
            dst_port=port,
            protocol=Protocol.TCP.value,
            tcp_flags="SYN",
            is_malicious=True,
            attack_type="port_scan",
        )
        alerts.extend(detector.process_event(ev))

    assert len(alerts) >= 1
    exp = alerts[0].explanation
    assert exp is not None

    # Verify all 7 core questions are answered
    assert exp.what_happened != "", "Q1: What happened must be answered"
    assert exp.evidence_summary != "", "Q2: Evidence summary must be answered"
    assert exp.expected_baseline != "", "Q3: Expected baseline must be answered"
    assert exp.trigger_comparison != "", "Q4: Trigger comparison must be answered"
    assert exp.detector_source != "", "Q5: Detector source must be answered"
    assert exp.severity_rationale != "", "Q6: Severity rationale must be answered"
    assert exp.operational_limitations != "", "Q7: Operational limitations must be answered"


def test_seven_question_explainability_in_combined_alerts():
    """Validates that combined explainable alerts synthesize dual evidence into 7-question answers."""
    detector = CombinedExplainableDetector()

    # Warm up adaptive baseline
    for i in range(30):
        ev = PacketEvent(timestamp=100.0 + i * 0.1, is_malicious=False)
        detector.adaptive_detector.process_event(ev)
    detector.adaptive_detector.flush_window(current_time=105.0)

    # Surge of SYN packets
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

    assert len(alerts) >= 1
    comb_exp = alerts[0].explanation
    assert comb_exp is not None
    assert "What happened" in comb_exp.what_happened or len(comb_exp.what_happened) > 10
    assert comb_exp.evidence_summary != ""
    assert comb_exp.trigger_comparison != ""
    assert "Correlator" in comb_exp.detector_source or "Engine" in comb_exp.detector_source
    assert comb_exp.severity_rationale != ""
    assert comb_exp.operational_limitations != ""


def test_live_capture_engine_pause_and_resume():
    """Verifies that LiveCaptureEngine supports pause, resume, and rate tracking."""
    engine = LiveCaptureEngine()
    assert engine.state == CaptureState.STOPPED

    # Test state transitions
    engine.state = CaptureState.CAPTURING
    engine.pause_capture()
    assert engine.state == CaptureState.PAUSED
    assert engine.is_paused is True

    # Packets ingested while paused are ignored
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80)
    engine._packet_callback(pkt)
    assert engine.captured_packets_count == 0

    # Resume
    engine.resume_capture()
    assert engine.state == CaptureState.CAPTURING
    assert engine.is_paused is False

    # Ingest direct
    engine.ingest_packet_direct(pkt)
    assert engine.captured_packets_count == 1
    assert engine.current_packet_rate >= 0.0

    engine.stop_capture()
    assert engine.state == CaptureState.STOPPED


def test_export_dataframes_include_source_and_explainability():
    """Verifies that DataFrame and CSV exports contain data_source and all 7 explainability columns."""
    exp = Explanation(
        rule_or_condition="TestRule",
        observed_value="10 pkts",
        threshold_or_baseline="5 pkts",
        entity="192.168.1.50",
        reason="Test alert reason",
        what_happened="Surge happened",
        evidence_summary="10 packets observed",
        expected_baseline="Expected 5",
        trigger_comparison="10 >= 5",
        detector_source="Unit Test Detector",
        severity_rationale="Severity mapped based on test",
        operational_limitations="Test limitation",
    )
    alert = Alert(
        src_ip="192.168.1.50",
        method=DetectionMethod.RULE_BASED,
        severity=Severity.HIGH,
        risk_score=75.0,
        explanation=exp,
        data_source="Live Capture",
    )

    df_alerts = export_alerts_to_dataframe([alert])
    assert "data_source" in df_alerts.columns
    assert "what_happened" in df_alerts.columns
    assert "evidence_summary" in df_alerts.columns
    assert "expected_baseline" in df_alerts.columns
    assert "trigger_comparison" in df_alerts.columns
    assert "detector_source" in df_alerts.columns
    assert "severity_rationale" in df_alerts.columns
    assert "operational_limitations" in df_alerts.columns

    assert df_alerts["data_source"].iloc[0] == "Live Capture"
    assert df_alerts["what_happened"].iloc[0] == "Surge happened"

    csv_out = export_alerts_to_csv([alert])
    assert "data_source" in csv_out
    assert "operational_limitations" in csv_out

    # Events export check
    ev = PacketEvent(scenario="Live Network Traffic", is_malicious=False)
    df_events = export_events_to_dataframe([ev])
    assert "data_source" in df_events.columns
    assert df_events["data_source"].iloc[0] == "Live Capture"
