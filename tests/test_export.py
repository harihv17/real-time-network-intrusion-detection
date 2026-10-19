"""Unit tests for data export functions."""

import pytest
from simulator.models import PacketEvent
from detection.models import Alert, Severity, DetectionMethod, Explanation
from utils.export import (
    export_events_to_dataframe,
    export_events_to_csv,
    export_alerts_to_dataframe,
    export_alerts_to_csv,
    export_experiment_to_csv,
)


def test_export_events():
    events = [
        PacketEvent(src_ip="192.168.1.101", dst_port=80, packet_size=350),
        PacketEvent(src_ip="192.168.1.199", dst_port=22, packet_size=54, is_malicious=True),
    ]
    df = export_events_to_dataframe(events)
    assert len(df) == 2
    assert "src_ip" in df.columns
    assert "is_malicious" in df.columns

    csv_str = export_events_to_csv(events)
    assert "192.168.1.101" in csv_str
    assert "192.168.1.199" in csv_str


def test_export_alerts():
    alerts = [
        Alert(
            src_ip="192.168.1.199",
            method=DetectionMethod.RULE_BASED,
            severity=Severity.HIGH,
            risk_score=75.0,
            attack_type="port_scan",
            explanation=Explanation(
                rule_or_condition="PortScanRule",
                observed_value="10 ports",
                threshold_or_baseline="8 ports",
                entity="192.168.1.199",
                reason="Scanning detected",
            ),
        )
    ]
    df = export_alerts_to_dataframe(alerts)
    assert len(df) == 1
    assert df["rule_or_condition"].iloc[0] == "PortScanRule"
    assert df["risk_score"].iloc[0] == 75.0

    csv_str = export_alerts_to_csv(alerts)
    assert "PortScanRule" in csv_str


def test_export_experiment():
    rows = [{"detector": "Rule-Based", "precision": 0.9, "recall": 0.85, "f1_score": 0.87}]
    csv_str = export_experiment_to_csv(rows)
    assert "Rule-Based" in csv_str
    assert "precision" in csv_str
