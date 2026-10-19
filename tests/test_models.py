"""Unit tests for data models and schemas."""

import pytest
from simulator.models import PacketEvent, Protocol, ScenarioType
from detection.models import Alert, Severity, DetectionMethod, Explanation


def test_packet_event_defaults():
    event = PacketEvent()
    assert event.event_id is not None
    assert event.protocol == Protocol.TCP.value
    assert event.scenario == ScenarioType.NORMAL.value
    assert not event.is_malicious
    assert event.attack_type is None


def test_packet_event_serialization():
    event = PacketEvent(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=12345,
        dst_port=80,
        protocol=Protocol.TCP.value,
        packet_size=120,
        tcp_flags="SYN",
        scenario=ScenarioType.PORT_SCAN.value,
        is_malicious=True,
        attack_type="port_scan",
    )
    data = event.to_dict()
    assert data["src_ip"] == "10.0.0.1"
    assert data["is_malicious"] is True
    assert data["attack_type"] == "port_scan"

    rebuilt = PacketEvent.from_dict(data)
    assert rebuilt.src_ip == event.src_ip
    assert rebuilt.dst_port == event.dst_port
    assert rebuilt.is_malicious == event.is_malicious


def test_alert_model():
    exp = Explanation(
        rule_or_condition="PortScanRule",
        observed_value="10 ports",
        threshold_or_baseline="8 ports",
        entity="192.168.1.199",
        reason="Exceeded unique destination ports threshold",
        feature_name="unique_dst_ports",
    )
    alert = Alert(
        src_ip="192.168.1.199",
        method=DetectionMethod.RULE_BASED,
        severity=Severity.HIGH,
        risk_score=75.0,
        explanation=exp,
    )
    assert alert.alert_id.startswith("ALT-")
    d = alert.to_dict()
    assert d["severity"] == "HIGH"
    assert d["method"] == "Rule-Based"
    assert d["explanation"]["rule_or_condition"] == "PortScanRule"
