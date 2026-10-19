"""Unit tests for rule-based intrusion detector heuristics."""

import pytest
from simulator.models import PacketEvent, Protocol
from detection.rule_based import RuleBasedDetector
from utils.config import RuleDetectorConfig


def test_rule_detector_benign_traffic_no_alerts():
    cfg = RuleDetectorConfig(
        port_scan_threshold=5,
        high_rate_threshold=10,
        syn_flood_threshold=5,
        icmp_spike_threshold=5,
    )
    detector = RuleBasedDetector(config=cfg)

    # Stream 20 benign packets from diverse normal clients to port 80/443 with ACK flags
    alerts = []
    for i in range(20):
        ev = PacketEvent(
            timestamp=100.0 + i * 0.5,
            src_ip=f"192.168.1.{100 + (i % 5)}",
            dst_ip="192.168.1.10",
            src_port=50000 + i,
            dst_port=80,
            protocol=Protocol.TCP.value,
            tcp_flags="ACK",
            is_malicious=False,
        )
        alerts.extend(detector.process_event(ev))

    assert len(alerts) == 0, "Benign traffic must not trigger heuristic alerts."


def test_port_scan_detection_and_deduplication():
    cfg = RuleDetectorConfig(port_scan_threshold=5, port_scan_window_seconds=5.0, dedup_window_seconds=3.0)
    detector = RuleBasedDetector(config=cfg)

    attacker_ip = "192.168.1.199"
    scan_ports = [21, 22, 23, 80, 443, 8080, 3306]

    alerts = []
    # Send packets to distinct ports within 1 second
    for idx, port in enumerate(scan_ports):
        ev = PacketEvent(
            timestamp=100.0 + idx * 0.1,
            src_ip=attacker_ip,
            dst_ip="192.168.1.10",
            src_port=40000 + idx,
            dst_port=port,
            protocol=Protocol.TCP.value,
            tcp_flags="SYN",
            is_malicious=True,
            attack_type="port_scan",
        )
        alerts.extend(detector.process_event(ev))

    # Alert should trigger once threshold (5) is reached
    assert len(alerts) >= 1
    first_alert = alerts[0]
    assert first_alert.attack_type == "port_scan"
    assert first_alert.src_ip == attacker_ip
    assert first_alert.explanation is not None
    assert first_alert.explanation.rule_or_condition == "PortScanRule"
    assert "unique ports" in first_alert.explanation.observed_value


def test_syn_flood_detection():
    cfg = RuleDetectorConfig(syn_flood_threshold=6, syn_flood_window_seconds=3.0)
    detector = RuleBasedDetector(config=cfg)

    attacker_ip = "192.168.1.205"
    alerts = []
    for i in range(8):
        ev = PacketEvent(
            timestamp=200.0 + i * 0.1,
            src_ip=attacker_ip,
            dst_ip="192.168.1.10",
            src_port=1024 + i,
            dst_port=80,
            protocol=Protocol.TCP.value,
            tcp_flags="SYN",
            is_malicious=True,
            attack_type="syn_flood",
        )
        alerts.extend(detector.process_event(ev))

    assert len(alerts) >= 1
    assert alerts[0].attack_type == "syn_flood"
    assert alerts[0].explanation.rule_or_condition == "SynFloodRule"


def test_icmp_spike_detection():
    cfg = RuleDetectorConfig(icmp_spike_threshold=5, icmp_spike_window_seconds=2.0)
    detector = RuleBasedDetector(config=cfg)

    attacker_ip = "192.168.1.220"
    alerts = []
    for i in range(7):
        ev = PacketEvent(
            timestamp=300.0 + i * 0.1,
            src_ip=attacker_ip,
            dst_ip="192.168.1.10",
            src_port=0,
            dst_port=0,
            protocol=Protocol.ICMP.value,
            packet_size=64,
            tcp_flags="NONE",
            is_malicious=True,
            attack_type="icmp_spike",
        )
        alerts.extend(detector.process_event(ev))

    assert len(alerts) >= 1
    assert alerts[0].attack_type == "icmp_spike"
    assert alerts[0].explanation.rule_or_condition == "IcmpSpikeRule"


def test_high_rate_detection():
    cfg = RuleDetectorConfig(high_rate_threshold=10, high_rate_window_seconds=2.0)
    detector = RuleBasedDetector(config=cfg)

    attacker_ip = "192.168.1.210"
    alerts = []
    for i in range(12):
        ev = PacketEvent(
            timestamp=400.0 + i * 0.05,
            src_ip=attacker_ip,
            dst_ip="192.168.1.10",
            src_port=50000,
            dst_port=80,
            protocol=Protocol.TCP.value,
            tcp_flags="ACK",
            is_malicious=True,
            attack_type="high_traffic_rate",
        )
        alerts.extend(detector.process_event(ev))

    assert len(alerts) >= 1
    assert alerts[0].attack_type == "high_traffic_rate"
