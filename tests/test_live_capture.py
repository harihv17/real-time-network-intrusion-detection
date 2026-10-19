"""Automated unit and integration tests for live packet capture and parser modules.

Uses deterministic mocked and synthesized Scapy packet structures so tests
run reliably without requiring active promiscuous network access or admin elevation.
"""

import pytest
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether

from capture.parser import parse_packet_metadata, format_tcp_flags
from capture.interfaces import check_capture_prerequisites, get_available_interfaces
from capture.engine import LiveCaptureEngine, CaptureState
from detection.engine import DetectionPipeline
from detection.models import DetectionMethod, Severity


def test_tcp_flags_formatting():
    assert format_tcp_flags("S") == "SYN"
    assert "SYN" in format_tcp_flags("SA") and "ACK" in format_tcp_flags("SA")
    assert format_tcp_flags("FA") in ("FIN, ACK", "ACK, FIN")
    assert format_tcp_flags("") == "NONE"


def test_parse_scapy_tcp_packet():
    pkt = Ether() / IP(src="192.168.1.15", dst="192.168.1.1") / TCP(sport=54321, dport=443, flags="S")
    event = parse_packet_metadata(pkt)

    assert event is not None
    assert event.src_ip == "192.168.1.15"
    assert event.dst_ip == "192.168.1.1"
    assert event.src_port == 54321
    assert event.dst_port == 443
    assert event.protocol == "TCP"
    assert "SYN" in event.tcp_flags
    assert event.scenario == "Live Network Traffic"
    assert event.is_malicious is False
    assert event.packet_size > 0


def test_parse_scapy_udp_packet():
    pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / UDP(sport=5353, dport=53)
    event = parse_packet_metadata(pkt)

    assert event is not None
    assert event.src_ip == "10.0.0.5"
    assert event.dst_ip == "10.0.0.1"
    assert event.src_port == 5353
    assert event.dst_port == 53
    assert event.protocol == "UDP"
    assert event.tcp_flags == "NONE"


def test_parse_scapy_icmp_packet():
    pkt = Ether() / IP(src="192.168.1.50", dst="192.168.1.1") / ICMP()
    event = parse_packet_metadata(pkt)

    assert event is not None
    assert event.protocol == "ICMP"
    assert event.src_ip == "192.168.1.50"
    assert event.src_port == 0
    assert event.dst_port == 0


def test_parse_malformed_object_returns_none():
    assert parse_packet_metadata("not_a_packet") is None
    assert parse_packet_metadata(None) is None


def test_capture_prerequisites_check():
    diag = check_capture_prerequisites()
    assert isinstance(diag, dict)
    assert "can_capture" in diag
    assert "is_admin" in diag
    assert "scapy_installed" in diag
    assert "npcap_installed" in diag
    assert "diagnostic_notes" in diag
    assert diag["scapy_installed"] is True


def test_interface_enumeration():
    ifs = get_available_interfaces()
    assert isinstance(ifs, list)
    # If interfaces are found, check schema
    if ifs:
        first = ifs[0]
        assert "id" in first
        assert "name" in first
        assert "display_label" in first


def test_live_capture_engine_direct_ingest_and_drain():
    engine = LiveCaptureEngine(max_buffer_size=100)
    assert engine.state == CaptureState.STOPPED
    assert engine.captured_packets_count == 0

    # Ingest 5 mocked live packets
    for i in range(5):
        pkt = Ether() / IP(src=f"192.168.1.{10+i}", dst="192.168.1.1") / TCP(sport=50000+i, dport=80, flags="A")
        engine.ingest_packet_direct(pkt)

    assert engine.captured_packets_count == 5
    assert engine.observed_bytes_count > 0
    assert len(engine.unique_src_ips) == 5

    # Drain queue
    drained = engine.drain_packet_queue(max_packets=10)
    assert len(drained) == 5
    assert drained[0].src_ip == "192.168.1.10"
    # Secondary drain should be empty
    assert len(engine.drain_packet_queue()) == 0

    # Reset
    engine.reset()
    assert engine.captured_packets_count == 0
    assert engine.observed_bytes_count == 0
    assert len(engine.captured_events_buffer) == 0


def test_live_traffic_detection_pipeline_processing():
    """Verifies that genuine live-parsed packets flow through the detection pipeline and trigger alerts."""
    engine = LiveCaptureEngine()
    pipeline = DetectionPipeline()

    attacker_ip = "192.168.1.88"
    scan_ports = [21, 22, 23, 25, 80, 443, 8080, 3306, 5432]

    # Generate live packets simulating port probing
    for port in scan_ports:
        pkt = Ether() / IP(src=attacker_ip, dst="192.168.1.1") / TCP(sport=40000, dport=port, flags="S")
        engine.ingest_packet_direct(pkt)

    # Drain from engine into detection pipeline
    live_events = engine.drain_packet_queue(max_packets=50)
    emitted_alerts = []
    for ev in live_events:
        alerts = pipeline.process_event(ev, active_method=DetectionMethod.COMBINED_EXPLAINABLE)
        emitted_alerts.extend(alerts)

    # The pipeline should detect the port scan from live packet features
    assert len(emitted_alerts) >= 1
    first_alert = emitted_alerts[0]
    assert first_alert.src_ip == attacker_ip
    assert first_alert.explanation is not None
    assert "PortScanRule" in first_alert.explanation.rule_or_condition


def test_mode_separation_metrics_isolation():
    """Ensures simulated metrics and live capture metrics remain completely separated."""
    from simulator.engine import SimulationEngine

    sim_engine = SimulationEngine()
    live_engine = LiveCaptureEngine()

    sim_pipeline = DetectionPipeline()
    live_pipeline = DetectionPipeline()

    # Step simulation
    sim_events = sim_engine.step(num_events=15)
    for ev in sim_events:
        sim_pipeline.process_event(ev)

    # Ingest live
    live_pkt = Ether() / IP(src="172.16.0.4", dst="172.16.0.1") / UDP(sport=123, dport=123)
    live_engine.ingest_packet_direct(live_pkt)
    for ev in live_engine.drain_packet_queue():
        live_pipeline.process_event(ev)

    # Verify simulation counters
    assert sim_engine.total_events == 15
    assert live_engine.captured_packets_count == 1

    # Verify pipeline alert repositories are separate
    assert sim_pipeline.alerts_history is not live_pipeline.alerts_history
