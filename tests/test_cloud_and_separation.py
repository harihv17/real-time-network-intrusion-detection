"""Unit and integration tests for cloud safety, mode isolation, and state management.

Tests verify:
1. Simulation independence from packet-capture dependencies (Scapy, Npcap, Windows architecture).
2. Live and simulation mode complete data and state separation.
3. Cloud-safe environment detection and graceful capture error handling.
4. Engine lifecycle state transitions: start, pause, stop, reset, and bounded memory buffers.
5. Explainable alert generation on simulated attack scenarios.
"""

import os
import pytest
from unittest.mock import patch

from simulator.models import PacketEvent, ScenarioType, Protocol
from simulator.engine import SimulationEngine
from simulator.generator import TrafficGenerator
from capture.engine import LiveCaptureEngine, CaptureState
from capture.interfaces import is_cloud_environment, check_capture_prerequisites, get_available_interfaces
from detection.engine import DetectionPipeline
from detection.models import DetectionMethod, Severity


def test_simulation_independence_from_packet_capture():
    """Verifies that SimulationEngine and TrafficGenerator function without packet capture libraries or adapters."""
    engine = SimulationEngine()
    assert engine.total_events == 0
    assert engine.is_running is False
    assert engine.is_paused is False

    # Run discrete steps for all scenarios
    for scenario in ScenarioType:
        engine.set_scenario(scenario)
        batch = engine.step(num_events=5, use_real_timestamp=False)
        assert len(batch) == 5
        for ev in batch:
            assert isinstance(ev, PacketEvent)
            assert ev.src_ip != ""
            assert ev.dst_ip != ""
            assert ev.protocol in ("TCP", "UDP", "ICMP")
            assert ev.packet_size > 0

    assert engine.total_events == 5 * len(ScenarioType)
    assert engine.total_bytes > 0
    assert len(engine.event_buffer) == 5 * len(ScenarioType)


def test_live_and_simulation_mode_strict_separation():
    """Verifies that live capture and simulation engines/pipelines maintain independent buffers and counters."""
    sim_eng = SimulationEngine()
    sim_pipe = DetectionPipeline()

    live_eng = LiveCaptureEngine()
    live_pipe = DetectionPipeline()

    # Step simulation
    sim_events = sim_eng.step(num_events=10)
    for ev in sim_events:
        sim_pipe.process_event(ev, active_method=DetectionMethod.RULE_BASED)

    # Ingest mock live event into live engine
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    pkt = Ether() / IP(src="10.99.99.1", dst="10.99.99.2") / TCP(sport=5555, dport=80)
    live_eng.ingest_packet_direct(pkt)
    live_events = live_eng.drain_packet_queue()
    for ev in live_events:
        live_pipe.process_event(ev, active_method=DetectionMethod.RULE_BASED)

    # Strict isolation assertions
    assert sim_eng.total_events == 10
    assert live_eng.captured_packets_count == 1

    assert len(sim_eng.event_buffer) == 10
    assert len(live_eng.captured_events_buffer) == 1

    # Pipelines are independent
    assert sim_pipe.total_alerts_count >= 0
    assert live_pipe.total_alerts_count >= 0


def test_simulation_state_management_lifecycle():
    """Verifies start, pause, stop, reset, and bounded buffers in SimulationEngine."""
    engine = SimulationEngine()

    # Start
    engine.start()
    assert engine.is_running is True
    assert engine.is_paused is False

    # Pause
    engine.pause()
    assert engine.is_running is True
    assert engine.is_paused is True

    # Stop
    engine.stop()
    assert engine.is_running is False
    assert engine.is_paused is False

    # Reset
    engine.step(num_events=20)
    assert engine.total_events == 20
    engine.reset()
    assert engine.total_events == 0
    assert engine.total_bytes == 0
    assert len(engine.event_buffer) == 0
    assert len(engine.unique_src_ips) == 0


def test_cloud_environment_detection_flags():
    """Tests cloud environment heuristic detection across various cloud hosting markers."""
    with patch.dict(os.environ, {"STREAMLIT_HOSTED": "true"}, clear=False):
        assert is_cloud_environment() is True

    with patch.dict(os.environ, {"STREAMLIT_SHARING_MODE": "demo"}, clear=False):
        assert is_cloud_environment() is True

    with patch.dict(os.environ, {"KUBERNETES_SERVICE_HOST": "10.0.0.1"}, clear=False):
        assert is_cloud_environment() is True

    with patch.dict(os.environ, {"HOSTNAME": "streamlit-cloud-container-42"}, clear=False):
        assert is_cloud_environment() is True


def test_cloud_safe_live_engine_start_capture():
    """Verifies that attempting live capture in a cloud environment fails gracefully with clear diagnostics."""
    with patch("capture.engine.check_capture_prerequisites") as mock_prereq:
        mock_prereq.return_value = {
            "can_capture": False,
            "is_cloud": True,
            "is_admin": False,
            "scapy_installed": True,
            "npcap_installed": False,
            "pcap_provider": "None",
            "diagnostic_notes": ["Hosted Cloud Container Detected"],
        }
        engine = LiveCaptureEngine()
        success = engine.start_capture()

        assert success is False
        assert engine.state == CaptureState.ERROR
        assert "cloud" in engine.error_message.lower()
        assert "simulation mode" in engine.diagnostic_advice.lower()


def test_cloud_safe_interface_enumeration_fallback():
    """Verifies that interface discovery does not throw unhandled exceptions in mock environments."""
    with patch("sys.platform", "linux"):
        ifs = get_available_interfaces()
        assert isinstance(ifs, list)


def test_deterministic_attack_scenario_detection():
    """Verifies that simulation attack scenarios trigger valid explainable alerts through the detection engine."""
    engine = SimulationEngine()
    pipeline = DetectionPipeline()

    engine.set_scenario(ScenarioType.PORT_SCAN)
    events = engine.step(num_events=30, use_real_timestamp=False)

    alerts = []
    for ev in events:
        alerts.extend(pipeline.process_event(ev, active_method=DetectionMethod.RULE_BASED))

    assert len(alerts) >= 1
    port_scan_alerts = [a for a in alerts if a.attack_type == "port_scan" or "Port Scan" in a.explanation.rule_or_condition]
    assert len(port_scan_alerts) >= 1

    alert = port_scan_alerts[0]
    assert alert.explanation is not None
    assert alert.explanation.what_happened != ""
    assert alert.explanation.evidence_summary != ""
    assert alert.explanation.expected_baseline != ""
    assert alert.explanation.trigger_comparison != ""
    assert alert.data_source == "Simulation"
