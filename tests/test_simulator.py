"""Unit tests for traffic generator and simulation engine."""

import pytest
from simulator.models import ScenarioType, Protocol
from simulator.generator import TrafficGenerator
from simulator.engine import SimulationEngine
from utils.config import SimulatorConfig


def test_generator_deterministic_seed():
    gen1 = TrafficGenerator(seed=42)
    e1 = [gen1.generate_normal_event(timestamp=100.0) for _ in range(5)]

    gen2 = TrafficGenerator(seed=42)
    e2 = [gen2.generate_normal_event(timestamp=100.0) for _ in range(5)]

    for a, b in zip(e1, e2):
        assert a.src_ip == b.src_ip
        assert a.dst_port == b.dst_port
        assert a.packet_size == b.packet_size


def test_generator_all_scenarios():
    gen = TrafficGenerator(seed=100)

    # 1. Normal
    norm = gen.generate_normal_event()
    assert not norm.is_malicious
    assert norm.scenario == ScenarioType.NORMAL.value

    # 2. Port scan
    scan = gen.generate_port_scan_event()
    assert scan.is_malicious
    assert scan.attack_type == "port_scan"
    assert "SYN" in scan.tcp_flags

    # 3. High rate
    high = gen.generate_high_rate_event()
    assert high.is_malicious
    assert high.attack_type == "high_traffic_rate"

    # 4. SYN flood
    syn = gen.generate_syn_flood_event()
    assert syn.is_malicious
    assert syn.attack_type == "syn_flood"
    assert syn.tcp_flags == "SYN"

    # 5. ICMP spike
    icmp = gen.generate_icmp_spike_event()
    assert icmp.is_malicious
    assert icmp.protocol == Protocol.ICMP.value

    # 6. Gradual drift
    drift = gen.generate_gradual_drift_event()
    assert drift.scenario == ScenarioType.GRADUAL_DRIFT.value

    # 7. Mixed
    mixed = gen.generate_mixed_event()
    assert mixed.scenario == ScenarioType.MIXED.value


def test_simulation_engine_controls():
    cfg = SimulatorConfig(max_history_events=50, default_events_per_second=10.0)
    engine = SimulationEngine(config=cfg)

    assert not engine.is_running
    assert not engine.is_paused

    # Start and step
    engine.start()
    assert engine.is_running

    events = engine.step(num_events=10)
    assert len(events) == 10
    assert engine.total_events == 10
    assert len(engine.event_buffer) == 10

    # Pause
    engine.pause()
    assert engine.is_paused
    # tick while paused produces no events
    assert len(engine.tick()) == 0

    # Resume
    engine.resume()
    assert not engine.is_paused

    # Reset
    engine.reset()
    assert not engine.is_running
    assert engine.total_events == 0
    assert len(engine.event_buffer) == 0


def test_simulation_engine_buffer_overflow_bounds():
    cfg = SimulatorConfig(max_history_events=20)
    engine = SimulationEngine(config=cfg)

    engine.step(num_events=35)
    # Bounded deque ensures buffer does not exceed maxlen
    assert len(engine.event_buffer) == 20
    assert engine.total_events == 35
