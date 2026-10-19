"""Synthetic network traffic generator.

Produces realistic, reproducible packet-like events across normal
and various adversarial network traffic patterns.
"""

import random
import time
from typing import Optional, List
from simulator.models import PacketEvent, Protocol, ScenarioType


class TrafficGenerator:
    """Generates synthetic packet events with realistic attributes and ground truth labels."""

    COMMON_SERVICES = [
        ("192.168.1.10", 80, Protocol.TCP.value, "HTTP"),
        ("192.168.1.10", 443, Protocol.TCP.value, "HTTPS"),
        ("192.168.1.20", 3306, Protocol.TCP.value, "MySQL"),
        ("192.168.1.20", 5432, Protocol.TCP.value, "PostgreSQL"),
        ("192.168.1.30", 53, Protocol.UDP.value, "DNS"),
        ("192.168.1.40", 22, Protocol.TCP.value, "SSH"),
        ("192.168.1.50", 8080, Protocol.TCP.value, "HTTP-Proxy/API"),
    ]

    SCAN_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
        443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080, 8443
    ]

    NORMAL_CLIENT_IPS = [f"192.168.1.{i}" for i in range(101, 140)]
    ATTACKER_IPS = {
        "port_scan": "192.168.1.199",
        "high_rate": "192.168.1.210",
        "syn_flood": "192.168.1.205",
        "icmp_spike": "192.168.1.220",
        "drift": "192.168.1.180",
    }

    def __init__(self, seed: Optional[int] = 42):
        self._rng = random.Random(seed)
        self._port_scan_idx = 0
        self._drift_step = 0

    def seed(self, seed: int) -> None:
        """Resets the internal pseudorandom generator seed."""
        self._rng = random.Random(seed)
        self._port_scan_idx = 0
        self._drift_step = 0

    def generate_normal_event(self, timestamp: Optional[float] = None) -> PacketEvent:
        """Generates a standard benign packet transaction."""
        ts = timestamp if timestamp is not None else time.time()
        dst_ip, dst_port, protocol, _ = self._rng.choice(self.COMMON_SERVICES)
        src_ip = self._rng.choice(self.NORMAL_CLIENT_IPS)
        src_port = self._rng.randint(49152, 65535)

        if protocol == Protocol.TCP.value:
            # Benign established session: usually ACK or PSH+ACK
            flags = self._rng.choice(["ACK", "PSH, ACK", "ACK", "FIN, ACK"])
            packet_size = self._rng.randint(128, 1460)
        elif protocol == Protocol.UDP.value:
            flags = "NONE"
            packet_size = self._rng.randint(64, 512)
        else:
            flags = "NONE"
            packet_size = 64

        return PacketEvent(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_size=packet_size,
            tcp_flags=flags,
            scenario=ScenarioType.NORMAL.value,
            is_malicious=False,
            attack_type=None,
        )

    def generate_port_scan_event(self, timestamp: Optional[float] = None) -> PacketEvent:
        """Simulates reconnaissance port scanning activity from an attacker IP."""
        ts = timestamp if timestamp is not None else time.time()
        src_ip = self.ATTACKER_IPS["port_scan"]
        dst_ip = "192.168.1.10"
        dst_port = self.SCAN_PORTS[self._port_scan_idx % len(self.SCAN_PORTS)]
        self._port_scan_idx += 1
        src_port = self._rng.randint(40000, 65000)

        return PacketEvent(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=Protocol.TCP.value,
            packet_size=self._rng.randint(44, 60),
            tcp_flags="SYN",
            scenario=ScenarioType.PORT_SCAN.value,
            is_malicious=True,
            attack_type="port_scan",
        )

    def generate_high_rate_event(self, timestamp: Optional[float] = None) -> PacketEvent:
        """Simulates high-velocity volumetric traffic aimed at overwhelming a service."""
        ts = timestamp if timestamp is not None else time.time()
        src_ip = self.ATTACKER_IPS["high_rate"]
        dst_ip = "192.168.1.10"
        dst_port = 80
        src_port = self._rng.randint(49152, 65535)

        return PacketEvent(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=Protocol.TCP.value,
            packet_size=self._rng.randint(1024, 1500),
            tcp_flags="PSH, ACK",
            scenario=ScenarioType.HIGH_RATE.value,
            is_malicious=True,
            attack_type="high_traffic_rate",
        )

    def generate_syn_flood_event(self, timestamp: Optional[float] = None) -> PacketEvent:
        """Simulates repeated half-open TCP connection attempts (SYN flood)."""
        ts = timestamp if timestamp is not None else time.time()
        src_ip = self.ATTACKER_IPS["syn_flood"]
        dst_ip = "192.168.1.10"
        dst_port = 80
        src_port = self._rng.randint(1024, 65535)

        return PacketEvent(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=Protocol.TCP.value,
            packet_size=54,
            tcp_flags="SYN",
            scenario=ScenarioType.SYN_FLOOD.value,
            is_malicious=True,
            attack_type="syn_flood",
        )

    def generate_icmp_spike_event(self, timestamp: Optional[float] = None) -> PacketEvent:
        """Simulates an ICMP echo flood / ping broadcast storm."""
        ts = timestamp if timestamp is not None else time.time()
        src_ip = self.ATTACKER_IPS["icmp_spike"]
        dst_ip = "192.168.1.255" if self._rng.random() < 0.3 else "192.168.1.10"

        return PacketEvent(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=0,
            dst_port=0,
            protocol=Protocol.ICMP.value,
            packet_size=self._rng.randint(64, 128),
            tcp_flags="NONE",
            scenario=ScenarioType.ICMP_SPIKE.value,
            is_malicious=True,
            attack_type="icmp_spike",
        )

    def generate_gradual_drift_event(self, timestamp: Optional[float] = None) -> PacketEvent:
        """Simulates gradual statistical deviation from the normal baseline."""
        ts = timestamp if timestamp is not None else time.time()
        self._drift_step += 1
        # As drift step increases, probability of abnormal packet sizes and rates increases
        is_deviant = (self._drift_step > 20) and (self._rng.random() < min(0.9, self._drift_step * 0.03))

        if is_deviant:
            src_ip = self.ATTACKER_IPS["drift"]
            dst_ip = "192.168.1.20"
            dst_port = 5432
            src_port = self._rng.randint(49152, 65535)
            # Unusually large data exfiltration / payload chunks
            packet_size = self._rng.randint(2500, 4500)
            return PacketEvent(
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=Protocol.TCP.value,
                packet_size=packet_size,
                tcp_flags="PSH, ACK",
                scenario=ScenarioType.GRADUAL_DRIFT.value,
                is_malicious=True,
                attack_type="gradual_drift",
            )
        else:
            event = self.generate_normal_event(timestamp=ts)
            event.scenario = ScenarioType.GRADUAL_DRIFT.value
            return event

    def generate_mixed_event(self, timestamp: Optional[float] = None, attack_prob: float = 0.25) -> PacketEvent:
        """Produces a continuous stream blending mostly normal traffic with random attack episodes."""
        if self._rng.random() < attack_prob:
            attack_choice = self._rng.choice([
                self.generate_port_scan_event,
                self.generate_syn_flood_event,
                self.generate_icmp_spike_event,
                self.generate_high_rate_event,
            ])
            event = attack_choice(timestamp=timestamp)
            event.scenario = ScenarioType.MIXED.value
            return event
        else:
            event = self.generate_normal_event(timestamp=timestamp)
            event.scenario = ScenarioType.MIXED.value
            return event

    def generate_event(self, scenario: ScenarioType, timestamp: Optional[float] = None) -> PacketEvent:
        """Dispatches event generation based on scenario selection."""
        if scenario == ScenarioType.NORMAL:
            return self.generate_normal_event(timestamp)
        elif scenario == ScenarioType.PORT_SCAN:
            return self.generate_port_scan_event(timestamp)
        elif scenario == ScenarioType.HIGH_RATE:
            return self.generate_high_rate_event(timestamp)
        elif scenario == ScenarioType.SYN_FLOOD:
            return self.generate_syn_flood_event(timestamp)
        elif scenario == ScenarioType.ICMP_SPIKE:
            return self.generate_icmp_spike_event(timestamp)
        elif scenario == ScenarioType.GRADUAL_DRIFT:
            return self.generate_gradual_drift_event(timestamp)
        elif scenario == ScenarioType.MIXED:
            return self.generate_mixed_event(timestamp)
        else:
            return self.generate_normal_event(timestamp)
