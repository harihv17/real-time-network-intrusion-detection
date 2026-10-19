"""Data models and schemas for packet events and simulation scenarios."""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Optional
import time
import uuid


class Protocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"


class ScenarioType(str, Enum):
    NORMAL = "Normal traffic"
    PORT_SCAN = "Port scan activity"
    HIGH_RATE = "High packet-rate activity"
    SYN_FLOOD = "Repeated TCP SYN attempts"
    ICMP_SPIKE = "ICMP traffic spike"
    GRADUAL_DRIFT = "Gradual traffic-rate deviation"
    MIXED = "Mixed normal and suspicious"


@dataclass
class PacketEvent:
    """Represents a single synthetic packet-level network event record."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: float = field(default_factory=time.time)
    src_ip: str = "192.168.1.100"
    dst_ip: str = "192.168.1.10"
    src_port: int = 49152
    dst_port: int = 80
    protocol: str = Protocol.TCP.value
    packet_size: int = 64
    tcp_flags: str = "ACK"
    scenario: str = ScenarioType.NORMAL.value
    # Ground-truth evaluation annotations (STRICTLY ISOLATED from detection logic)
    is_malicious: bool = False
    attack_type: Optional[str] = None

    def to_dict(self) -> dict:
        """Serializes event to a clean dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "PacketEvent":
        """Instantiates PacketEvent from dictionary."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
