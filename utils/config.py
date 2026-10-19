"""Configuration settings for the NIDS system.

Centralizes default parameters for simulator, rule thresholds,
statistical baselines, risk scoring, and UI settings.
"""

from dataclasses import dataclass, field
from typing import Dict, Any


@dataclass
class SimulatorConfig:
    """Traffic simulator parameters."""
    default_events_per_second: float = 10.0
    max_history_events: int = 5000
    max_alerts_history: int = 2000
    random_seed: int = 42
    default_subnet: str = "192.168.1.0/24"
    server_ips: list[str] = field(default_factory=lambda: [
        "192.168.1.10",  # Web Server (HTTP/HTTPS)
        "192.168.1.20",  # Database (PostgreSQL/MySQL)
        "192.168.1.30",  # DNS Server
        "192.168.1.40",  # SSH Gateway
        "192.168.1.50",  # Internal API
    ])


@dataclass
class RuleDetectorConfig:
    """Rule-based detection thresholds and rolling window durations."""
    # Port scan: count of distinct destination ports or dst IPs from a src IP
    port_scan_window_seconds: float = 5.0
    port_scan_threshold: int = 8

    # High traffic rate: total packets from an IP or overall in a window
    high_rate_window_seconds: float = 2.0
    high_rate_threshold: int = 25

    # Repeated SYN attempts: SYN without ACK in a window
    syn_flood_window_seconds: float = 3.0
    syn_flood_threshold: int = 10

    # ICMP spike: ICMP packets in a window
    icmp_spike_window_seconds: float = 3.0
    icmp_spike_threshold: int = 12

    # Deduplication window per (rule_name, src_ip) to avoid alert spam
    dedup_window_seconds: float = 3.0


@dataclass
class AdaptiveDetectorConfig:
    """Statistical anomaly detector parameters."""
    warmup_samples: int = 25
    ewma_alpha: float = 0.15
    z_score_threshold: float = 2.5
    min_std_floor: float = 1.0
    window_interval_seconds: float = 1.0


@dataclass
class RiskScoringConfig:
    """Weights and thresholds for explainable combined risk scoring."""
    rule_weight: float = 0.60
    anomaly_weight: float = 0.40

    # Score thresholds [0, 100]
    low_threshold: float = 25.0
    medium_threshold: float = 50.0
    high_threshold: float = 75.0
    critical_threshold: float = 90.0


@dataclass
class SystemConfig:
    """Root configuration object."""
    simulator: SimulatorConfig = field(default_factory=SimulatorConfig)
    rules: RuleDetectorConfig = field(default_factory=RuleDetectorConfig)
    adaptive: AdaptiveDetectorConfig = field(default_factory=AdaptiveDetectorConfig)
    risk: RiskScoringConfig = field(default_factory=RiskScoringConfig)


# Default system singleton
DEFAULT_CONFIG = SystemConfig()
