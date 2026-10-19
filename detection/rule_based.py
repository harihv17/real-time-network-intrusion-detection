"""Rule-based intrusion detection engine using time-aware rolling windows."""

from collections import defaultdict, deque
from typing import List, Dict, Tuple, Optional
from simulator.models import PacketEvent, Protocol
from detection.models import Alert, Severity, DetectionMethod, Explanation
from utils.config import RuleDetectorConfig, DEFAULT_CONFIG


class RuleBasedDetector:
    """Evaluates packet events against signature and threshold heuristic rules."""

    def __init__(self, config: Optional[RuleDetectorConfig] = None):
        self.config = config or DEFAULT_CONFIG.rules

        # Rolling window buffers:
        # src_ip -> deque of (timestamp, dst_port)
        self._port_scan_history: Dict[str, deque[Tuple[float, int]]] = defaultdict(deque)

        # src_ip -> deque of (timestamp)
        self._rate_history: Dict[str, deque[float]] = defaultdict(deque)

        # src_ip -> deque of (timestamp)
        self._syn_history: Dict[str, deque[float]] = defaultdict(deque)

        # src_ip -> deque of (timestamp)
        self._icmp_history: Dict[str, deque[float]] = defaultdict(deque)

        # Deduplication tracker: (rule_name, src_ip) -> last_alert_timestamp
        self._last_alert_time: Dict[Tuple[str, str], float] = {}

    def reset(self) -> None:
        """Clears all rolling state and deduplication records."""
        self._port_scan_history.clear()
        self._rate_history.clear()
        self._syn_history.clear()
        self._icmp_history.clear()
        self._last_alert_time.clear()

    def _should_suppress_alert(self, rule_name: str, src_ip: str, current_time: float) -> bool:
        """Checks if an alert for this rule and entity was emitted recently."""
        key = (rule_name, src_ip)
        last_time = self._last_alert_time.get(key)
        if last_time is not None and (current_time - last_time) < self.config.dedup_window_seconds:
            return True
        self._last_alert_time[key] = current_time
        return False

    def process_event(self, event: PacketEvent) -> List[Alert]:
        """Evaluates an incoming packet event across all rule definitions."""
        alerts: List[Alert] = []
        now = event.timestamp
        is_sim = "Simulated" in getattr(event, "scenario", "") or getattr(event, "scenario", "") != "Live Network Traffic"
        data_source = "Simulation" if is_sim else "Live Capture"

        # 1. Rule: Port Scanning
        if event.protocol in (Protocol.TCP.value, Protocol.UDP.value):
            history = self._port_scan_history[event.src_ip]
            history.append((now, event.dst_port))
            cutoff = now - self.config.port_scan_window_seconds
            while history and history[0][0] < cutoff:
                history.popleft()

            unique_ports = {port for _, port in history}
            if len(unique_ports) >= self.config.port_scan_threshold:
                if not self._should_suppress_alert("PortScanRule", event.src_ip, now):
                    port_sample = sorted(list(unique_ports))[:6]
                    alerts.append(Alert(
                        timestamp=now,
                        src_ip=event.src_ip,
                        dst_ip=event.dst_ip,
                        method=DetectionMethod.RULE_BASED,
                        severity=Severity.HIGH,
                        risk_score=75.0,
                        attack_type="port_scan",
                        event_id=event.event_id,
                        ground_truth_malicious=event.is_malicious,
                        data_source=data_source,
                        explanation=Explanation(
                            rule_or_condition="PortScanRule",
                            observed_value=f"{len(unique_ports)} unique ports",
                            threshold_or_baseline=f"{self.config.port_scan_threshold} ports in {self.config.port_scan_window_seconds}s",
                            entity=event.src_ip,
                            reason=f"Host {event.src_ip} probed {len(unique_ports)} distinct destination ports within {self.config.port_scan_window_seconds}s.",
                            feature_name="unique_dst_ports",
                            what_happened=f"Host {event.src_ip} conducted reconnaissance port scanning, probing {len(unique_ports)} distinct ports within {self.config.port_scan_window_seconds}s.",
                            evidence_summary=f"Probed ports include: {port_sample}{'...' if len(unique_ports) > 6 else ''} across {len(history)} total packets.",
                            expected_baseline=f"Expected single-host sweep: < {self.config.port_scan_threshold} unique ports per {self.config.port_scan_window_seconds}s.",
                            trigger_comparison=f"Observed count ({len(unique_ports)} ports) >= rule threshold ({self.config.port_scan_threshold} ports).",
                            detector_source="Rule-Based Signature Engine (PortScanRule)",
                            severity_rationale="High severity (75.0/100) assigned due to active enumeration targeting vulnerable services.",
                            operational_limitations="Legitimate network vulnerability scanners (e.g. Nmap) produce identical port sweep patterns.",
                        ),
                    ))

        # 2. Rule: High Packet Rate
        rate_hist = self._rate_history[event.src_ip]
        rate_hist.append(now)
        cutoff_rate = now - self.config.high_rate_window_seconds
        while rate_hist and rate_hist[0] < cutoff_rate:
            rate_hist.popleft()

        packet_count = len(rate_hist)
        if packet_count >= self.config.high_rate_threshold:
            if not self._should_suppress_alert("HighTrafficRateRule", event.src_ip, now):
                rate_val = round(packet_count / max(0.1, self.config.high_rate_window_seconds), 1)
                alerts.append(Alert(
                    timestamp=now,
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    method=DetectionMethod.RULE_BASED,
                    severity=Severity.MEDIUM,
                    risk_score=60.0,
                    attack_type="high_traffic_rate",
                    event_id=event.event_id,
                    ground_truth_malicious=event.is_malicious,
                    data_source=data_source,
                    explanation=Explanation(
                        rule_or_condition="HighTrafficRateRule",
                        observed_value=f"{packet_count} packets",
                        threshold_or_baseline=f"{self.config.high_rate_threshold} pkts / {self.config.high_rate_window_seconds}s",
                        entity=event.src_ip,
                        reason=f"Host {event.src_ip} generated {packet_count} packets in {self.config.high_rate_window_seconds}s, exceeding high-rate threshold.",
                        feature_name="packet_rate",
                        what_happened=f"Volumetric surge observed: Host {event.src_ip} transmitted {packet_count} packets in {self.config.high_rate_window_seconds}s.",
                        evidence_summary=f"Effective transmission rate: ~{rate_val} pkts/s sustained across {self.config.high_rate_window_seconds} seconds.",
                        expected_baseline=f"Normal host transmission ceiling: < {self.config.high_rate_threshold} pkts per {self.config.high_rate_window_seconds}s.",
                        trigger_comparison=f"Observed rate ({packet_count} pkts) >= rule threshold ({self.config.high_rate_threshold} pkts).",
                        detector_source="Rule-Based Signature Engine (HighTrafficRateRule)",
                        severity_rationale="Medium severity (60.0/100) reflecting bandwidth/pipeline congestion without confirmed exploit payload.",
                        operational_limitations="Legitimate bulk data transfers, video streaming, or database backups can trigger high packet rates.",
                    ),
                ))

        # 3. Rule: Repeated SYN Attempts (SYN Flood)
        if event.protocol == Protocol.TCP.value and "SYN" in event.tcp_flags and "ACK" not in event.tcp_flags:
            syn_hist = self._syn_history[event.src_ip]
            syn_hist.append(now)
            cutoff_syn = now - self.config.syn_flood_window_seconds
            while syn_hist and syn_hist[0] < cutoff_syn:
                syn_hist.popleft()

            syn_count = len(syn_hist)
            if syn_count >= self.config.syn_flood_threshold:
                if not self._should_suppress_alert("SynFloodRule", event.src_ip, now):
                    alerts.append(Alert(
                        timestamp=now,
                        src_ip=event.src_ip,
                        dst_ip=event.dst_ip,
                        method=DetectionMethod.RULE_BASED,
                        severity=Severity.HIGH,
                        risk_score=80.0,
                        attack_type="syn_flood",
                        event_id=event.event_id,
                        ground_truth_malicious=event.is_malicious,
                        data_source=data_source,
                        explanation=Explanation(
                            rule_or_condition="SynFloodRule",
                            observed_value=f"{syn_count} half-open SYNs",
                            threshold_or_baseline=f"{self.config.syn_flood_threshold} SYNs / {self.config.syn_flood_window_seconds}s",
                            entity=event.src_ip,
                            reason=f"Host {event.src_ip} issued {syn_count} unacknowledged TCP SYN connection requests within {self.config.syn_flood_window_seconds}s.",
                            feature_name="tcp_syn_rate",
                            what_happened=f"Potential TCP SYN Flood: Host {event.src_ip} issued {syn_count} half-open SYN handshakes without completion.",
                            evidence_summary=f"{syn_count} TCP packets with SYN=1 and ACK=0 targeting port {event.dst_port} within {self.config.syn_flood_window_seconds}s.",
                            expected_baseline=f"Normal embryonic connection rate: < {self.config.syn_flood_threshold} SYNs per {self.config.syn_flood_window_seconds}s.",
                            trigger_comparison=f"Observed count ({syn_count} SYNs) >= threshold ({self.config.syn_flood_threshold} SYNs).",
                            detector_source="Rule-Based Signature Engine (SynFloodRule)",
                            severity_rationale="High severity (80.0/100) due to OS kernel TCP backlog starvation and DoS hazard.",
                            operational_limitations="Rapid web browser tab reloading or broken firewall NAT translations may generate uncompleted SYNs.",
                        ),
                    ))

        # 4. Rule: ICMP Spike
        if event.protocol == Protocol.ICMP.value:
            icmp_hist = self._icmp_history[event.src_ip]
            icmp_hist.append(now)
            cutoff_icmp = now - self.config.icmp_spike_window_seconds
            while icmp_hist and icmp_hist[0] < cutoff_icmp:
                icmp_hist.popleft()

            icmp_count = len(icmp_hist)
            if icmp_count >= self.config.icmp_spike_threshold:
                if not self._should_suppress_alert("IcmpSpikeRule", event.src_ip, now):
                    alerts.append(Alert(
                        timestamp=now,
                        src_ip=event.src_ip,
                        dst_ip=event.dst_ip,
                        method=DetectionMethod.RULE_BASED,
                        severity=Severity.MEDIUM,
                        risk_score=55.0,
                        attack_type="icmp_spike",
                        event_id=event.event_id,
                        ground_truth_malicious=event.is_malicious,
                        data_source=data_source,
                        explanation=Explanation(
                            rule_or_condition="IcmpSpikeRule",
                            observed_value=f"{icmp_count} ICMP packets",
                            threshold_or_baseline=f"{self.config.icmp_spike_threshold} pkts / {self.config.icmp_spike_window_seconds}s",
                            entity=event.src_ip,
                            reason=f"Host {event.src_ip} transmitted {icmp_count} ICMP messages within {self.config.icmp_spike_window_seconds}s, indicating potential ping storm.",
                            feature_name="icmp_rate",
                            what_happened=f"ICMP Flooding activity detected: Host {event.src_ip} transmitted {icmp_count} ICMP packets in {self.config.icmp_spike_window_seconds}s.",
                            evidence_summary=f"{icmp_count} echo-request/reply packets observed in a {self.config.icmp_spike_window_seconds}s rolling window.",
                            expected_baseline=f"Normal diagnostic ICMP traffic: < {self.config.icmp_spike_threshold} pkts per {self.config.icmp_spike_window_seconds}s.",
                            trigger_comparison=f"Observed ICMP count ({icmp_count}) >= threshold ({self.config.icmp_spike_threshold}).",
                            detector_source="Rule-Based Signature Engine (IcmpSpikeRule)",
                            severity_rationale="Medium severity (55.0/100) reflecting potential ICMP smurf/flood attack or aggressive network probe.",
                            operational_limitations="Automated router path testing or network topology mapping tools create ICMP bursts benignly.",
                        ),
                    ))

        return alerts
