"""Adaptive statistical baseline anomaly detector.

Maintains dynamic exponentially weighted moving average (EWMA) baselines
for traffic rate and volume, provides safe warm-up progression,
and enforces contamination prevention against poisoned samples.
"""

import math
from collections import deque
from typing import List, Optional, Dict, Any, Tuple
from simulator.models import PacketEvent
from detection.models import Alert, Severity, DetectionMethod, Explanation
from utils.config import AdaptiveDetectorConfig, DEFAULT_CONFIG


class AdaptiveBaselineDetector:
    """Statistical anomaly detector comparing rolling observations against learned baselines."""

    def __init__(self, config: Optional[AdaptiveDetectorConfig] = None):
        self.config = config or DEFAULT_CONFIG.adaptive

        # Statistical state for packet rate (packets / window)
        self.mean_rate: float = 0.0
        self.var_rate: float = 0.0

        # Statistical state for byte volume (bytes / window)
        self.mean_bytes: float = 0.0
        self.var_bytes: float = 0.0

        # Progress tracking
        self.sample_count: int = 0
        self.warmup_target: int = self.config.warmup_samples

        # Current window observation buffer: list of (timestamp, packet_size, is_malicious)
        self._current_window_events: List[Tuple[float, int, bool]] = []
        self._current_window_start: float = 0.0

        # Telemetry snapshots for UI and explanations
        self.last_observed_rate: float = 0.0
        self.last_observed_bytes: float = 0.0
        self.last_z_score: float = 0.0

        # Deduplication tracker for anomaly alerts
        self._last_alert_time: float = -999.0
        self._dedup_interval: float = 2.0

    @property
    def is_warmed_up(self) -> bool:
        """Indicates whether sufficient normal traffic has been observed to activate detection."""
        return self.sample_count >= self.warmup_target

    @property
    def std_rate(self) -> float:
        """Standard deviation of packet rate with variance safety floor."""
        return math.sqrt(max(self.var_rate, self.config.min_std_floor ** 2))

    @property
    def std_bytes(self) -> float:
        """Standard deviation of byte rate with variance safety floor."""
        return math.sqrt(max(self.var_bytes, (self.config.min_std_floor * 50) ** 2))

    def reset(self) -> None:
        """Resets the baseline model to uninitialized state."""
        self.mean_rate = 0.0
        self.var_rate = 0.0
        self.mean_bytes = 0.0
        self.var_bytes = 0.0
        self.sample_count = 0
        self._current_window_events.clear()
        self._current_window_start = 0.0
        self.last_observed_rate = 0.0
        self.last_observed_bytes = 0.0
        self.last_z_score = 0.0
        self._last_alert_time = -999.0

    def process_event(self, event: PacketEvent) -> List[Alert]:
        """Ingests an event, aggregates across the configured interval, and evaluates anomalies."""
        alerts: List[Alert] = []
        now = event.timestamp

        if self._current_window_start == 0.0:
            self._current_window_start = now

        # Check if current window interval has elapsed
        if (now - self._current_window_start) >= self.config.window_interval_seconds:
            alerts.extend(self._evaluate_window(now, latest_src_ip=event.src_ip, event_id=event.event_id))
            # Start new window
            self._current_window_start = now
            self._current_window_events = []

        self._current_window_events.append((now, event.packet_size, event.is_malicious))
        return alerts

    def flush_window(self, current_time: float, latest_src_ip: str = "192.168.1.100") -> List[Alert]:
        """Forces evaluation of whatever remains in the current window."""
        if not self._current_window_events:
            return []
        alerts = self._evaluate_window(current_time, latest_src_ip=latest_src_ip)
        self._current_window_start = current_time
        self._current_window_events = []
        return alerts

    def _evaluate_window(self, timestamp: float, latest_src_ip: str, event_id: Optional[str] = None) -> List[Alert]:
        """Calculates window statistics and raises alerts or updates baseline."""
        alerts: List[Alert] = []
        obs_rate = float(len(self._current_window_events))
        obs_bytes = float(sum(p[1] for p in self._current_window_events))
        has_malicious_samples = any(p[2] for p in self._current_window_events)

        self.last_observed_rate = obs_rate
        self.last_observed_bytes = obs_bytes

        # Check if in warm-up phase
        if not self.is_warmed_up:
            # Baseline Contamination Prevention:
            # Only update baseline if the window contains no known attack traffic
            if not has_malicious_samples:
                self._update_baseline(obs_rate, obs_bytes)
                self.sample_count += 1
            return []

        # Warmed up: Compute Z-scores
        z_rate = (obs_rate - self.mean_rate) / self.std_rate
        z_bytes = (obs_bytes - self.mean_bytes) / self.std_bytes
        max_z = max(z_rate, z_bytes)
        self.last_z_score = max_z

        is_anomaly = max_z >= self.config.z_score_threshold

        if is_anomaly:
            # Raise alert if not within dedup interval
            if (timestamp - self._last_alert_time) >= self._dedup_interval:
                self._last_alert_time = timestamp

                primary_feature = "packet_rate" if z_rate >= z_bytes else "byte_volume"
                obs_val = f"{obs_rate:.1f} pkts/s" if primary_feature == "packet_rate" else f"{obs_bytes:.0f} B/s"
                base_val = f"{self.mean_rate:.1f} (std={self.std_rate:.1f})" if primary_feature == "packet_rate" else f"{self.mean_bytes:.0f} (std={self.std_bytes:.0f})"

                # Severity scaling based on Z-score magnitude
                if max_z > 5.0:
                    severity = Severity.CRITICAL
                    risk = min(99.0, 75.0 + max_z * 3.0)
                elif max_z > 3.5:
                    severity = Severity.HIGH
                    risk = min(85.0, 65.0 + max_z * 3.0)
                else:
                    severity = Severity.MEDIUM
                    risk = min(70.0, 50.0 + max_z * 4.0)

                alerts.append(Alert(
                    timestamp=timestamp,
                    src_ip=latest_src_ip,
                    method=DetectionMethod.ADAPTIVE_BASELINE,
                    severity=severity,
                    risk_score=round(risk, 1),
                    attack_type="statistical_anomaly",
                    event_id=event_id,
                    ground_truth_malicious=has_malicious_samples,
                    explanation=Explanation(
                        rule_or_condition=f"AdaptiveZScoreAnomaly (z={max_z:.2f})",
                        observed_value=obs_val,
                        threshold_or_baseline=f"{base_val} [Z-thresh: {self.config.z_score_threshold}]",
                        entity="traffic_aggregate",
                        reason=(
                            f"Traffic {primary_feature} deviated by {max_z:.2f} standard deviations "
                            f"from established adaptive baseline."
                        ),
                        feature_name=primary_feature,
                        z_score=round(max_z, 2),
                        what_happened=f"Statistical anomaly detected: Ingestion rate ({obs_val}) surged by {max_z:.2f} standard deviations above the learned baseline.",
                        evidence_summary=f"Observed {primary_feature}: {obs_val} (Z-Score: {max_z:.2f}σ). Window totals: {obs_rate:.0f} pkts, {obs_bytes:.0f} bytes.",
                        expected_baseline=f"Learned EWMA baseline: Mean = {self.mean_rate:.2f} pkts/s (σ = {self.std_rate:.2f}), Volume Mean = {self.mean_bytes:.0f} B/s (σ = {self.std_bytes:.0f}).",
                        trigger_comparison=f"Computed Z-Score ({max_z:.2f}σ) crossed configured anomaly threshold ({self.config.z_score_threshold}σ).",
                        detector_source="Adaptive Statistical Baseline Engine (EWMA & Z-Score Test)",
                        severity_rationale=f"Severity scaled to {severity.value} (Risk: {round(risk, 1)}/100) proportional to deviation magnitude (Z = {max_z:.2f}σ).",
                        operational_limitations="Statistical anomalies indicate behavioral deviation from normal historical patterns, not deterministic proof of malicious intent. Legitimate traffic spikes (e.g. video streams or downloads) can also trigger anomalies.",
                    ),
                ))
            # Contamination Prevention: Do NOT update baseline with anomalous samples!
        else:
            # Normal traffic: update baseline only if not contaminated with ground-truth attack
            if not has_malicious_samples:
                self._update_baseline(obs_rate, obs_bytes)
                self.sample_count += 1

        return alerts

    def _update_baseline(self, obs_rate: float, obs_bytes: float) -> None:
        """Updates running EWMA baseline mean and variance."""
        alpha = self.config.ewma_alpha

        if self.sample_count == 0:
            self.mean_rate = obs_rate
            self.var_rate = max(1.0, obs_rate * 0.2)
            self.mean_bytes = obs_bytes
            self.var_bytes = max(100.0, obs_bytes * 0.2)
            return

        # Welford/EWMA running update
        diff_rate = obs_rate - self.mean_rate
        self.mean_rate += alpha * diff_rate
        self.var_rate = (1.0 - alpha) * (self.var_rate + alpha * (diff_rate ** 2))

        diff_bytes = obs_bytes - self.mean_bytes
        self.mean_bytes += alpha * diff_bytes
        self.var_bytes = (1.0 - alpha) * (self.var_bytes + alpha * (diff_bytes ** 2))

    def get_baseline_status(self) -> Dict[str, Any]:
        """Provides telemetry for dashboard display and reporting."""
        return {
            "is_warmed_up": self.is_warmed_up,
            "sample_count": self.sample_count,
            "warmup_target": self.warmup_target,
            "warmup_progress_pct": min(100.0, round((self.sample_count / max(1, self.warmup_target)) * 100, 1)),
            "mean_rate": round(self.mean_rate, 2),
            "std_rate": round(self.std_rate, 2),
            "mean_bytes": round(self.mean_bytes, 2),
            "std_bytes": round(self.std_bytes, 2),
            "last_observed_rate": round(self.last_observed_rate, 2),
            "last_observed_bytes": round(self.last_observed_bytes, 2),
            "last_z_score": round(self.last_z_score, 2),
            "z_threshold": self.config.z_score_threshold,
        }
