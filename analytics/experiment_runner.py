"""Reproducible experiment runner for systematic detector comparison."""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import time
import random
from simulator.models import PacketEvent, ScenarioType
from simulator.generator import TrafficGenerator
from detection.rule_based import RuleBasedDetector
from detection.adaptive_baseline import AdaptiveBaselineDetector
from detection.combined_detector import CombinedExplainableDetector
from analytics.metrics import ConfusionMatrix, DetectorEvaluationReport, calculate_metrics
from utils.config import DEFAULT_CONFIG, SystemConfig


@dataclass
class ExperimentResult:
    """Consolidated findings across all evaluated detectors for an experiment run."""
    scenario_name: str
    random_seed: int
    total_events: int
    benign_count: int
    malicious_count: int
    reports: Dict[str, DetectorEvaluationReport]

    def to_summary_table(self) -> List[Dict[str, Any]]:
        """Transforms reports into tabular summary rows for display/export."""
        return [report.to_dict() for report in self.reports.values()]


class ExperimentRunner:
    """Executes controlled, reproducible benchmark experiments across detectors."""

    def __init__(self, config: Optional[SystemConfig] = None):
        self.config = config or DEFAULT_CONFIG

    def run_benchmark(
        self,
        scenario: ScenarioType = ScenarioType.PORT_SCAN,
        total_events: int = 200,
        warmup_events: int = 40,
        random_seed: int = 42,
    ) -> ExperimentResult:
        """Executes a standardized benchmark with a warm-up phase and test workload."""
        generator = TrafficGenerator(seed=random_seed)

        # Initialize fresh detector instances for fair comparison
        rule_detector = RuleBasedDetector(self.config.rules)
        adaptive_detector = AdaptiveBaselineDetector(self.config.adaptive)
        combined_detector = CombinedExplainableDetector(
            rule_detector=rule_detector,
            adaptive_detector=adaptive_detector,
            config=self.config.risk,
        )

        sim_clock = 1000.0

        # Phase 1: Baseline Warm-up with purely benign traffic
        for _ in range(warmup_events):
            sim_clock += 0.1
            benign_event = generator.generate_normal_event(timestamp=sim_clock)
            # Both detectors process warm-up events to establish baseline
            rule_detector.process_event(benign_event)
            adaptive_detector.process_event(benign_event)

        # Phase 2: Test Dataset Generation
        test_events: List[PacketEvent] = []
        for i in range(total_events):
            sim_clock += 0.1
            if scenario == ScenarioType.NORMAL:
                ev = generator.generate_normal_event(timestamp=sim_clock)
            elif scenario == ScenarioType.PORT_SCAN:
                ev = generator.generate_port_scan_event(timestamp=sim_clock) if (i % 2 == 0) else generator.generate_normal_event(timestamp=sim_clock)
            elif scenario == ScenarioType.HIGH_RATE:
                ev = generator.generate_high_rate_event(timestamp=sim_clock) if (i % 2 == 0) else generator.generate_normal_event(timestamp=sim_clock)
            elif scenario == ScenarioType.SYN_FLOOD:
                ev = generator.generate_syn_flood_event(timestamp=sim_clock) if (i % 2 == 0) else generator.generate_normal_event(timestamp=sim_clock)
            elif scenario == ScenarioType.ICMP_SPIKE:
                ev = generator.generate_icmp_spike_event(timestamp=sim_clock) if (i % 2 == 0) else generator.generate_normal_event(timestamp=sim_clock)
            elif scenario == ScenarioType.GRADUAL_DRIFT:
                ev = generator.generate_gradual_drift_event(timestamp=sim_clock)
            elif scenario == ScenarioType.MIXED:
                ev = generator.generate_mixed_event(timestamp=sim_clock, attack_prob=0.3)
            else:
                ev = generator.generate_normal_event(timestamp=sim_clock)

            test_events.append(ev)

        # Ground truth series
        ground_truth = [ev.is_malicious for ev in test_events]
        benign_count = sum(1 for gt in ground_truth if not gt)
        malicious_count = sum(1 for gt in ground_truth if gt)

        # Separate runs for independent detectors:
        # 1. Rule detector evaluation
        r_preds, r_delay, r_latencies = self._evaluate_isolated_detector(
            detector=rule_detector,
            events=test_events,
            detector_type="rule",
        )

        # 2. Adaptive detector evaluation
        a_preds, a_delay, a_latencies = self._evaluate_isolated_detector(
            detector=adaptive_detector,
            events=test_events,
            detector_type="adaptive",
        )

        # 3. Combined detector evaluation
        c_preds, c_delay, c_latencies = self._evaluate_isolated_detector(
            detector=combined_detector,
            events=test_events,
            detector_type="combined",
        )

        reports = {
            "Rule-Based Detector": DetectorEvaluationReport(
                detector_name="Rule-Based Detector",
                dataset_size=total_events,
                malicious_count=malicious_count,
                benign_count=benign_count,
                confusion_matrix=calculate_metrics(ground_truth, r_preds),
                mean_detection_latency_ms=sum(r_latencies) / len(r_latencies) if r_latencies else None,
                first_detection_delay_events=r_delay,
            ),
            "Adaptive Baseline Detector": DetectorEvaluationReport(
                detector_name="Adaptive Baseline Detector",
                dataset_size=total_events,
                malicious_count=malicious_count,
                benign_count=benign_count,
                confusion_matrix=calculate_metrics(ground_truth, a_preds),
                mean_detection_latency_ms=sum(a_latencies) / len(a_latencies) if a_latencies else None,
                first_detection_delay_events=a_delay,
            ),
            "Combined Explainable Detector": DetectorEvaluationReport(
                detector_name="Combined Explainable Detector",
                dataset_size=total_events,
                malicious_count=malicious_count,
                benign_count=benign_count,
                confusion_matrix=calculate_metrics(ground_truth, c_preds),
                mean_detection_latency_ms=sum(c_latencies) / len(c_latencies) if c_latencies else None,
                first_detection_delay_events=c_delay,
            ),
        }

        return ExperimentResult(
            scenario_name=scenario.value,
            random_seed=random_seed,
            total_events=total_events,
            benign_count=benign_count,
            malicious_count=malicious_count,
            reports=reports,
        )

    def _evaluate_isolated_detector(
        self, detector: Any, events: List[PacketEvent], detector_type: str
    ) -> tuple[List[bool], Optional[int], List[float]]:
        """Processes events through the detector and tracks predictions and latency."""
        predictions: List[bool] = []
        first_attack_seen_idx: Optional[int] = None
        first_alert_idx: Optional[int] = None
        latencies_ms: List[float] = []

        for idx, event in enumerate(events):
            t0 = time.perf_counter()
            alerts = detector.process_event(event)
            t_elapsed_ms = (time.perf_counter() - t0) * 1000.0

            if event.is_malicious and first_attack_seen_idx is None:
                first_attack_seen_idx = idx

            has_alert = len(alerts) > 0
            predictions.append(has_alert)

            if has_alert:
                latencies_ms.append(t_elapsed_ms)
                if event.is_malicious and first_alert_idx is None:
                    first_alert_idx = idx

        delay_events = None
        if first_attack_seen_idx is not None and first_alert_idx is not None:
            delay_events = max(0, first_alert_idx - first_attack_seen_idx)

        return predictions, delay_events, latencies_ms
