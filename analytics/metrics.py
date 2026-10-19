"""Evaluation metrics, confusion matrices, and detection performance calculation."""

from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional, List


@dataclass
class ConfusionMatrix:
    """Standard binary classification confusion matrix with defensive zero-division guards."""
    tp: int = 0  # True Positives
    fp: int = 0  # False Positives
    tn: int = 0  # True Negatives
    fn: int = 0  # False Negatives

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return float(self.tp / denom) if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return float(self.tp / denom) if denom > 0 else 0.0

    @property
    def f1_score(self) -> float:
        p = self.precision
        r = self.recall
        denom = p + r
        return float(2.0 * (p * r) / denom) if denom > 0 else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.fp + self.tn
        return float(self.fp / denom) if denom > 0 else 0.0

    @property
    def accuracy(self) -> float:
        return float((self.tp + self.tn) / self.total) if self.total > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "total": self.total,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "accuracy": round(self.accuracy, 4),
        }


@dataclass
class DetectorEvaluationReport:
    """Performance evaluation record for a single detector approach."""
    detector_name: str
    dataset_size: int
    malicious_count: int
    benign_count: int
    confusion_matrix: ConfusionMatrix
    mean_detection_latency_ms: Optional[float] = None
    first_detection_delay_events: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        cm_dict = self.confusion_matrix.to_dict()
        return {
            "detector": self.detector_name,
            "dataset_size": self.dataset_size,
            "malicious_events": self.malicious_count,
            "benign_events": self.benign_count,
            "precision": cm_dict["precision"],
            "recall": cm_dict["recall"],
            "f1_score": cm_dict["f1_score"],
            "fpr": cm_dict["false_positive_rate"],
            "accuracy": cm_dict["accuracy"],
            "tp": cm_dict["tp"],
            "fp": cm_dict["fp"],
            "tn": cm_dict["tn"],
            "fn": cm_dict["fn"],
            "detection_latency_ms": round(self.mean_detection_latency_ms, 2) if self.mean_detection_latency_ms is not None else "N/A",
            "first_detection_delay_events": self.first_detection_delay_events if self.first_detection_delay_events is not None else "N/A",
        }


def calculate_metrics(
    ground_truth: List[bool],
    predictions: List[bool],
    latency_records: Optional[List[float]] = None,
) -> ConfusionMatrix:
    """Calculates confusion matrix from pairwise boolean arrays."""
    cm = ConfusionMatrix()
    for actual, pred in zip(ground_truth, predictions):
        if actual and pred:
            cm.tp += 1
        elif not actual and pred:
            cm.fp += 1
        elif not actual and not pred:
            cm.tn += 1
        else:
            cm.fn += 1
    return cm
