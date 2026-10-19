"""Unit tests for confusion matrix, evaluation metrics, and experiment runner."""

import pytest
from analytics.metrics import ConfusionMatrix, calculate_metrics
from analytics.experiment_runner import ExperimentRunner
from simulator.models import ScenarioType


def test_confusion_matrix_metrics_and_zero_division():
    # Test zero denominators handling
    empty_cm = ConfusionMatrix(tp=0, fp=0, tn=0, fn=0)
    assert empty_cm.precision == 0.0
    assert empty_cm.recall == 0.0
    assert empty_cm.f1_score == 0.0
    assert empty_cm.false_positive_rate == 0.0
    assert empty_cm.accuracy == 0.0

    # Test standard values
    cm = ConfusionMatrix(tp=80, fp=10, tn=90, fn=20)
    assert cm.total == 200
    # Precision = 80 / (80 + 10) = 80/90 ~= 0.8889
    assert abs(cm.precision - (80 / 90)) < 0.001
    # Recall = 80 / (80 + 20) = 80/100 = 0.8
    assert abs(cm.recall - 0.8) < 0.001
    # F1 = 2 * (p*r) / (p+r)
    expected_f1 = 2 * (cm.precision * cm.recall) / (cm.precision + cm.recall)
    assert abs(cm.f1_score - expected_f1) < 0.001
    # FPR = 10 / (10 + 90) = 0.1
    assert abs(cm.false_positive_rate - 0.1) < 0.001


def test_calculate_metrics_helper():
    gt = [True, True, False, False, True]
    pred = [True, False, False, True, True]
    cm = calculate_metrics(gt, pred)
    assert cm.tp == 2
    assert cm.fn == 1
    assert cm.fp == 1
    assert cm.tn == 1


def test_experiment_runner_benchmark():
    runner = ExperimentRunner()
    result = runner.run_benchmark(
        scenario=ScenarioType.PORT_SCAN,
        total_events=60,
        warmup_events=20,
        random_seed=42,
    )

    assert result.total_events == 60
    assert len(result.reports) == 3
    assert "Rule-Based Detector" in result.reports
    assert "Adaptive Baseline Detector" in result.reports
    assert "Combined Explainable Detector" in result.reports

    summary_table = result.to_summary_table()
    assert len(summary_table) == 3
    for row in summary_table:
        assert "precision" in row
        assert "recall" in row
        assert "f1_score" in row
        assert "fpr" in row
