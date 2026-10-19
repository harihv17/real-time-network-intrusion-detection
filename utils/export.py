"""Data export utilities for events, alerts, and benchmark evaluations."""

import io
from typing import List, Dict, Any
import pandas as pd
from simulator.models import PacketEvent
from detection.models import Alert


def export_events_to_dataframe(events: List[PacketEvent]) -> pd.DataFrame:
    """Converts a collection of PacketEvents to a pandas DataFrame."""
    if not events:
        return pd.DataFrame(columns=[
            "event_id", "timestamp", "src_ip", "dst_ip", "src_port",
            "dst_port", "protocol", "packet_size", "tcp_flags", "scenario",
            "data_source", "is_malicious", "attack_type"
        ])
    rows = []
    for e in events:
        d = e.to_dict()
        d["data_source"] = "Live Capture" if e.scenario == "Live Network Traffic" else "Simulation"
        rows.append(d)
    return pd.DataFrame(rows)


def export_events_to_csv(events: List[PacketEvent]) -> str:
    """Serializes events into a CSV string."""
    df = export_events_to_dataframe(events)
    return df.to_csv(index=False)


def export_alerts_to_dataframe(alerts: List[Alert]) -> pd.DataFrame:
    """Converts a collection of Alerts to a flattened pandas DataFrame for analysis."""
    if not alerts:
        return pd.DataFrame(columns=[
            "alert_id", "timestamp", "data_source", "src_ip", "dst_ip", "method", "severity",
            "risk_score", "attack_type", "rule_or_condition", "observed_value",
            "threshold_or_baseline", "what_happened", "evidence_summary",
            "expected_baseline", "trigger_comparison", "detector_source",
            "severity_rationale", "operational_limitations", "reason", "z_score", "status"
        ])

    rows = []
    for a in alerts:
        exp = a.explanation
        row = {
            "alert_id": a.alert_id,
            "timestamp": a.timestamp,
            "data_source": getattr(a, "data_source", "Live Capture"),
            "src_ip": a.src_ip,
            "dst_ip": a.dst_ip or "",
            "method": a.method.value if hasattr(a.method, "value") else str(a.method),
            "severity": a.severity.value if hasattr(a.severity, "value") else str(a.severity),
            "risk_score": a.risk_score,
            "attack_type": a.attack_type,
            "rule_or_condition": exp.rule_or_condition if exp else "",
            "observed_value": exp.observed_value if exp else "",
            "threshold_or_baseline": exp.threshold_or_baseline if exp else "",
            "what_happened": exp.what_happened if exp else "",
            "evidence_summary": exp.evidence_summary if exp else "",
            "expected_baseline": exp.expected_baseline if exp else "",
            "trigger_comparison": exp.trigger_comparison if exp else "",
            "detector_source": exp.detector_source if exp else "",
            "severity_rationale": exp.severity_rationale if exp else "",
            "operational_limitations": exp.operational_limitations if exp else "",
            "reason": exp.reason if exp else "",
            "z_score": exp.z_score if exp else "",
            "status": a.status,
            "ground_truth_malicious": a.ground_truth_malicious if a.ground_truth_malicious is not None else "",
        }
        rows.append(row)
    return pd.DataFrame(rows)


def export_alerts_to_csv(alerts: List[Alert]) -> str:
    """Serializes alerts into a CSV string."""
    df = export_alerts_to_dataframe(alerts)
    return df.to_csv(index=False)


def export_experiment_to_csv(experiment_summary_rows: List[Dict[str, Any]]) -> str:
    """Serializes benchmark results into a CSV string."""
    df = pd.DataFrame(experiment_summary_rows)
    return df.to_csv(index=False)
