"""Design and Implementation of a Real-Time Network Intrusion Detection System
Using Packet Traffic Analysis

Streamlit Security Operations Center (SOC) Dashboard.
Supports both Genuine Live Packet Capture and Deterministic Network Simulation.
"""

import time
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from simulator.models import ScenarioType, Protocol
from simulator.engine import SimulationEngine
from capture.engine import LiveCaptureEngine, CaptureState
from capture.interfaces import check_capture_prerequisites, get_available_interfaces, is_running_as_admin
from detection.engine import DetectionPipeline
from detection.models import DetectionMethod, Severity
from analytics.experiment_runner import ExperimentRunner
from utils.config import SystemConfig, DEFAULT_CONFIG
from utils.export import (
    export_events_to_csv,
    export_alerts_to_csv,
    export_events_to_dataframe,
    export_alerts_to_dataframe,
    export_experiment_to_csv,
)

# ---------------------------------------------------------
# Page Configuration
# ---------------------------------------------------------
st.set_page_config(
    page_title="SOC CyberGuard — Real-Time NIDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------
# Refined SOC Dark Theme CSS
# ---------------------------------------------------------
SOC_CSS = """
<style>
    /* Global Background and Typography */
    .stApp {
        background-color: #0b0f19;
        color: #f1f5f9;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }
    
    /* Remove white header strip & tighten layout spacing */
    header[data-testid="stHeader"] {
        background: transparent !important;
        height: 2rem !important;
    }
    
    .block-container {
        padding-top: 1.25rem !important;
        padding-bottom: 2rem !important;
        padding-left: 1.5rem !important;
        padding-right: 1.5rem !important;
        max-width: 100% !important;
    }
    
    /* Sidebar Styling */
    [data-testid="stSidebar"] {
        background-color: #0d131f !important;
        border-right: 1px solid #1e293b !important;
    }
    [data-testid="stSidebar"] .stMarkdown p,
    [data-testid="stSidebar"] label,
    [data-testid="stSidebar"] span {
        color: #cbd5e1 !important;
        font-size: 0.85rem;
    }
    [data-testid="stSidebar"] h1,
    [data-testid="stSidebar"] h2,
    [data-testid="stSidebar"] h3,
    [data-testid="stSidebar"] h4 {
        color: #f8fafc !important;
        font-weight: 600 !important;
        letter-spacing: -0.01em;
    }
    
    /* Input and Selectbox Dark SOC Styling */
    div[data-baseweb="select"] > div {
        background-color: #141d2e !important;
        border-color: #2d3b55 !important;
        color: #f8fafc !important;
    }
    div[data-baseweb="input"] {
        background-color: #141d2e !important;
        border-color: #2d3b55 !important;
        color: #f8fafc !important;
    }
    
    /* Buttons */
    button[kind="secondary"] {
        background-color: #162032 !important;
        border: 1px solid #26354a !important;
        color: #e2e8f0 !important;
        font-weight: 500 !important;
        transition: all 0.15s ease-in-out;
    }
    button[kind="secondary"]:hover {
        background-color: #1e2d44 !important;
        border-color: #38bdf8 !important;
        color: #ffffff !important;
    }
    button[kind="primary"] {
        background-color: #0284c7 !important;
        border: 1px solid #0284c7 !important;
        color: #ffffff !important;
        font-weight: 600 !important;
        transition: all 0.15s ease-in-out;
    }
    button[kind="primary"]:hover {
        background-color: #0369a1 !important;
        border-color: #0369a1 !important;
    }

    /* KPI Card styling */
    .kpi-card {
        background-color: #111827;
        border: 1px solid #1e293b;
        border-radius: 6px;
        padding: 12px 14px;
        margin-bottom: 8px;
    }
    .kpi-title {
        color: #94a3b8;
        font-size: 0.72rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        font-weight: 600;
        margin-bottom: 3px;
    }
    .kpi-value {
        color: #f8fafc;
        font-size: 1.45rem;
        font-weight: 700;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        line-height: 1.2;
    }
    .kpi-sub {
        font-size: 0.72rem;
        color: #64748b;
        margin-top: 4px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }

    /* Severity badges */
    .badge-critical {
        background-color: #450a0a;
        color: #fca5a5;
        border: 1px solid #b91c1c;
        padding: 2px 7px;
        border-radius: 4px;
        font-size: 0.72rem;
        font-weight: 700;
        display: inline-block;
    }
    .badge-high {
        background-color: #431407;
        color: #fdba74;
        border: 1px solid #c2410c;
        padding: 2px 7px;
        border-radius: 4px;
        font-size: 0.72rem;
        font-weight: 700;
        display: inline-block;
    }
    .badge-medium {
        background-color: #422006;
        color: #fde047;
        border: 1px solid #a16207;
        padding: 2px 7px;
        border-radius: 4px;
        font-size: 0.72rem;
        font-weight: 600;
        display: inline-block;
    }
    .badge-low {
        background-color: #172554;
        color: #93c5fd;
        border: 1px solid #1d4ed8;
        padding: 2px 7px;
        border-radius: 4px;
        font-size: 0.72rem;
        font-weight: 600;
        display: inline-block;
    }

    /* Mode indicator badge */
    .mode-badge-live {
        background-color: #064e3b;
        color: #34d399;
        border: 1px solid #059669;
        padding: 3px 10px;
        border-radius: 4px;
        font-size: 0.78rem;
        font-weight: 700;
        letter-spacing: 0.04em;
        display: inline-block;
    }
    .mode-badge-sim {
        background-color: #1e3a5f;
        color: #60a5fa;
        border: 1px solid #2563eb;
        padding: 3px 10px;
        border-radius: 4px;
        font-size: 0.78rem;
        font-weight: 700;
        letter-spacing: 0.04em;
        display: inline-block;
    }

    /* Restrained status indicators */
    .status-pill {
        display: inline-block;
        width: 8px;
        height: 8px;
        border-radius: 50%;
        margin-right: 6px;
    }
    .status-green { background-color: #10b981; }
    .status-amber { background-color: #f59e0b; }
    .status-red { background-color: #ef4444; }
    .status-gray { background-color: #64748b; }

    /* Explainability forensic card */
    .explain-card {
        background-color: #111827;
        border: 1px solid #1e293b;
        border-radius: 6px;
        padding: 12px 14px;
        margin-bottom: 10px;
    }
    .explain-q {
        color: #38bdf8;
        font-size: 0.78rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        margin-bottom: 4px;
    }
    .explain-a {
        color: #e2e8f0;
        font-size: 0.88rem;
        line-height: 1.45;
    }

    /* Compact tables */
    .stDataFrame {
        border: 1px solid #1e293b;
        border-radius: 6px;
    }
</style>
"""
st.markdown(SOC_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------
# Session State Initialization (Complete Isolation of Modes)
# ---------------------------------------------------------
if "operating_mode" not in st.session_state:
    st.session_state.operating_mode = "Simulation"

if "sim_engine" not in st.session_state:
    st.session_state.sim_engine = SimulationEngine()

if "sim_pipeline" not in st.session_state:
    st.session_state.sim_pipeline = DetectionPipeline()

if "live_engine" not in st.session_state:
    st.session_state.live_engine = LiveCaptureEngine()

if "live_pipeline" not in st.session_state:
    st.session_state.live_pipeline = DetectionPipeline()

if "auto_run" not in st.session_state:
    st.session_state.auto_run = False

if "last_benchmark" not in st.session_state:
    st.session_state.last_benchmark = None

if "iface_refresh_nonce" not in st.session_state:
    st.session_state.iface_refresh_nonce = 0

sim_engine: SimulationEngine = st.session_state.sim_engine
sim_pipeline: DetectionPipeline = st.session_state.sim_pipeline
live_engine: LiveCaptureEngine = st.session_state.live_engine
live_pipeline: DetectionPipeline = st.session_state.live_pipeline


# ---------------------------------------------------------
# Sidebar: Structured Operations & Controls
# ---------------------------------------------------------
with st.sidebar:
    st.markdown("### 🛡️ NIDS SOC Command")
    st.caption("College Final Year Project • CS & Cybersecurity")
    st.markdown("---")

    # SECTION 1: OPERATING MODE
    st.markdown("#### OPERATING MODE")
    selected_mode = st.radio(
        "Select Pipeline Mode",
        options=["Simulation", "Live Capture"],
        index=0 if st.session_state.operating_mode == "Simulation" else 1,
        help="Switch between synthetic traffic simulation and live packet sniffing on network interfaces.",
    )
    st.session_state.operating_mode = selected_mode

    st.markdown("---")

    # SECTION 2: DETECTION CONFIGURATION (Shared Architecture)
    st.markdown("#### DETECTION CONFIGURATION")
    detection_mode_str = st.radio(
        "Detection Strategy",
        options=[
            DetectionMethod.COMBINED_EXPLAINABLE.value,
            DetectionMethod.RULE_BASED.value,
            DetectionMethod.ADAPTIVE_BASELINE.value,
        ],
        index=0,
        help="Combined mode fuses heuristic rules and statistical baselines into explainable alerts.",
    )
    active_detection_method = DetectionMethod(detection_mode_str)

    # Active pipeline reference based on selected mode
    current_pipeline = live_pipeline if st.session_state.operating_mode == "Live Capture" else sim_pipeline

    with st.expander("⚙️ Detection Thresholds"):
        st.caption("Sliding-window heuristics & statistical bounds")
        ps_thresh = st.number_input("Port Scan Ports Thresh", min_value=3, max_value=30, value=current_pipeline.config.rules.port_scan_threshold)
        current_pipeline.config.rules.port_scan_threshold = ps_thresh

        syn_thresh = st.number_input("SYN Flood Count Thresh", min_value=3, max_value=50, value=current_pipeline.config.rules.syn_flood_threshold)
        current_pipeline.config.rules.syn_flood_threshold = syn_thresh

        hr_thresh = st.number_input("High Rate Count Thresh", min_value=10, max_value=100, value=current_pipeline.config.rules.high_rate_threshold)
        current_pipeline.config.rules.high_rate_threshold = hr_thresh

        icmp_thresh = st.number_input("ICMP Spike Count Thresh", min_value=5, max_value=50, value=current_pipeline.config.rules.icmp_spike_threshold)
        current_pipeline.config.rules.icmp_spike_threshold = icmp_thresh

        z_thresh = st.slider("Adaptive Z-Score Thresh", min_value=1.5, max_value=5.0, value=float(current_pipeline.config.adaptive.z_score_threshold), step=0.1)
        current_pipeline.config.adaptive.z_score_threshold = z_thresh

    # SECTION 3: MODE-SPECIFIC CONTROLS & STATUS
    if st.session_state.operating_mode == "Live Capture":
        st.markdown("---")
        st.markdown("#### NETWORK CONFIGURATION")

        # Network Interface Discovery
        available_ifs = get_available_interfaces()
        selected_if_name = None

        if available_ifs:
            if_options = {item["display_label"]: item["name"] for item in available_ifs}
            selected_if_label = st.selectbox(
                "Network Interface",
                options=list(if_options.keys()),
                help="Select network adapter to listen for live incoming/outgoing packets.",
            )
            selected_if_name = if_options[selected_if_label]
        else:
            st.warning("No physical adapters enumerated. Defaulting to system default interface.")

        col_ref1, col_ref2 = st.columns([1, 1])
        with col_ref1:
            if st.button("🔄 Refresh List", width="stretch"):
                st.session_state.iface_refresh_nonce += 1
                st.rerun()

        # Optional BPF Capture Filter
        bpf_filter_input = st.text_input(
            "BPF Capture Filter (Optional)",
            value="",
            placeholder="e.g. ip, tcp, port 80, udp",
            help="Berkeley Packet Filter string passed to Scapy sniffer.",
        )

        # Prerequisites Status Indicator
        prereq = check_capture_prerequisites()
        if prereq.get("is_cloud", False):
            st.warning(
                "☁️ **Hosted Cloud Instance**\n\n"
                "Streamlit Community Cloud runs in a virtual container without physical network adapter or raw packet driver access.\n\n"
                "👉 Switch to **Simulation Mode** above for the complete real-time detection demonstration."
            )
        else:
            if not prereq["npcap_installed"]:
                st.caption("⚠️ Npcap driver: **Not Installed**")
            else:
                st.caption("✅ Npcap driver: **Installed**")
            if not prereq["is_admin"]:
                st.caption("ℹ️ Elevation: **Standard User** (Admin recommended)")
            else:
                st.caption("🛡️ Elevation: **Administrator**")

        st.markdown("---")
        st.markdown("#### CAPTURE CONTROLS")

        col_l1, col_l2 = st.columns(2)
        with col_l1:
            start_btn = st.button("▶️ Start Sniffing", width="stretch", type="primary", disabled=(live_engine.state == CaptureState.CAPTURING or prereq.get("is_cloud", False)))
            if start_btn:
                success = live_engine.start_capture(interface_name=selected_if_name, bpf_filter=bpf_filter_input)
                st.rerun()
        with col_l2:
            stop_btn = st.button("⏹️ Stop Sniffing", width="stretch", disabled=(live_engine.state == CaptureState.STOPPED))
            if stop_btn:
                live_engine.stop_capture()
                st.rerun()

        col_p1, col_p2 = st.columns(2)
        with col_p1:
            if live_engine.state == CaptureState.CAPTURING:
                if st.button("⏸️ Pause", width="stretch"):
                    live_engine.pause_capture()
                    st.rerun()
            elif live_engine.state == CaptureState.PAUSED:
                if st.button("▶️ Resume", width="stretch"):
                    live_engine.resume_capture()
                    st.rerun()
            else:
                st.button("⏸️ Pause", width="stretch", disabled=True)
        with col_p2:
            if st.button("🔄 Reset Ledger", width="stretch"):
                live_engine.reset()
                live_pipeline.reset()
                st.rerun()

        st.markdown("#### CAPTURE STATUS")
        cap_status = live_engine.state
        if cap_status == CaptureState.CAPTURING:
            st.markdown(f'<div><span class="status-pill status-green"></span><b>CAPTURING LIVE TRAFFIC</b><br><small style="color:#94a3b8;">Adapter: {selected_if_name or "Default"}</small></div>', unsafe_allow_html=True)
        elif cap_status == CaptureState.PAUSED:
            st.markdown(f'<div><span class="status-pill status-amber"></span><b>CAPTURE PAUSED</b><br><small style="color:#94a3b8;">Ingestion suspended</small></div>', unsafe_allow_html=True)
        elif cap_status == CaptureState.STARTING:
            st.markdown('<div><span class="status-pill status-amber"></span><b>STARTING WORKER...</b></div>', unsafe_allow_html=True)
        elif cap_status == CaptureState.ERROR:
            st.markdown('<div><span class="status-pill status-red"></span><b>CAPTURE ERROR</b></div>', unsafe_allow_html=True)
        else:
            st.markdown('<div><span class="status-pill status-gray"></span><b>SNIFFER STOPPED</b></div>', unsafe_allow_html=True)

        st.caption(f"Captured: **{live_engine.captured_packets_count:,}** | Buffer: **{len(live_engine.captured_events_buffer)}**")

        # Drain packet queue into live detection pipeline
        if live_engine.state == CaptureState.CAPTURING:
            new_live_packets = live_engine.drain_packet_queue(max_packets=100)
            for pkt_event in new_live_packets:
                live_pipeline.process_event(pkt_event, active_method=active_detection_method)

    else:
        # Simulation Mode Controls
        st.markdown("---")
        st.markdown("#### SIMULATION CONTROLS")

        selected_scenario_val = st.selectbox(
            "Traffic Scenario",
            options=[s.value for s in ScenarioType],
            index=0,
            help="Selects network condition generated by the simulator.",
        )
        for s in ScenarioType:
            if s.value == selected_scenario_val:
                sim_engine.set_scenario(s)
                break

        sim_rate = st.slider("Simulated Rate (pkts/sec)", min_value=1, max_value=50, value=int(sim_engine.events_per_second), step=1)
        sim_engine.set_rate(sim_rate)

        col_c1, col_c2, col_c3 = st.columns(3)
        with col_c1:
            if st.button("▶️ Run", width="stretch", type="primary", disabled=(sim_engine.is_running and not sim_engine.is_paused)):
                sim_engine.start()
                st.session_state.auto_run = True
                st.rerun()
        with col_c2:
            if st.button("⏸️ Pause", width="stretch", disabled=(not sim_engine.is_running or sim_engine.is_paused)):
                sim_engine.pause()
                st.session_state.auto_run = False
                st.rerun()
        with col_c3:
            if st.button("⏹️ Stop", width="stretch", disabled=(not sim_engine.is_running and not sim_engine.is_paused)):
                sim_engine.stop()
                st.session_state.auto_run = False
                st.rerun()

        col_s1, col_s2 = st.columns(2)
        with col_s1:
            step_10 = st.button("⏩ Step +10", width="stretch")
        with col_s2:
            step_50 = st.button("⏩ Step +50", width="stretch")

        if st.button("🔄 Reset Simulator State", width="stretch"):
            sim_engine.reset()
            sim_pipeline.reset()
            st.session_state.auto_run = False
            st.session_state.last_benchmark = None
            st.rerun()

        st.markdown("#### SIMULATION STATUS")
        if sim_engine.is_running and not sim_engine.is_paused:
            st.markdown(f'<div><span class="status-pill status-green"></span><b>SIMULATION ACTIVE</b><br><small style="color:#94a3b8;">Scenario: {sim_engine.current_scenario.value}</small></div>', unsafe_allow_html=True)
        elif sim_engine.is_paused:
            st.markdown('<div><span class="status-pill status-amber"></span><b>SIMULATION PAUSED</b></div>', unsafe_allow_html=True)
        else:
            st.markdown('<div><span class="status-pill status-gray"></span><b>SIMULATOR STANDBY</b></div>', unsafe_allow_html=True)

        st.caption(f"Generated: **{sim_engine.total_events:,}** | Buffer: **{len(sim_engine.event_buffer)}**")

        # Step generation logic
        if step_10:
            new_events = sim_engine.step(num_events=10)
            for ev in new_events:
                sim_pipeline.process_event(ev, active_method=active_detection_method)
        elif step_50:
            new_events = sim_engine.step(num_events=50)
            for ev in new_events:
                sim_pipeline.process_event(ev, active_method=active_detection_method)

        # Continuous Auto-run batch if active
        if st.session_state.auto_run and not sim_engine.is_paused:
            batch_size = max(5, int(sim_engine.events_per_second * 0.5))
            new_events = sim_engine.step(num_events=batch_size)
            for ev in new_events:
                sim_pipeline.process_event(ev, active_method=active_detection_method)


# ---------------------------------------------------------
# Dynamic Binding of Current Mode Data & Pipeline
# ---------------------------------------------------------
is_live_mode = (st.session_state.operating_mode == "Live Capture")

if is_live_mode:
    active_engine = live_engine
    active_pipeline = live_pipeline
    total_packets_label = "Captured Packets"
    total_packets_val = live_engine.captured_packets_count
    volume_label = "Observed Volume"
    volume_bytes = live_engine.observed_bytes_count
    hosts_label = "Observed Hosts"
    unique_hosts_count = len(live_engine.unique_src_ips)
    recent_events_list = list(live_engine.captured_events_buffer)
    buffer_capacity = "5,000"
    current_packet_rate_val = live_engine.current_packet_rate
else:
    active_engine = sim_engine
    active_pipeline = sim_pipeline
    total_packets_label = "Simulated Packets"
    total_packets_val = sim_engine.total_events
    volume_label = "Simulated Volume"
    volume_bytes = sim_engine.total_bytes
    hosts_label = "Active Hosts"
    unique_hosts_count = len(sim_engine.unique_src_ips)
    recent_events_list = list(sim_engine.event_buffer)
    buffer_capacity = f"{sim_engine.config.max_history_events:,}"
    current_packet_rate_val = sim_engine.events_per_second if (sim_engine.is_running and not sim_engine.is_paused) else 0.0


# ---------------------------------------------------------
# Main Page Header & Operational Status Indicator
# ---------------------------------------------------------
col_h1, col_h2 = st.columns([3, 2])
with col_h1:
    st.markdown("## 🛡️ Real-Time Network Intrusion Detection System")
    st.caption("Packet Traffic Analysis • Rule-Based Signatures • Adaptive EWMA Anomaly Engine • Explainable Risk Scoring")
with col_h2:
    st.markdown("<div style='text-align: right; margin-top: 6px;'>", unsafe_allow_html=True)
    if is_live_mode:
        st.markdown('<span class="mode-badge-live">📡 LIVE CAPTURE MODE (LOCAL ADAPTER)</span>', unsafe_allow_html=True)
        if live_engine.state == CaptureState.CAPTURING:
            if_disp = live_engine.selected_interface or "Default"
            st.markdown(f'<div style="margin-top: 5px; font-size: 0.8rem; color: #34d399;"><span class="status-pill status-green"></span>Capturing on <b>{if_disp}</b></div>', unsafe_allow_html=True)
        elif live_engine.state == CaptureState.PAUSED:
            st.markdown('<div style="margin-top: 5px; font-size: 0.8rem; color: #f59e0b;"><span class="status-pill status-amber"></span>Capture Paused</div>', unsafe_allow_html=True)
        elif live_engine.state == CaptureState.ERROR:
            st.markdown('<div style="margin-top: 5px; font-size: 0.8rem; color: #ef4444;"><span class="status-pill status-red"></span>Capture Error</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div style="margin-top: 5px; font-size: 0.8rem; color: #64748b;"><span class="status-pill status-gray"></span>Capture Stopped</div>', unsafe_allow_html=True)
    else:
        st.markdown('<span class="mode-badge-sim">🧪 SIMULATION MODE (PUBLIC DEMO)</span>', unsafe_allow_html=True)
        if sim_engine.is_running and not sim_engine.is_paused:
            st.markdown(f'<div style="margin-top: 5px; font-size: 0.8rem; color: #60a5fa;"><span class="status-pill status-green"></span>Simulating: <b>{sim_engine.current_scenario.value}</b></div>', unsafe_allow_html=True)
        elif sim_engine.is_paused:
            st.markdown('<div style="margin-top: 5px; font-size: 0.8rem; color: #f59e0b;"><span class="status-pill status-amber"></span>Simulation Paused</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div style="margin-top: 5px; font-size: 0.8rem; color: #64748b;"><span class="status-pill status-gray"></span>Simulator Standby</div>', unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)


# ---------------------------------------------------------
# Cloud Hosting & Live Capture Guidance Banner
# ---------------------------------------------------------
if is_live_mode:
    prereq = check_capture_prerequisites()
    if prereq.get("is_cloud", False):
        st.info(
            "☁️ **Streamlit Community Cloud Notice: Live Adapter Capture Disabled**\n\n"
            "This public web app is hosted on a secure cloud container. Web applications running on public cloud servers "
            "do not have permission or physical access to sniff visitors' local laptop network adapters.\n\n"
            "• **For faculty demonstration on this public URL:** Switch to **Simulation Mode** in the sidebar. "
            "It streams reproducible network traffic through the exact same heuristic and adaptive anomaly detection engines.\n"
            "• **For genuine local packet capture:** Clone this repository to an authorized local machine with Python and Npcap/libpcap installed (`streamlit run app.py`)."
        )
    elif live_engine.state == CaptureState.ERROR:
        st.error(
            f"🚨 **Live Packet Capture Error:** {live_engine.error_message}\n\n"
            f"**Resolution Instructions:**\n{live_engine.diagnostic_advice}"
        )


# ---------------------------------------------------------
# Operational Metrics (6 Compact KPI Cards)
# ---------------------------------------------------------
summary = active_pipeline.get_metrics_summary()
base_stats = summary["baseline_stats"]

kpi1, kpi2, kpi3, kpi4, kpi5, kpi6 = st.columns(6)

with kpi1:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-title">{total_packets_label}</div>
            <div class="kpi-value">{total_packets_val:,}</div>
            <div class="kpi-sub">Buffer: {len(recent_events_list)} / {buffer_capacity}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with kpi2:
    bytes_kb = volume_bytes / 1024.0
    bytes_str = f"{bytes_kb:.1f} KB" if bytes_kb < 1024 else f"{(bytes_kb / 1024):.2f} MB"
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-title">{volume_label}</div>
            <div class="kpi-value">{bytes_str}</div>
            <div class="kpi-sub">Header & Payload Bytes</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with kpi3:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-title">Ingestion Rate</div>
            <div class="kpi-value">{current_packet_rate_val:.1f}</div>
            <div class="kpi-sub">Packets / Second</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with kpi4:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-title">{hosts_label}</div>
            <div class="kpi-value">{unique_hosts_count}</div>
            <div class="kpi-sub">Unique Source IPs</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with kpi5:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-title">Total Alerts</div>
            <div class="kpi-value">{summary['total_alerts']}</div>
            <div class="kpi-sub">{active_detection_method.value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with kpi6:
    crit_count = summary["critical_count"] + summary["high_count"]
    crit_color = "#f87171" if crit_count > 0 else "#34d399"
    warmed = base_stats["is_warmed_up"]
    base_sub = "Baseline: Active" if warmed else f"Learning ({base_stats['sample_count']}/{base_stats['warmup_target']})"
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-title">High / Critical</div>
            <div class="kpi-value" style="color: {crit_color};">{crit_count}</div>
            <div class="kpi-sub">{base_sub}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------
# Main Tabs: Dashboard, Alerts, Baseline, Evaluation, Data
# ---------------------------------------------------------
tab_soc, tab_alerts, tab_baseline, tab_eval, tab_export = st.tabs([
    "📊 Traffic Telemetry",
    "🚨 Explainable Alert Centre",
    "📈 Adaptive Baseline Engine",
    "🔬 Detector Benchmark",
    "💾 Export & Investigation",
])


# ---------------------------------------------------------
# TAB 1: Traffic Telemetry
# ---------------------------------------------------------
with tab_soc:
    stream_title = "Live Network Ingestion Stream (Hardware Packet Capture)" if is_live_mode else "Synthetic Traffic Ingestion Stream"
    st.markdown(f"#### {stream_title}")

    df_events = export_events_to_dataframe(recent_events_list[-200:] if len(recent_events_list) > 200 else recent_events_list)

    if not df_events.empty:
        col_g1, col_g2 = st.columns([2, 1])

        with col_g1:
            # 1. Packet Ingestion Rate Over Time
            df_events["time_sec"] = pd.to_datetime(df_events["timestamp"], unit="s")
            resampled = df_events.set_index("time_sec").resample("1s").size().reset_index(name="packet_count")

            fig_rate = px.line(
                resampled,
                x="time_sec",
                y="packet_count",
                title=f"{'Live Capture' if is_live_mode else 'Simulated'} Ingestion Rate (Packets / Second)",
                labels={"time_sec": "Time", "packet_count": "Packets/sec"},
                template="plotly_dark",
            )
            fig_rate.update_traces(line=dict(color="#38bdf8", width=2.5))
            fig_rate.update_layout(
                paper_bgcolor="#111827",
                plot_bgcolor="#111827",
                margin=dict(l=20, r=20, t=35, b=20),
                height=250,
            )
            st.plotly_chart(fig_rate, width="stretch")

        with col_g2:
            # 2. Protocol Distribution Donut Chart
            proto_counts = df_events["protocol"].value_counts().reset_index()
            proto_counts.columns = ["Protocol", "Count"]

            fig_proto = px.pie(
                proto_counts,
                names="Protocol",
                values="Count",
                hole=0.55,
                title="Protocol Breakdown",
                template="plotly_dark",
                color="Protocol",
                color_discrete_map={"TCP": "#0284c7", "UDP": "#10b981", "ICMP": "#f59e0b", "ARP": "#8b5cf6", "IP-OTHER": "#94a3b8"},
            )
            fig_proto.update_layout(
                paper_bgcolor="#111827",
                plot_bgcolor="#111827",
                margin=dict(l=20, r=20, t=35, b=20),
                height=250,
            )
            st.plotly_chart(fig_proto, width="stretch")

        col_ip1, col_ip2 = st.columns([1, 1])
        with col_ip1:
            # 3. Top Active Source IPs
            ip_counts = df_events["src_ip"].value_counts().head(8).reset_index()
            ip_counts.columns = ["Source IP", "Packets"]
            fig_ips = px.bar(
                ip_counts,
                x="Packets",
                y="Source IP",
                orientation="h",
                title="Top Active Source Hosts",
                template="plotly_dark",
                color="Packets",
                color_continuous_scale="Teal",
            )
            fig_ips.update_layout(
                paper_bgcolor="#111827",
                plot_bgcolor="#111827",
                margin=dict(l=20, r=20, t=35, b=20),
                height=220,
            )
            st.plotly_chart(fig_ips, width="stretch")

        with col_ip2:
            # 4. Destination Port Frequency
            dst_port_counts = df_events["dst_port"].value_counts().head(8).reset_index()
            dst_port_counts.columns = ["Destination Port", "Packets"]
            dst_port_counts["Destination Port"] = dst_port_counts["Destination Port"].astype(str)
            fig_ports = px.bar(
                dst_port_counts,
                x="Packets",
                y="Destination Port",
                orientation="h",
                title="Top Target Ports (Target Services)",
                template="plotly_dark",
                color="Packets",
                color_continuous_scale="Blues",
            )
            fig_ports.update_layout(
                paper_bgcolor="#111827",
                plot_bgcolor="#111827",
                margin=dict(l=20, r=20, t=35, b=20),
                height=220,
            )
            st.plotly_chart(fig_ports, width="stretch")

        # Row 3: Packet Size Distribution & Ground Truth / Traffic Classification
        col_ps1, col_ps2 = st.columns([1, 1])
        with col_ps1:
            # 5. Packet Size Distribution Histogram
            fig_size = px.histogram(
                df_events,
                x="packet_size",
                nbins=20,
                title="Packet Size Distribution (Bytes)",
                labels={"packet_size": "Frame Size (Bytes)"},
                template="plotly_dark",
                color_discrete_sequence=["#0284c7"],
            )
            fig_size.update_layout(
                paper_bgcolor="#111827",
                plot_bgcolor="#111827",
                margin=dict(l=20, r=20, t=35, b=20),
                height=220,
            )
            st.plotly_chart(fig_size, width="stretch")

        with col_ps2:
            if not is_live_mode:
                # 6. Simulation Ground Truth Distribution
                sec_counts = df_events["is_malicious"].value_counts().reset_index()
                sec_counts.columns = ["Classification", "Count"]
                sec_counts["Classification"] = sec_counts["Classification"].map({False: "Normal Traffic", True: "Suspicious Traffic"})

                fig_sec = px.pie(
                    sec_counts,
                    names="Classification",
                    values="Count",
                    hole=0.55,
                    title="Ground Truth Traffic Distribution",
                    template="plotly_dark",
                    color="Classification",
                    color_discrete_map={"Normal Traffic": "#10b981", "Suspicious Traffic": "#ef4444"},
                )
                fig_sec.update_layout(
                    paper_bgcolor="#111827",
                    plot_bgcolor="#111827",
                    margin=dict(l=20, r=20, t=35, b=20),
                    height=220,
                )
                st.plotly_chart(fig_sec, width="stretch")
            else:
                # In live mode, show Transport Protocol breakdown (TCP vs UDP vs ICMP vs ARP)
                proto_bar = df_events["protocol"].value_counts().reset_index()
                proto_bar.columns = ["Protocol", "Packets"]
                fig_live_p = px.bar(
                    proto_bar,
                    x="Protocol",
                    y="Packets",
                    title="Observed Layer 3/4 Protocol Counts",
                    template="plotly_dark",
                    color="Protocol",
                    color_discrete_map={"TCP": "#0284c7", "UDP": "#10b981", "ICMP": "#f59e0b", "ARP": "#8b5cf6", "IP-OTHER": "#94a3b8"},
                )
                fig_live_p.update_layout(
                    paper_bgcolor="#111827",
                    plot_bgcolor="#111827",
                    margin=dict(l=20, r=20, t=35, b=20),
                    height=220,
                    showlegend=False,
                )
                st.plotly_chart(fig_live_p, width="stretch")

        # Packet Inspection Stream Table with Filtering
        st.markdown(f"##### Recent {'Captured Packet Metadata' if is_live_mode else 'Simulated Event Log'}")
        
        col_tbl1, col_tbl2, col_tbl3 = st.columns([1, 1, 1])
        with col_tbl1:
            table_proto_filter = st.selectbox("Filter by Protocol", ["ALL"] + sorted(list(df_events["protocol"].unique())))
        with col_tbl2:
            table_ip_filter = st.text_input("Search Source IP", value="")
        with col_tbl3:
            table_limit = st.selectbox("Rows to Display", [15, 30, 50, 100], index=0)

        filtered_df = df_events.copy()
        if table_proto_filter != "ALL":
            filtered_df = filtered_df[filtered_df["protocol"] == table_proto_filter]
        if table_ip_filter.strip():
            filtered_df = filtered_df[filtered_df["src_ip"].str.contains(table_ip_filter.strip(), na=False)]

        display_df = filtered_df[[
            "event_id", "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "packet_size", "tcp_flags", "data_source", "scenario"
        ]].tail(int(table_limit)).iloc[::-1]

        st.dataframe(display_df, width="stretch", height=230)

    else:
        # ---------------------------------------------------------
        # Informative Standby State (No packets in memory buffer yet)
        # ---------------------------------------------------------
        target_if_display = (selected_if_name or "System Default") if is_live_mode else sim_engine.current_scenario.value
        ingest_mode_desc = "Promiscuous Layer 2/3 Sniffing (Scapy)" if is_live_mode else "Deterministic Workload Generator (7 Scenarios)"

        st.markdown(
            f"""
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-top: 4px; margin-bottom: 14px;">
                <div style="background-color: #111827; border: 1px solid #1e293b; border-radius: 6px; padding: 12px 14px;">
                    <div style="color: #38bdf8; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 4px;">1. Ingestion Layer</div>
                    <div style="color: #f8fafc; font-size: 0.92rem; font-weight: 600; margin-bottom: 6px;">{'Live Adapter Sniffer' if is_live_mode else 'Synthetic Generator'}</div>
                    <div style="color: #94a3b8; font-size: 0.78rem; line-height: 1.5;">
                        <div>Target: <span style="color: #e2e8f0; font-family: monospace;">{target_if_display}</span></div>
                        <div>Type: <span style="color: #e2e8f0;">{ingest_mode_desc}</span></div>
                        <div>Queue: <span style="color: #38bdf8;">0 / 10,000 pkts (Thread-safe FIFO)</span></div>
                    </div>
                </div>
                <div style="background-color: #111827; border: 1px solid #1e293b; border-radius: 6px; padding: 12px 14px;">
                    <div style="color: #38bdf8; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 4px;">2. Header Extraction</div>
                    <div style="color: #f8fafc; font-size: 0.92rem; font-weight: 600; margin-bottom: 6px;">Zero-Payload Privacy Shield</div>
                    <div style="color: #94a3b8; font-size: 0.78rem; line-height: 1.5;">
                        <div>Layers: <span style="color: #e2e8f0;">IP, TCP, UDP, ICMP, ARP</span></div>
                        <div>Metadata: <span style="color: #e2e8f0;">IPs, Ports, Flags, Size, Ts</span></div>
                        <div>Privacy: <span style="color: #34d399;">Payload bodies discarded</span></div>
                    </div>
                </div>
                <div style="background-color: #111827; border: 1px solid #1e293b; border-radius: 6px; padding: 12px 14px;">
                    <div style="color: #38bdf8; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 4px;">3. Threat Detection</div>
                    <div style="color: #f8fafc; font-size: 0.92rem; font-weight: 600; margin-bottom: 6px;">{active_detection_method.value}</div>
                    <div style="color: #94a3b8; font-size: 0.78rem; line-height: 1.5;">
                        <div>Rules: <span style="color: #e2e8f0;">PortScan, SYNFlood, HighRate, ICMP</span></div>
                        <div>Anomaly: <span style="color: #e2e8f0;">EWMA Dynamic Model (Z ≥ {current_pipeline.config.adaptive.z_score_threshold})</span></div>
                        <div>Alerts: <span style="color: #34d399;">0 Active Threats Emitted</span></div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if is_live_mode:
            st.info(
                "📡 **Live Packet Sniffing Standby:** Select your network adapter from the sidebar dropdown, "
                "optionally configure a BPF capture filter, and click **▶️ Start Sniffing** to initiate real-time packet ingestion. "
                "Packets traversing the selected network interface will immediately generate rate telemetry, protocol breakdowns, and forensic alerts."
            )
        else:
            st.info(
                "🧪 **Simulation Pipeline Standby:** Select a traffic scenario (e.g. *Port scan activity* or *Repeated TCP SYN attempts*) "
                "and click **▶️ Start / Run** or **⏩ Step +10** in the sidebar to stream synthetic events into the live detection pipeline."
            )

        # Wireframe Placeholder Panels (Awaiting Ingestion Stream)
        col_wf1, col_wf2 = st.columns([2, 1])
        with col_wf1:
            st.markdown(
                """
                <div style="background-color: #111827; border: 1px dashed #1e293b; border-radius: 6px; height: 210px; display: flex; flex-direction: column; align-items: center; justify-content: center; color: #64748b; text-align: center; padding: 20px;">
                    <div style="font-size: 1.3rem; margin-bottom: 6px;">📈</div>
                    <div style="color: #94a3b8; font-size: 0.85rem; font-weight: 600; margin-bottom: 2px;">Ingestion Rate (Packets / Second)</div>
                    <div style="font-size: 0.75rem;">Awaiting incoming packet timestamps to plot real-time throughput.</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with col_wf2:
            st.markdown(
                """
                <div style="background-color: #111827; border: 1px dashed #1e293b; border-radius: 6px; height: 210px; display: flex; flex-direction: column; align-items: center; justify-content: center; color: #64748b; text-align: center; padding: 20px;">
                    <div style="font-size: 1.3rem; margin-bottom: 6px;">🍩</div>
                    <div style="color: #94a3b8; font-size: 0.85rem; font-weight: 600; margin-bottom: 2px;">Protocol Breakdown</div>
                    <div style="font-size: 0.75rem;">Awaiting frames to calculate TCP, UDP, ICMP, and ARP shares.</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

        col_wf3, col_wf4 = st.columns([1, 1])
        with col_wf3:
            st.markdown(
                """
                <div style="background-color: #111827; border: 1px dashed #1e293b; border-radius: 6px; height: 180px; display: flex; flex-direction: column; align-items: center; justify-content: center; color: #64748b; text-align: center; padding: 20px;">
                    <div style="font-size: 1.3rem; margin-bottom: 6px;">🌐</div>
                    <div style="color: #94a3b8; font-size: 0.85rem; font-weight: 600; margin-bottom: 2px;">Top Active Source Hosts</div>
                    <div style="font-size: 0.75rem;">Awaiting IP packets to rank transmitting client addresses.</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with col_wf4:
            st.markdown(
                """
                <div style="background-color: #111827; border: 1px dashed #1e293b; border-radius: 6px; height: 180px; display: flex; flex-direction: column; align-items: center; justify-content: center; color: #64748b; text-align: center; padding: 20px;">
                    <div style="font-size: 1.3rem; margin-bottom: 6px;">🎯</div>
                    <div style="color: #94a3b8; font-size: 0.85rem; font-weight: 600; margin-bottom: 2px;">Target Services & Destination Ports</div>
                    <div style="font-size: 0.75rem;">Awaiting transport headers to identify destination service ports.</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
        st.markdown(f"##### Recent {'Captured Packet Metadata' if is_live_mode else 'Simulated Event Log'}")
        empty_table_df = pd.DataFrame(columns=[
            "Timestamp", "Source IP", "Destination IP", "Protocol", "Src Port",
            "Dst Port", "Packet Size (B)", "TCP Flags", "Data Source", "Scenario"
        ])
        st.dataframe(empty_table_df, width="stretch", height=120)
        st.caption("ℹ️ Packet buffer empty. Start capture or step simulation in sidebar to ingest network traffic.")


# ---------------------------------------------------------
# TAB 2: Explainable Alert Centre
# ---------------------------------------------------------
with tab_alerts:
    st.markdown(f"#### Security Alert Management & Forensic Explanations ({'Live Traffic' if is_live_mode else 'Simulation'})")
    st.caption("Transparent intrusion alerts with rigorous 7-question forensic explainability for academic review.")

    col_flt1, col_flt2, col_flt3 = st.columns([1, 1, 1])
    with col_flt1:
        sev_filter = st.selectbox("Filter by Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    with col_flt2:
        meth_filter = st.selectbox("Filter by Detector", ["ALL", DetectionMethod.COMBINED_EXPLAINABLE.value, DetectionMethod.RULE_BASED.value, DetectionMethod.ADAPTIVE_BASELINE.value])
    with col_flt3:
        alert_limit = st.selectbox("Alerts to Display", [25, 50, 100, 200], index=1)

    alerts_list = active_pipeline.get_recent_alerts(limit=alert_limit, severity_filter=sev_filter, method_filter=meth_filter)

    if alerts_list:
        df_alerts = export_alerts_to_dataframe(alerts_list)

        table_view = df_alerts[["alert_id", "data_source", "src_ip", "method", "severity", "risk_score", "attack_type", "rule_or_condition", "status"]].iloc[::-1]
        st.dataframe(table_view, width="stretch", height=240)

        st.markdown("---")
        st.markdown("##### 🔍 Forensic Alert Drilldown & 7-Question Explainability Report")
        st.caption("Select an alert below to review the observed evidence, learned baselines, detection thresholds, and risk scoring rationale.")

        alert_ids = [a.alert_id for a in alerts_list[::-1]]
        selected_alert_id = st.selectbox("Select Alert for Forensic Inspection", alert_ids)

        selected_alert = next((a for a in alerts_list if a.alert_id == selected_alert_id), None)
        if selected_alert and selected_alert.explanation:
            exp = selected_alert.explanation

            c_exp1, c_exp2, c_exp3, c_exp4 = st.columns(4)
            with c_exp1:
                st.markdown(f"**Alert ID:** `{selected_alert.alert_id}`")
                st.markdown(f"**Source Entity:** `{selected_alert.src_ip}`")
            with c_exp2:
                st.markdown(f"**Detector Source:** `{selected_alert.method.value if hasattr(selected_alert.method, 'value') else selected_alert.method}`")
                st.markdown(f"**Threat Category:** `{selected_alert.attack_type}`")
            with c_exp3:
                sev_val = selected_alert.severity.value if hasattr(selected_alert.severity, "value") else selected_alert.severity
                st.markdown(f"**Severity:** <span class='badge-{sev_val.lower()}'>{sev_val}</span>", unsafe_allow_html=True)
                st.markdown(f"**Risk Score:** `{selected_alert.risk_score} / 100.0`")
            with c_exp4:
                z_display = f"{exp.z_score:.2f} σ" if exp.z_score is not None else "N/A (Heuristic Rule)"
                st.markdown(f"**Statistical Z-Score:** `{z_display}`")
                st.markdown(f"**Data Source:** `{getattr(selected_alert, 'data_source', 'Live Capture')}`")

            # Comparative Evidence Cards
            col_sub1, col_sub2 = st.columns(2)
            with col_sub1:
                st.markdown(
                    f"""
                    <div style="background-color: #111827; padding: 12px; border-radius: 6px; border: 1px solid #1e293b;">
                        <span style="color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; font-weight: 600;">Observed Traffic Metric</span>
                        <div style="font-size: 1.15rem; color: #f87171; font-weight: 700; margin-top: 4px;">{exp.observed_value}</div>
                        <div style="font-size: 0.75rem; color: #64748b; margin-top: 2px;">Feature: {exp.feature_name}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            with col_sub2:
                st.markdown(
                    f"""
                    <div style="background-color: #111827; padding: 12px; border-radius: 6px; border: 1px solid #1e293b;">
                        <span style="color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; font-weight: 600;">Expected Baseline / Configured Threshold</span>
                        <div style="font-size: 1.15rem; color: #34d399; font-weight: 700; margin-top: 4px;">{exp.threshold_or_baseline}</div>
                        <div style="font-size: 0.75rem; color: #64748b; margin-top: 2px;">Condition: {exp.rule_or_condition}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            # 7 Core Faculty Questions
            st.markdown("###### Structured Forensic Explanation")

            st.markdown(
                f"""
                <div class="explain-card">
                    <div class="explain-q">1. What happened?</div>
                    <div class="explain-a">{exp.what_happened}</div>
                </div>
                <div class="explain-card">
                    <div class="explain-q">2. What evidence supports the alert?</div>
                    <div class="explain-a">{exp.evidence_summary}</div>
                </div>
                <div class="explain-card">
                    <div class="explain-q">3. What was expected?</div>
                    <div class="explain-a">{exp.expected_baseline}</div>
                </div>
                <div class="explain-card">
                    <div class="explain-q">4. Why was the alert triggered?</div>
                    <div class="explain-a">{exp.trigger_comparison}</div>
                </div>
                <div class="explain-card">
                    <div class="explain-q">5. Which detector triggered it?</div>
                    <div class="explain-a">{exp.detector_source}</div>
                </div>
                <div class="explain-card">
                    <div class="explain-q">6. How was severity determined?</div>
                    <div class="explain-a">{exp.severity_rationale}</div>
                </div>
                <div class="explain-card">
                    <div class="explain-q">7. What are the operational limitations?</div>
                    <div class="explain-a">{exp.operational_limitations}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            with st.expander("🔍 Raw Forensic Alert Metadata (JSON)"):
                st.json(selected_alert.to_dict())

    else:
        st.markdown(
            f"""
            <div style="background-color: #111827; border: 1px solid #1e293b; border-radius: 6px; padding: 16px 18px; margin-top: 10px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <div>
                        <span style="color: #34d399; font-weight: 700; font-size: 0.95rem;">● Security Ledger Clean — 0 Alerts Recorded</span>
                        <div style="color: #94a3b8; font-size: 0.8rem; margin-top: 2px;">Detection pipeline active. System operating within normal security parameters.</div>
                    </div>
                    <span class="mode-badge-{'live' if is_live_mode else 'sim'}">{active_detection_method.value}</span>
                </div>
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; margin-top: 12px; font-size: 0.8rem; color: #94a3b8;">
                    <div style="background-color: #0b0f19; padding: 10px 12px; border-radius: 4px; border: 1px solid #1e293b;">
                        <span style="color: #38bdf8; font-weight: 600; text-transform: uppercase; font-size: 0.72rem;">Active Signature Rules</span>
                        <div style="margin-top: 4px; line-height: 1.5; color: #cbd5e1;">
                            • Port Scan: ≥ {current_pipeline.config.rules.port_scan_threshold} ports / 5.0s<br>
                            • SYN Flood: ≥ {current_pipeline.config.rules.syn_flood_threshold} SYNs / 3.0s<br>
                            • High Rate: ≥ {current_pipeline.config.rules.high_rate_threshold} pkts / 2.0s<br>
                            • ICMP Spike: ≥ {current_pipeline.config.rules.icmp_spike_threshold} pkts / 3.0s
                        </div>
                    </div>
                    <div style="background-color: #0b0f19; padding: 10px 12px; border-radius: 4px; border: 1px solid #1e293b;">
                        <span style="color: #38bdf8; font-weight: 600; text-transform: uppercase; font-size: 0.72rem;">Statistical Baseline Engine</span>
                        <div style="margin-top: 4px; line-height: 1.5; color: #cbd5e1;">
                            • EWMA Smoothing Alpha: {current_pipeline.config.adaptive.ewma_alpha}<br>
                            • Anomaly Z-Score Threshold: ≥ {current_pipeline.config.adaptive.z_score_threshold} σ<br>
                            • Baseline Warm-Up: {base_stats['sample_count']} / {base_stats['warmup_target']} windows<br>
                            • Contamination Quarantine: Active
                        </div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


# ---------------------------------------------------------
# TAB 3: Adaptive Baseline Anomaly Engine
# ---------------------------------------------------------
with tab_baseline:
    st.markdown(f"#### Adaptive Statistical Baseline Model (EWMA & Z-Score) — {'Live Pipeline' if is_live_mode else 'Simulation Pipeline'}")
    st.markdown(
        """
        The adaptive detector establishes a dynamic mathematical model of normal network traffic using
        **Exponentially Weighted Moving Averages (EWMA)** and standard deviation estimation.
        Incoming traffic observations are evaluated against the learned baseline using **Z-Score deviation tests**.
        """
    )

    b_stats = active_pipeline.adaptive_detector.get_baseline_status()

    col_b1, col_b2, col_b3, col_b4 = st.columns(4)
    with col_b1:
        st.metric("Baseline Mean Rate", f"{b_stats['mean_rate']:.2f} pkts/s", delta=None)
    with col_b2:
        st.metric("Baseline Std Dev (σ)", f"{b_stats['std_rate']:.2f}", delta=None)
    with col_b3:
        st.metric("Current Observed Rate", f"{b_stats['last_observed_rate']:.2f} pkts/s", delta=None)
    with col_b4:
        st.metric("Current Z-Score", f"{b_stats['last_z_score']:.2f} σ", delta=f"Threshold: {b_stats['z_threshold']} σ")

    st.markdown("---")

    col_g_base, col_g_bar = st.columns([1, 1])

    with col_g_base:
        st.markdown("##### Warm-up & Baseline Learning Status")
        progress = b_stats["warmup_progress_pct"] / 100.0
        st.progress(progress, text=f"Warm-up Progress: {b_stats['sample_count']} / {b_stats['warmup_target']} windows ({b_stats['warmup_progress_pct']}%)")

        if b_stats["is_warmed_up"]:
            st.success("✅ **Baseline Warmed Up:** Statistical anomaly detection is fully operational.")
        else:
            st.warning("⚠️ **Baseline Learning:** System is calibrating on normal traffic. Anomaly alerts are muted during warm-up to prevent early false positives.")

        st.markdown("##### Contamination Prevention Policy")
        st.markdown(
            """
            - **Anomalous Window Quarantine:** Any window triggering a statistical anomaly (Z ≥ Threshold) is barred from updating the baseline mean/variance.
            - **Ground-Truth Attack Filtering (Simulation):** Known adversarial packet streams are isolated from baseline calibration.
            - **Zero-Variance Floor:** A variance safety floor (`min_std_floor = 1.0`) prevents division-by-zero errors when traffic volume is steady.
            """
        )

    with col_g_bar:
        st.markdown("##### Observed Rate vs Dynamic Baseline Bounds")
        upper_threshold = b_stats["mean_rate"] + b_stats["z_threshold"] * b_stats["std_rate"]
        bar_df = pd.DataFrame([
            {"Metric": "Learned Mean", "Value": b_stats["mean_rate"], "Type": "Baseline"},
            {"Metric": "Anomaly Threshold (Mean + Z*σ)", "Value": upper_threshold, "Type": "Threshold"},
            {"Metric": "Last Observed Rate", "Value": b_stats["last_observed_rate"], "Type": "Current Observation"},
        ])
        fig_bar = px.bar(
            bar_df,
            x="Metric",
            y="Value",
            color="Type",
            template="plotly_dark",
            color_discrete_map={"Baseline": "#0284c7", "Threshold": "#f59e0b", "Current Observation": "#ef4444" if b_stats["last_observed_rate"] > upper_threshold else "#10b981"},
        )
        fig_bar.update_layout(
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            margin=dict(l=20, r=20, t=20, b=20),
            height=280,
            showlegend=False,
        )
        st.plotly_chart(fig_bar, width="stretch")


# ---------------------------------------------------------
# TAB 4: Detector Benchmark & Scientific Evaluation
# ---------------------------------------------------------
with tab_eval:
    st.markdown("#### Scientific Evaluation & Detector Comparison")
    st.caption("Executes controlled, reproducible experiments with ground-truth validation across Rule-Based, Adaptive Baseline, and Combined detectors.")

    col_e1, col_e2, col_e3, col_e4 = st.columns(4)
    with col_e1:
        bench_scenario_val = st.selectbox(
            "Benchmark Scenario",
            [s.value for s in ScenarioType if s != ScenarioType.NORMAL],
            index=0,
        )
        bench_scenario = next(s for s in ScenarioType if s.value == bench_scenario_val)
    with col_e2:
        bench_events = st.number_input("Test Event Count", min_value=50, max_value=1000, value=200, step=50)
    with col_e3:
        bench_warmup = st.number_input("Warm-up Benign Events", min_value=10, max_value=100, value=40, step=10)
    with col_e4:
        bench_seed = st.number_input("Random Seed", min_value=1, max_value=999999, value=42, step=1)

    if st.button("🚀 Run Controlled Benchmark Experiment", type="primary"):
        with st.spinner("Executing reproducible multi-detector benchmark..."):
            runner = ExperimentRunner(sim_pipeline.config)
            st.session_state.last_benchmark = runner.run_benchmark(
                scenario=bench_scenario,
                total_events=int(bench_events),
                warmup_events=int(bench_warmup),
                random_seed=int(bench_seed),
            )
        st.success("Benchmark completed successfully!")

    if st.session_state.last_benchmark is not None:
        res = st.session_state.last_benchmark
        st.markdown(f"##### Results for Scenario: `{res.scenario_name}` (Seed: {res.random_seed})")
        st.caption(f"Evaluated on {res.total_events} test events ({res.malicious_count} malicious ground-truth, {res.benign_count} benign).")

        summary_rows = res.to_summary_table()
        df_summary = pd.DataFrame(summary_rows)

        display_metrics_df = df_summary[[
            "detector", "precision", "recall", "f1_score", "fpr", "accuracy",
            "tp", "fp", "tn", "fn", "detection_latency_ms", "first_detection_delay_events"
        ]].copy()
        display_metrics_df.columns = [
            "Detector", "Precision", "Recall", "F1 Score", "FPR", "Accuracy",
            "TP", "FP", "TN", "FN", "Mean Latency (ms)", "First Alert Delay (pkts)"
        ]
        st.dataframe(display_metrics_df, width="stretch")

        col_chart, col_cm = st.columns([3, 2])

        with col_chart:
            melted = pd.melt(
                df_summary,
                id_vars=["detector"],
                value_vars=["precision", "recall", "f1_score"],
                var_name="Metric",
                value_name="Score",
            )
            melted["Metric"] = melted["Metric"].str.upper()

            fig_comp = px.bar(
                melted,
                x="detector",
                y="Score",
                color="Metric",
                barmode="group",
                title="Precision, Recall, and F1 Score Comparison",
                template="plotly_dark",
                range_y=[0.0, 1.05],
                color_discrete_sequence=["#0284c7", "#10b981", "#8b5cf6"],
            )
            fig_comp.update_layout(
                paper_bgcolor="#111827",
                plot_bgcolor="#111827",
                margin=dict(l=20, r=20, t=35, b=20),
                height=300,
            )
            st.plotly_chart(fig_comp, width="stretch")

        with col_cm:
            st.markdown("##### Confusion Matrices")
            for det_name, report in res.reports.items():
                cm = report.confusion_matrix
                st.markdown(f"**{det_name}**")
                cm_data = [
                    ["True Malicious (Actual +)", f"TP: {cm.tp}", f"FN: {cm.fn}"],
                    ["True Benign (Actual -)", f"FP: {cm.fp}", f"TN: {cm.tn}"],
                ]
                cm_df = pd.DataFrame(cm_data, columns=["Ground Truth", "Predicted Malicious", "Predicted Benign"])
                st.dataframe(cm_df, width="stretch", hide_index=True)

        csv_exp = export_experiment_to_csv(summary_rows)
        st.download_button(
            label="📥 Download Benchmark Results (CSV)",
            data=csv_exp,
            file_name=f"nids_benchmark_{res.scenario_name.lower().replace(' ', '_')}_seed{res.random_seed}.csv",
            mime="text/csv",
        )
    else:
        st.info("Configure parameters and click **🚀 Run Controlled Benchmark Experiment** to generate scientific comparisons.")


# ---------------------------------------------------------
# TAB 5: Export & Historical Investigation
# ---------------------------------------------------------
with tab_export:
    st.markdown(f"#### Data Export & Offline SOC Investigation ({'Live Capture Data' if is_live_mode else 'Simulation Data'})")
    st.markdown("Download captured packet traffic logs, security alerts, and evaluation results for external reporting or auditing.")

    col_exp1, col_exp2 = st.columns(2)

    with col_exp1:
        st.markdown(f"##### 📁 Export {'Captured Packets' if is_live_mode else 'Packet Events'}")
        all_events = recent_events_list
        st.write(f"Total events in active buffer: **{len(all_events)}** ({'Live Capture' if is_live_mode else 'Simulation'})")
        if all_events:
            csv_events = export_events_to_csv(all_events)
            st.download_button(
                label=f"📥 Download {'Captured' if is_live_mode else 'Simulated'} Packets (CSV)",
                data=csv_events,
                file_name=f"{'live_captured_packets' if is_live_mode else 'simulated_packet_events'}_{int(time.time())}.csv",
                mime="text/csv",
                width="stretch",
            )
        else:
            st.caption("No events in buffer to export.")

    with col_exp2:
        st.markdown("##### 🚨 Export Security Alerts")
        all_alerts = list(active_pipeline.alerts_history)
        st.write(f"Total alerts in active memory: **{len(all_alerts)}**")
        if all_alerts:
            csv_alerts = export_alerts_to_csv(all_alerts)
            st.download_button(
                label="📥 Download Alerts Log (CSV)",
                data=csv_alerts,
                file_name=f"{'live_security_alerts' if is_live_mode else 'simulated_security_alerts'}_{int(time.time())}.csv",
                mime="text/csv",
                width="stretch",
            )
        else:
            st.caption("No alerts recorded yet.")


# ---------------------------------------------------------
# Continuous Loop for Active Streams
# ---------------------------------------------------------
if is_live_mode and live_engine.state == CaptureState.CAPTURING:
    time.sleep(0.5)
    st.rerun()
elif (not is_live_mode) and st.session_state.auto_run and not sim_engine.is_paused:
    time.sleep(0.5)
    st.rerun()
