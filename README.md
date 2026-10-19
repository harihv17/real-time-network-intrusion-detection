# Design and Implementation of a Real-Time Network Intrusion Detection System Using Packet Traffic Analysis

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-1.40+-red.svg)
![Plotly](https://img.shields.io/badge/Plotly-5.20+-purple.svg)
![Tests](https://img.shields.io/badge/Pytest-46%20Passed-brightgreen.svg)
![Capture](https://img.shields.io/badge/Capture-Live%20Npcap%20%2B%20Simulation-orange.svg)
![Cloud Ready](https://img.shields.io/badge/Streamlit%20Cloud-Deployment%20Ready-success.svg)

---

## 1. Project Objective & Academic Scope

This project implements an explainable, dual-mode **Real-Time Network Intrusion Detection System (NIDS)** designed for university defense demonstrations and security operations center (SOC) analysis. It provides:

1. **Deterministic Real-Time Traffic Simulator (Public Demo Ready):** Full continuous traffic streaming pipeline generating 7 realistic network profiles (Benign Web, Port Scanning, SYN Flood, UDP Spike, ICMP Flood, High-Rate Volumetric Burst, Mixed Multi-Vector). Runs seamlessly on **Streamlit Community Cloud** without requiring visitors to install Python, Scapy, Npcap, or Antigravity.
2. **Genuine Live Network Packet Capture (Local Mode):** Hardware-level promiscuous packet sniffing on real network adapters via Scapy & Npcap on Windows (or libpcap on Linux) with thread-safe queues, BPF filter support, pause/resume, and zero payload retention.
3. **Multi-Heuristic Signature Engine:** Sliding time-window analysis of known attack signatures (Port Scans, TCP SYN Floods, ICMP Ping Storms, High-Rate Volumetric Floods).
4. **Adaptive Statistical Baseline Anomaly Engine:** Self-calibrating Exponentially Weighted Moving Average (EWMA) and dynamic Z-Score anomaly detection with baseline contamination prevention.
5. **Combined Explainable Correlator:** Transparent fusion engine scoring threat risk and generating comprehensive **7-question forensic reports** for faculty review.
6. **Reproducible Scientific Benchmark Suite:** Controlled evaluation experiments calculating Ground-Truth Confusion Matrices, Precision, Recall, F1 Score, False Positive Rate (FPR), and Detection Latency.
7. **Refined Dark SOC Dashboard:** Professional cybersecurity operations center UI tailored for 1366x768 and 1080p displays without generic templates or unreadable widgets.

---

## 2. System Architecture

The project features a decoupled, modular architecture maintaining complete data isolation between Live Capture and Simulation pipelines:

```
cn/
├── .streamlit/
│   └── config.toml             # Dark SOC theme configuration (charcoal/navy background, zero top-bar white strips)
├── app.py                      # Primary Streamlit Entry Point (Telemetry, Alert Centre, Baseline, Benchmark, Export)
├── requirements.txt            # Cloud-safe dependencies (Streamlit, Plotly, Pandas, NumPy, Pytest, Scapy)
├── .gitignore                  # Excludes .venv, caches, local captures, and secrets; tracks config.toml
├── README.md                   # Comprehensive documentation, deployment guide, and presentation protocol
│
├── capture/                    # Genuine Live Packet Sniffing Backend
│   ├── __init__.py
│   ├── engine.py               # LiveCaptureEngine (worker thread, queue management, BPF filter, pause/resume)
│   ├── parser.py               # Header metadata extraction (IPs, ports, flags, size) with zero payload retention
│   └── interfaces.py           # Cloud-safe interface discovery, Npcap checks, and container environment detection
│
├── simulator/                  # Real-Time Network Traffic Generator & Engine
│   ├── models.py               # PacketEvent schema, Protocol enum, ScenarioType
│   ├── generator.py            # Synthetic traffic generator for 7 network scenarios
│   └── engine.py               # Stateful SimulationEngine (Run, Pause, Stop, Step, Reset, Rate control)
│
├── detection/                  # Detection Engines & Alert Orchestration
│   ├── models.py               # Alert schema, Severity tiers, DetectionMethod, 7-question Explanation model
│   ├── rule_based.py           # Time-aware rolling window heuristic rules with deduplication
│   ├── adaptive_baseline.py    # EWMA running mean/std, Z-score deviation tests, warm-up & protection
│   ├── combined_detector.py    # Dual-alert fusion, weighted risk scoring & 7-question explanations
│   └── engine.py               # DetectionPipeline managing buffers & alert distribution
│
├── analytics/                  # Performance Evaluation & Benchmarking
│   ├── metrics.py              # ConfusionMatrix (TP, FP, TN, FN), Precision, Recall, F1, FPR, Accuracy
│   └── experiment_runner.py    # Controlled experiment runner with reproducible random seeds
│
├── utils/                      # Shared Utilities & Configuration
│   ├── config.py               # Centralized parameters, thresholds, and scoring weights
│   ├── logger.py               # Structured logger
│   └── export.py               # CSV and DataFrame export utilities with data_source identification
│
├── tests/                      # Automated Test Suite (46 Passing Tests)
│   ├── test_cloud_and_separation.py # Cloud safety, mode isolation, engine lifecycle & deterministic attacks
│   ├── test_explainability_and_capture.py # 7-question forensic validation, pause/resume, CSV export
│   ├── test_live_capture.py    # Scapy parsing, capture engine lifecycle, and mode isolation
│   ├── test_models.py          # Schema validation and serialization
│   ├── test_simulator.py       # Deterministic seeds, scenario outputs, engine controls
│   ├── test_rule_detector.py   # Heuristic rules & alert deduplication
│   ├── test_adaptive_detector.py # Baseline warm-up, Z-score surge, zero-variance safety
│   ├── test_combined_detector.py # Risk scoring arithmetic and dual-detector fusion
│   ├── test_metrics.py         # Zero-division safety and metric calculations
│   ├── test_export.py          # CSV format validation
│   ├── test_pipeline_integration.py # End-to-end pipeline integration
│   └── test_full_demo.py       # Full faculty demonstration workflow test
│
└── data/                       # Offline sample datasets
    ├── generate_sample.py      # Standalone sample generator
    └── sample_traffic.csv      # Generated 500-event synthetic traffic dataset
```

---

## 3. Operational Modes: Honest Separation

The application enforces strict data isolation between two operating modes:

### A. 🧪 Simulation Mode (Public Demonstration)
- **Zero Local Prerequisites:** Works on any visitor laptop, tablet, or phone via modern web browsers without installing Python, Scapy, or Npcap.
- **Genuine Detection Pipeline:** Synthetic events are fed directly into the active `DetectionPipeline`. Alerts are **never prefabricated**; every alert is computed live by the heuristic and adaptive anomaly algorithms.
- **Continuous Reactive Streaming:** Streamlit auto-refresh loop (`time.sleep(0.5); st.rerun()`) advances the simulation batch by batch without requiring manual clicks.
- **Interactive Controls:** `▶️ Run`, `⏸️ Pause`, `⏹️ Stop`, `⏩ Step +10`, `⏩ Step +50`, and `🔄 Reset Simulator State`.
- **Reproducible Academic Evaluation:** Deterministic pseudo-random seeds allow faculty to verify detection thresholds repeatably across 7 distinct traffic profiles.

### B. 📡 Live Capture Mode (Local Hardware Use)
- **Genuine Packet Sniffing:** Listens to actual incoming and outgoing packets on the host machine's physical network adapters (Wi-Fi, Ethernet) using Scapy and Npcap.
- **Continuous Reactive Pipeline:** A dedicated background sniffing thread puts parsed packet metadata into a thread-safe queue. The Streamlit dashboard continuously drains the queue and evaluates events in real time.
- **BPF Filtering:** Supports optional Berkeley Packet Filter strings (e.g. `tcp or udp`, `port 80`, `ip`) passed directly to the capture worker.
- **Strict Isolation:** Live traffic metrics are explicitly labeled as **"Captured Packets"** and **"Observed Volume"**. Simulated events are never mixed into live-capture metrics or alert logs.
- **Graceful Cloud Handling:** When hosted on Streamlit Community Cloud (where raw packet capture is restricted by the container runtime), the app displays a clear advisory banner and disables live sniffing, guiding viewers to Simulation Mode.
- **Privacy & Safety:** Captures only on authorized interfaces. Processes header metadata only (IPs, ports, flags, packet size, timestamps). **No raw packet payloads are stored or transmitted.**

---

## 4. Explainable Detection Architecture (The 7 Core Questions)

Every security alert emitted by the system provides concrete answers to the 7 core academic forensic questions:

| Question | Forensic Purpose | Engine Source |
| :--- | :--- | :--- |
| **Q1: What happened?** | Plain-language description of observed network behavior | Primary alert rule or anomaly summary |
| **Q2: Evidence Summary** | Quantitative metrics observed in the packet window | Packet counts, port tallies, flags, packet sizes |
| **Q3: Expected Baseline** | Statistical baseline or normal baseline threshold | Sliding-window threshold or EWMA Mean ($\mu$) |
| **Q4: Trigger Comparison** | Explicit mathematical condition that triggered the alert | e.g., `Observed [9 ports] >= Threshold [5 ports]` |
| **Q5: Detector Source** | Specific algorithm or sub-module responsible | `RuleBasedDetector`, `AdaptiveBaselineDetector`, or `CombinedCorrelator` |
| **Q6: Severity Rationale** | Explanation of risk weighting and impact score | Severity classification mapping based on threat impact |
| **Q7: Operational Limitations** | Known edge cases and boundary conditions | Benign bursts, rapid browser tabs, or NAT aggregation caveats |

---

## 5. Deployment Guide: Streamlit Community Cloud & GitHub

Deploying this project to Streamlit Community Cloud allows faculty to access the live dashboard via a public URL from any laptop without installing dependencies.

### Step 1: Initialize Git Repository
In the project directory (`cn/`):
```powershell
git init
git add .
git commit -m "feat: complete deployment-ready real-time NIDS for Streamlit Cloud"
```

### Step 2: Push to GitHub
1. Create a new repository on your GitHub account (e.g. `nids-realtime-soc`).
2. Link your local repository and push:
```powershell
git remote add origin https://github.com/<your-username>/nids-realtime-soc.git
git branch -M main
git push -u origin main
```

### Step 3: Deploy on Streamlit Community Cloud
1. Navigate to [share.streamlit.io](https://share.streamlit.io/) and log in with your GitHub account.
2. Click **"New app"**.
3. Select your repository: `<your-username>/nids-realtime-soc`.
4. Set **Branch**: `main`.
5. Set **Main file path**: `app.py`.
6. (Optional) Under **Advanced settings**, ensure Python version is set to `3.11`.
7. Click **"Deploy!"**.
8. Within 1–2 minutes, your public URL (e.g. `https://<your-app-name>.streamlit.app`) is live and ready for faculty review.

---

## 6. Local Setup (for Genuine Live Packet Capture)

To run the application locally and capture real network traffic from your Wi-Fi or Ethernet adapter:

### 1. Prerequisites
- **Python 3.11+** installed and added to PATH.
- **Npcap (Windows):** Download and install from [npcap.com](https://npcap.com/#download).
  > **Crucial:** During installation, check the box: **"Install Npcap in WinPcap API-compatible Mode"**.
- *(Linux alternative)*: Install `libpcap`: `sudo apt-get install libpcap-dev` and run with `sudo` or grant `cap_net_raw` privileges.

### 2. Environment Setup
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 3. Launch Application
For live capture, open PowerShell as **Administrator** and run:
```powershell
streamlit run app.py
```
Open your browser to `http://localhost:8501`.

---

## 7. Faculty Demonstration Protocols

### Protocol A: Public Demonstration (Faculty on Any Laptop via URL)
This protocol allows a faculty member to evaluate the entire pipeline using only a web browser:

1. **Access Public URL:** Open the deployed Streamlit Cloud URL (or `http://localhost:8501`).
2. **Review Initial State:** Point out the mode badge **`🧪 SIMULATION MODE (PUBLIC DEMO)`**, the 6 overview KPI cards, and the standby architecture guide.
3. **Stream Normal Traffic:**
   - In the sidebar, verify scenario is set to **"Normal traffic"** and click **"▶️ Run"**.
   - Watch the packet counter, observed volume, and rate chart update automatically every 500ms.
   - Show that zero critical alerts are emitted during benign operation.
4. **Demonstrate Port-Scan Detection:**
   - Change the **Traffic Scenario** dropdown to **"Port scan activity"**.
   - Within seconds, watch the **High Alerts** count increment.
   - Navigate to the **"🚨 Explainable Alert Centre"** tab.
   - Click to expand the detected alert and walk through the **7-question forensic analysis** (What happened, Evidence, Expected baseline, Trigger condition, Severity rationale).
5. **Demonstrate Adaptive Baseline Anomaly Detection:**
   - Change the scenario to **"High packet-rate activity"**.
   - Navigate to the **"📈 Adaptive Baseline Anomaly Engine"** tab.
   - Show the dynamic baseline chart displaying the learned mean, anomaly threshold ($Mean + Z \times \sigma$), and observed spikes.
   - Explain how the contamination prevention policy prevents malicious spikes from biasing the learned baseline.
6. **Run Scientific Benchmark:**
   - Navigate to the **"🔬 Detector Benchmark"** tab and click **"🚀 Run Controlled Benchmark Experiment"**.
   - Review the confusion matrices, precision, recall, F1 scores, and false positive rates computed against ground truth.
7. **Export Forensic Data:**
   - Navigate to the **"💾 Export & Investigation"** tab and download the CSV packet log and alert records. Show that every exported record includes the `data_source` tag and all 7 explainability fields.

### Protocol B: Genuine Local Packet Sniffing (Authorized Machine)
1. Launch PowerShell as Administrator and run `streamlit run app.py`.
2. Select **"Live Capture"** in the sidebar.
3. Select your active Wi-Fi or Ethernet adapter from the discovered interface list.
4. (Optional) Enter a BPF filter such as `tcp port 80 or tcp port 443`.
5. Click **"▶️ Start Sniffing"**.
6. Open a web browser and visit several websites or run a ping command (`ping google.com`).
7. Watch real network packets arrive, get parsed for metadata, and flow through the live detection engine without storing any private payload data.

---

## 8. Automated Test Suite

Run the full pytest suite:
```powershell
.\.venv\Scripts\python -m pytest -q
```
**Results:** `46 passed in 1.46s` (covers live packet parsing, Scapy synthesis, EWMA adaptive baselines, rule deduplication, 7-question explainability models, cloud environment safety, mode isolation, and state transitions).

---

## 9. Academic Integrity & Ground-Truth Isolation

In this system, **ground-truth labels are strictly isolated from detection logic**:
- Detectors never inspect `event.is_malicious` or `event.attack_type` to make detection decisions. Detection is strictly computed from observed header metadata (IPs, ports, flags, packet size) and rolling time windows.
- In Live Capture mode, ground truth is inherently unknown; detection relies exclusively on mathematical features derived from packet headers and traffic time windows.
- In Simulation mode, ground-truth labels are only used post-detection by the `analytics` module to compute scientific performance metrics (Confusion Matrices, Precision, Recall, F1 Score).

---

## 10. Operational Limitations & Known Boundary Conditions

1. **Cloud Multi-Tenant Restrictions:** Streamlit Community Cloud runs in isolated container runtimes without access to visitor network interfaces or promiscuous raw socket capabilities (`CAP_NET_RAW`). Live sniffing is disabled on cloud hosts with an informative explanation, while Simulation Mode provides 100% detection capability.
2. **Encrypted Payload Privacy:** The system adheres to strict network privacy principles by inspecting layer 2/3/4 header metadata only (Ethernet, IPv4, TCP, UDP, ICMP). TLS/HTTPS application payloads are never decrypted.
3. **Local Network Segment Promiscuity:** On switched Ethernet LANs, adapters without port mirroring (SPAN) or TAP devices observe only broadcast, multicast, and packets directly addressed to/from the host.
4. **Statistical Volatility:** In dynamic network environments, legitimate high-volume operations (e.g. OS updates or batch file transfers) may trigger temporary statistical rate anomalies unless baseline parameters are properly tuned.
