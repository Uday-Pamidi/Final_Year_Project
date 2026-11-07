# Adaptive Intrusion Detection System (DICI Framework)

An enterprise-grade, adaptive cybersecurity framework integrating **Cyber Threat Intelligence (CTI)**, **Hybrid Machine Learning (XGBoost + Isolation Forest)**, **Statistical Concept Drift Detection**, **Online Incremental Learning**, and **SHAP-based Explainable AI (XAI)**.

Based on the research paper:
> **Y. -D. Lin, Y. -H. Lu, R. -H. Hwang, Y. -C. Lai, D. Sudyana and W. -B. Lee**, *"Evolving ML-Based Intrusion Detection: Cyber Threat Intelligence for Dynamic Model Updates,"* **IEEE Transactions on Machine Learning in Communications and Networking (TMLCN)**, vol. 3, pp. 605-622, 2025.  
> **DOI:** [10.1109/TMLCN.2025.3564587](https://doi.org/10.1109/TMLCN.2025.3564587)

Built with **FastAPI** (asynchronous backend) and **Jinja2** (modern dark-mode SOC web interface with Chart.js and Tailwind CSS).

---

## 🛡️ Architecture & Key Components

```
                                 [ Incoming Network Flow Telemetry ]
                                                  │
                                                  ▼
                         ┌─────────────────────────────────────────────────┐
                         │              Hybrid IDS Screening               │
                         │   • XGBoost: Supervised Multi-Class Classifier  │
                         │   • Isolation Forest: Anomaly / Outlier Screen  │
                         └────────────────────────┬────────────────────────┘
                                                  │
                     ┌────────────────────────────┴──────────────────────────┐
                     │ High Confidence (C ≥ τ) & Normal                      │ Low Confidence (C < τ) OR Anomaly
                     ▼                                                       ▼
            [ Standard Alert / Log ]                         ┌───────────────────────────────┐
                                                             │     IoC Extraction Engine     │
                                                             │ (IP, Port, Protocol, Entropy) │
                                                             └───────────────┬───────────────┘
                                                                             │
                                                                             ▼
                                                             ┌───────────────────────────────┐
                                                             │   Cyber Threat Intel (CTI)    │
                                                             │ (AlienVault OTX, AbuseIPDB)   │
                                                             └───────────────┬───────────────┘
                                                                             │
                                                                             ▼
                                                             ┌───────────────────────────────┐
                                                             │      CTI Transfer Model       │
                                                             │ Correlates Sighting & Threat  │
                                                             └───────────────┬───────────────┘
                                                                             │
                                                                             ▼ Validated Ground Truth (Score ≥ 0.75)
                                                             ┌───────────────────────────────┐
                                                             │ Validated Training Buffer     │
                                                             └───────────────┬───────────────┘
                                                                             │
                     ┌───────────────────────────────────────────────────────┴───────────────────────────────────────┐
                     │                                                                                               │
                     ▼                                                                                               ▼
┌──────────────────────────────────────────────┐                                            ┌──────────────────────────────────────────────┐
│       Concept Drift Detection Engine         │                                            │         Online / Incremental Learner         │
│ • Two-Sample Kolmogorov-Smirnov (KS) Test    │──[ Drift Detected OR Buffer ≥ 25 Samples ]─▶ • Incremental Booster Trees Update            │
│ • Population Stability Index (PSI)           │                                            • Historical Replay Memory Retention           │
│ • ADWIN Streaming Anomaly Monitor            │                                            • Model Version Evolution (v1.0 -> v1.1)       │
└──────────────────────────────────────────────┘                                            └──────────────────────┬───────────────────────┘
                                                                                                                   │
                                                                                                                   ▼
                                                                                            ┌──────────────────────────────────────────────┐
                                                                                            │          SHAP Explainable AI Studio          │
                                                                                            │ • TreeExplainer Local Feature Attributions   │
                                                                                            │ • Automated Plain-English Analyst Narratives │
                                                                                            └──────────────────────────────────────────────┘
```

---

## 🚀 Key Features

1. **Hybrid Machine Learning Engine**:
   - **XGBoost Classifier**: Multi-class supervised detection (`Benign`, `DoS_DDoS`, `PortScan`, `BruteForce`, `Botnet_C2`, `Infiltration_Web`).
   - **Isolation Forest**: Screens outlier network behaviors and zero-day candidates that evade static decision boundaries.
   - **Uncertainty Trigger**: When prediction confidence $C < 0.70$ or Isolation Forest flags an anomaly, automated IoC extraction is initiated.

2. **CTI Ingestion & The CTI Transfer Model**:
   - Extracts network Indicators of Compromise (Source/Destination IP, Port, Protocol, Flow Hash, Shannon Entropy).
   - Queries threat intelligence repositories (AlienVault OTX, AbuseIPDB, MISP signatures).
   - **CTI Transfer Model**: Correlates threat intelligence (threat score, confidence, malware family) with observed network telemetry:
     $$\text{Score} = 0.40 \cdot \text{CTI}_{\text{conf}} + 0.35 \cdot \left(\frac{\text{ThreatScore}}{100}\right) + 0.25 \cdot \text{TelemetryConsistency}$$
   - When $\text{Score} \ge 0.75$, transforms the flow into a **Validated Ground Truth Training Vector**.

3. **Statistical Concept Drift Detection**:
   - **Two-Sample Kolmogorov-Smirnov (KS-Test)** across all 16 standardized network flow features, comparing the active sliding window against baseline.
   - **Population Stability Index (PSI)** for bin-level shift detection.
   - **ADWIN (Adaptive Windowing)** tracking streaming error/anomaly rates using Hoeffding bounds.
   - Flags traffic state: `STABLE`, `WARNING`, or `DRIFT_DETECTED`.

4. **Online Incremental Learning & Model Retraining**:
   - Automatically triggered upon concept drift or when the validated CTI buffer reaches threshold ($\ge 25$ samples).
   - Updates XGBoost booster trees incrementally while sampling historical replay memory to prevent catastrophic forgetting.
   - Refits Isolation Forest to calibrate against legitimate network shifts.
   - Preserves complete audit registry ($v1.0 \to v1.1 \to v1.2$) tracking F1-score, accuracy, precision, and recall.

5. **Explainable AI (SHAP) Studio**:
   - `shap.TreeExplainer` calculates per-feature Shapley contributions for any flow instance.
   - Interactive waterfall and force-attribution charts: red features ($+$) increase attack probability; green features ($-$) decrease risk.
   - Generates natural-language cybersecurity analyst narratives explaining *why* a classification was made.

---

## 📋 Standard 16 Flow Feature Taxonomy

Features standard to CIC-IDS2017 / NSL-KDD benchmark telemetry:
- `flow_duration`: Total session duration (seconds)
- `total_fwd_packets`: Packets transmitted forward
- `total_bwd_packets`: Packets transmitted backward
- `total_fwd_bytes`: Payload bytes transmitted forward
- `total_bwd_bytes`: Payload bytes transmitted backward
- `packet_length_mean`: Mean packet size
- `packet_length_std`: Standard deviation of packet sizes
- `flow_bytes_s`: Bytes transmitted per second
- `flow_packets_s`: Packets transmitted per second
- `syn_flag_count`: Count of SYN flags
- `fin_flag_count`: Count of FIN flags
- `rst_flag_count`: Count of RST flags
- `psh_flag_count`: Count of PSH flags
- `ack_flag_count`: Count of ACK flags
- `down_up_ratio`: Download / Upload ratio
- `payload_entropy`: Shannon Entropy of payload ($0.0 - 8.0$)

---

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.10+ (Tested on Python 3.11)

### Quick Start

1. Clone or navigate into the repository:
   ```bash
   cd c:\Users\heman\Pictures\adaptive_ids
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Launch the Application:
   ```bash
   python run.py
   ```
   Or via Uvicorn directly:
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
   ```

4. Open your browser:
   - **Enterprise Home Page:** [http://127.0.0.1:8000](http://127.0.0.1:8000)
   - **Executive SOC Dashboard:** [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard)
   - **Live Flow Inspector:** [http://127.0.0.1:8000/live](http://127.0.0.1:8000/live)
   - **CTI Transfer Hub:** [http://127.0.0.1:8000/cti](http://127.0.0.1:8000/cti)
   - **Concept Drift & Retraining:** [http://127.0.0.1:8000/drift](http://127.0.0.1:8000/drift)
   - **SHAP XAI Studio:** [http://127.0.0.1:8000/explain](http://127.0.0.1:8000/explain)
   - **Interactive OpenAPI (Swagger):** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## 🧪 Automated Testing

Unit tests for the Hybrid IDS, CTI Transfer Model, Drift Detector, and FastAPI endpoints are located in `tests/`:

```bash
pytest tests/ -v
```

---

## 📜 Citation

```bibtex
@article{lin2025evolving,
  title={Evolving ML-Based Intrusion Detection: Cyber Threat Intelligence for Dynamic Model Updates},
  author={Lin, Ying-Dar and Lu, Yi-Hsin and Hwang, Ren-Hung and Lai, Yuan-Cheng and Sudyana, Didik and Lee, Wei-Bin},
  journal={IEEE Transactions on Machine Learning in Communications and Networking},
  volume={3},
  pages={605--622},
  year={2025},
  publisher={IEEE},
  doi={10.1109/TMLCN.2025.3564587}
}
```
