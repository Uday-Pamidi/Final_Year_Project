import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "ids_database.sqlite"
MODEL_DIR = DATA_DIR / "saved_models"

# Ensure data directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
MODEL_DIR.mkdir(parents=True, exist_ok=True)

# Feature Taxonomy (Standard 16 Flow Features based on CIC-IDS and Base Paper)
FLOW_FEATURES = [
    "flow_duration",        # Flow duration in seconds
    "total_fwd_packets",    # Number of packets in forward direction
    "total_bwd_packets",    # Number of packets in backward direction
    "total_fwd_bytes",      # Total payload bytes in forward direction
    "total_bwd_bytes",      # Total payload bytes in backward direction
    "packet_length_mean",   # Average packet length in bytes
    "packet_length_std",    # Standard deviation of packet length
    "flow_bytes_s",         # Flow transfer rate in bytes per second
    "flow_packets_s",       # Flow rate in packets per second
    "syn_flag_count",       # SYN flag count
    "fin_flag_count",       # FIN flag count
    "rst_flag_count",       # RST flag count
    "psh_flag_count",       # PSH flag count
    "ack_flag_count",       # ACK flag count
    "down_up_ratio",        # Download / Upload ratio
    "payload_entropy"       # Shannon entropy of payload [0.0 - 8.0]
]

# Attack Classes mapping
ATTACK_CLASSES = {
    0: "Benign",
    1: "DoS_DDoS",
    2: "PortScan",
    3: "BruteForce",
    4: "Botnet_C2",
    5: "Infiltration_Web"
}

ATTACK_CLASS_TO_ID = {v: k for k, v in ATTACK_CLASSES.items()}

# Colors and Badges for UI Display
CLASS_COLORS = {
    "Benign": "#10b981",          # Emerald
    "DoS_DDoS": "#ef4444",        # Rose / Red
    "PortScan": "#f59e0b",        # Amber
    "BruteForce": "#f97316",      # Orange
    "Botnet_C2": "#8b5cf6",        # Purple
    "Infiltration_Web": "#ec4899" # Pink
}

# Decision & Correlation Thresholds (Based on Base Paper DICI)
CONFIDENCE_THRESHOLD = 0.70       # tau: below this, XGBoost prediction is uncertain
ISOLATION_FOREST_CONTAMINATION = 0.08  # Expected outlier ratio
CTI_CORRELATION_THRESHOLD = 0.75  # Minimum score to validate a sighting as ground truth

# Concept Drift Parameters
DRIFT_WINDOW_SIZE = 100           # Sliding window size for drift detection
REFERENCE_BASELINE_SIZE = 400     # Reference baseline sample size
KS_ALPHA_THRESHOLD = 0.05         # p-value threshold for Kolmogorov-Smirnov test
PSI_WARNING_THRESHOLD = 0.10      # Population Stability Index warning
PSI_DRIFT_THRESHOLD = 0.25        # Population Stability Index drift detected

# Online Retraining Parameters
CTI_BUFFER_RETRAIN_TRIGGER = 25   # Retrain automatically when buffer reaches N validated flows
REPLAY_BUFFER_SIZE = 500          # Replay memory buffer to prevent catastrophic forgetting

# Application Info
APP_TITLE = "Adaptive CTI-IDS | Dynamic Model Update Framework"
APP_SUBTITLE = "Hybrid XGBoost + Isolation Forest IDS with CTI Transfer, Concept Drift Detection & SHAP XAI"
PAPER_CITATION = "Lin et al., 'Evolving ML-Based Intrusion Detection: Cyber Threat Intelligence for Dynamic Model Updates', IEEE TMLCN 2025."
