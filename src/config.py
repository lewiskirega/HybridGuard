"""
Central configuration for HybridGuard IDS.

Defines paths (data, models, logs), the 21 flow features used for training and
live ML detection, and thresholds for signature-based rules. Training uses
LIVE_FEATURE_COLUMNS only so the model matches what the sniffer produces.
"""

import os

# --- Paths (relative to project root) ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data", "cic_ids_2017")  # CIC-IDS2017 CSVs or generated sample
MODEL_DIR = os.path.join(BASE_DIR, "models")
LOG_DIR = os.path.join(BASE_DIR, "logs")
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest_model.pkl")


def get_scaler_path():
    """Path to the StandardScaler pickle saved alongside the model."""
    return MODEL_PATH.replace(".pkl", "_scaler.pkl")


# --- Feature alignment: same 21 features produced by PacketSniffer and used by AnomalyDetector ---
# Training must use this subset so the model matches live traffic (no train/serve mismatch).
LIVE_FEATURE_COLUMNS = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Mean",
    "Packet Length Std",
    "Min Packet Length",
    "Max Packet Length",
    "SYN Flag Count",
    "ACK Flag Count",
    "FIN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "URG Flag Count",
]

# --- Signature detection thresholds ---
SYN_FLOOD_WINDOW_SEC = 10
SYN_FLOOD_THRESHOLD = 100

PORT_SCAN_WINDOW_SEC = 30
PORT_SCAN_UNIQUE_PORTS_THRESHOLD = 20
PORT_SCAN_ATTEMPTS_THRESHOLD = 20

ICMP_LARGE_PACKET_BYTES = 1000
ICMP_HIGH_RATE_PPS = 100

# --- Sniffer ---
FLOW_TIMEOUT_SEC = 5
CLEANUP_STATS_EVERY_N_FLOWS = 100  # Call signature_detector.cleanup_old_stats() every N flows

# --- Model training (when using sample or CIC data) ---
TRAIN_CONTAMINATION = 0.1
TRAIN_N_ESTIMATORS = 100
TRAIN_RATIO = 0.7
