# Hybrid Intrusion Detection System (IDS)

A comprehensive network intrusion detection system that combines machine learning-based anomaly detection with signature-based rules for real-time threat detection.

## Features

### 🤖 Machine Learning Detection
- **Isolation Forest** algorithm for anomaly detection
- Uses pre-trained Isolation Forest model (no CSV data or training step)
- Real-time flow analysis and prediction
- Confidence scoring for anomalies

### 🔍 Signature-Based Detection
- **SYN Flood Detection**: Detects >100 SYN packets from single IP in 10 seconds
- **Port Scan Detection**: Identifies >20 unique ports from single IP in 30 seconds
- **SQL Injection Detection**: Pattern matching for common SQL injection attacks
- **XSS Detection**: Identifies Cross-Site Scripting attempts
- **ICMP Flood Detection**: Detects large ICMP packets and high-frequency ICMP traffic

### 📊 Real-Time Dashboard
- Live packet and alert statistics
- Color-coded severity levels (Critical, High, Medium, Low)
- Filterable alert table
- System event logging
- Export functionality for alerts

## Installation

### Prerequisites
- Python 3.11 or higher (see `pyproject.toml`)
- For **live packet capture**: administrator/root privileges (see [How to Run](#how-to-run))

### Install dependencies

From the project root, use a virtual environment (recommended):

```bash
# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows

# Option A: with uv (if installed)
uv sync

# Option B: with pip
pip install -e .
# or: pip install joblib matplotlib numpy pandas scapy scikit-learn
```

---

## How to Run

### 1. GUI (with or without live capture)

```bash
# Without root: app starts, model loads (if present), GUI opens. Click "Start Monitoring" will fail with a clear message.
python main.py

# With root (required for live packet capture):
sudo python main.py   # Linux/macOS
# Windows: open terminal as Administrator, then: python main.py
```

- **First run**: If no model exists in `models/`, the app runs with signature-based detection only; place a pre-trained model and scaler in `models/` to enable ML detection.
- **Start Monitoring**: Starts packet capture. If you see "Failed to start monitoring", you need root/sudo (see above).
- **Stop Monitoring / Clear Alerts / Export Alerts**: Use the GUI buttons.

### 2. Test detection without root (no packet capture)

You can verify that signature and ML detection work using simulated flows:

```bash
python tests/test_detection.py
```

This runs synthetic attacks (SQLi, XSS, SYN flood, port scan) through the same pipeline and prints whether each signature fired. No admin rights needed.

### 3. Test with a PCAP file (no root)

If you have a `.pcap` file (e.g. from Wireshark or a test lab):

```bash
python tests/replay_pcap.py path/to/file.pcap
```

Packets are replayed through the same flow aggregation and detection logic as live capture. Useful for demos and testing without raw sockets.

### Purpose of the `tests/` folder

The app runs without the `tests/` folder; the GUI and live monitoring use only `main.py` and `src/`. The `tests/` folder exists to **verify detection and run offline experiments** without root or live traffic:

| Script | Purpose |
|--------|--------|
| **`test_detection.py`** | Runs **simulated** attack flows (SQL injection, XSS, SYN flood, port scan) through the same signature and ML pipeline as live capture. Use it to confirm that detection logic works and that the model loads correctly—no admin rights or network needed. |
| **`replay_pcap.py`** | Feeds a **saved PCAP file** (e.g. from Wireshark or tcpdump) through the same flow aggregation and detection as live capture. Use it to test with real traffic offline or to demo the IDS without capturing live. |

So: the main app does not depend on `tests/`, but these scripts reuse the same detection code to check that it behaves correctly and to support PCAP-based testing.

---

## How to Test (full workflow)

### Option A: Nmap/tools directly (recommended)

**Preferred way to test.** No VM and no Docker required.

1. **Install and open GUI (no root)**  
   `python main.py` → model loads from `models/` if present → GUI opens.
2. **Verify detection logic (no root)**  
   `python tests/test_detection.py` → expect "All signature detection tests PASSED."
3. **Live capture and test**  
   `sudo python main.py` → **Start Monitoring** → in another terminal (or from another PC), run:
   - **Port scan:** `nmap -sT <HOST_IP>` (use your machine’s IP or `localhost`)
   - **SYN flood (lab only):** `sudo hping3 -S -p 80 --flood <HOST_IP>` then **Ctrl+C** after a few seconds
   - **SQLi-like HTTP:** `curl "http://<HOST_IP>/?id=1%20union%20select%20*"`
4. Check alerts in the GUI. When done, **Stop Monitoring** or close the window.

See **[DOCKER_SETUP.md](DOCKER_SETUP.md)** for full commands and the optional Docker-based flow.

### Option B: Docker traffic generator

If you prefer to generate traffic from a container instead of installing nmap/hping3 on the host, use the Docker option in [DOCKER_SETUP.md](DOCKER_SETUP.md) (helper script: `./scripts/docker-traffic-test.sh [HOST_IP]`).

### Option C: VirtualBox (two VMs)

Use two VMs only if you want an isolated lab. **See [VM_SETUP.md](VM_SETUP.md)** for setup. For most users, Option A or B (Docker) is simpler.

### Option D: Single machine with PCAP

1. Capture traffic (e.g. Wireshark) while you browse or run tools.  
2. Save as `capture.pcap`.  
3. Run: `python tests/replay_pcap.py capture.pcap`.  
4. Check console output for alert counts and types.

**Testing without a VM:** Use **nmap directly** (Option A) or the Docker option in [DOCKER_SETUP.md](DOCKER_SETUP.md) if you prefer.

---

## Quick Start (minimal)

1. **Install**: `uv sync` or `pip install -e .`
2. **Run**: `python main.py` (use `sudo python main.py` for live capture)
3. **Test without root**: `python tests/test_detection.py`

## Usage

### First-Time Setup

When you run the application:
1. The system loads the pre-trained model and scaler from `models/` if present
2. If no model exists, the app runs with **signature-based detection only** (SYN flood, port scan, SQLi, XSS, ICMP)
3. To enable ML anomaly detection, ensure `models/isolation_forest_model.pkl` and `models/isolation_forest_model_scaler.pkl` are in place

### Using the GUI

1. **Start Monitoring**: Click "Start Monitoring" to begin packet capture
2. **View Alerts**: Alerts appear in real-time in the alerts table
3. **Filter Alerts**: Use the dropdown to filter by severity level
4. **Export Data**: Click "Export Alerts" to save alerts to JSON file
5. **Stop Monitoring**: Click "Stop Monitoring" to pause detection

### Pre-trained models

This setup uses **pre-trained models** only (no training step or CSV data). The app expects `models/isolation_forest_model.pkl` and `models/isolation_forest_model_scaler.pkl`. If they are missing, the IDS runs with signature-based detection only.

## Project Structure

```
HybridGuard/
├── .gitignore
├── main.py                 # Application entry point
├── pyproject.toml          # Project metadata and dependencies
├── README.md               # This file
├── scripts/
│   └── docker-traffic-test.sh   # Optional: send test traffic via Docker to host IP
├── src/
│   ├── __init__.py
│   ├── alert_manager.py   # Alert handling, logging, JSON/PDF export
│   ├── anomaly_detector.py # ML-based anomaly detection (Isolation Forest)
│   ├── config.py           # Paths, thresholds, live feature set
│   ├── gui.py              # Tkinter GUI (dashboard, alerts, controls)
│   ├── packet_sniffer.py   # Real-time packet capture with Scapy
│   └── signature_detector.py # Rule-based detection (SYN flood, port scan, SQLi, XSS, ICMP)
├── tests/                  # Optional: verify detection without root (see "Purpose of the tests folder" above)
│   ├── __init__.py
│   ├── replay_pcap.py     # Replay a PCAP file through the same pipeline
│   └── test_detection.py   # Simulated flows through signature + ML pipeline
├── models/                 # Trained model and scaler (.pkl); see models/README.md
│   └── README.md
├── data/                    # Not used (app uses pre-trained models only)
└── logs/                    # Alert logs and exports (created at runtime)
```

## Detection Methods

### Signature-Based Rules

| Attack Type | Detection Criteria | Severity |
|------------|-------------------|----------|
| SYN Flood | >100 SYN packets in 10s | HIGH |
| Port Scan | >20 unique ports in 30s | HIGH |
| SQL Injection | Pattern matching in payload | CRITICAL |
| XSS Attack | Script tags in payload | HIGH |
| ICMP Flood | Large packets or high rate | MEDIUM-HIGH |

### ML-Based Detection

- Uses **Isolation Forest** for anomaly detection
- Analyzes 21+ network flow features
- Provides anomaly scores and confidence levels
- Adaptive to network baseline (trained on normal traffic)

## Performance Metrics

If the model was trained elsewhere, evaluation metrics may include:
- **Accuracy**: Overall prediction accuracy
- **Precision**: True positive rate
- **Recall**: Detection sensitivity
- **F1-Score**: Harmonic mean of precision and recall
- **Confusion Matrix**: Visualization of predictions

## Important Notes

⚠️ **Packet Capture Privileges**: 
- Linux/Mac: Run with `sudo python main.py`
- Windows: Run terminal as Administrator
- Replit: Packet capture may be limited in the cloud environment

⚠️ **Dataset**:
- The app uses pre-trained models only; no CSV data or training is required

⚠️ **Network Interface**:
- The system auto-selects the default network interface
- For specific interfaces, modify the `PacketSniffer` initialization in `main.py`

## Logs and Exports

- **Alert Logs**: `logs/alerts.log` - Real-time alert logging
- **Exported Alerts**: `logs/alerts_export_*.json` - Manual exports
- **Model visualization** (if present): `models/evaluation_results.png` - Evaluation metrics from when the model was trained

## Troubleshooting

### Packet Capture Not Working
- Ensure you have administrator/root privileges
- Check if another packet capture tool is running
- Verify network interface is available

### Model fails to load
- Ensure `models/isolation_forest_model.pkl` and `models/isolation_forest_model_scaler.pkl` exist and are compatible (21 features)
- Check logs for specific error messages

### "Scaler/model expects 61 features" or ML errors in tests
- The app expects a model trained on 21 features (same as live traffic). If you have an **old model** (e.g. 61 features), replace it with a compatible 21-feature model and scaler, then run again.

### GUI Not Responding
- Ensure Tkinter is installed (should be included with Python)
- Check system resources (CPU/Memory)
- Review system logs in the GUI log panel

## Security Considerations

This is an educational/demonstration project. For production use:
- Implement secure log storage and rotation
- Add authentication for the GUI
- Encrypt sensitive alert data
- Implement rate limiting for alert notifications
- Add network segmentation support

## License

This project is for educational purposes. Please ensure compliance with network monitoring regulations in your jurisdiction.

## Credits

- **Dataset**: CIC-IDS2017 by Canadian Institute for Cybersecurity
- **Libraries**: Scapy, scikit-learn, pandas, numpy, matplotlib
- **ML Algorithm**: Isolation Forest for anomaly detection
