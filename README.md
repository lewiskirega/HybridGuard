# Hybrid Intrusion Detection System (IDS)

A comprehensive network intrusion detection system that combines machine learning-based anomaly detection with signature-based rules for real-time threat detection.

## Features

### 🤖 Machine Learning Detection
- **Isolation Forest** algorithm for anomaly detection
- Trained on CIC-IDS2017 dataset (or sample data)
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
# Without root: app starts, model loads/trains, GUI opens. Click "Start Monitoring" will fail with a clear message.
python main.py

# With root (required for live packet capture):
sudo python main.py   # Linux/macOS
# Windows: open terminal as Administrator, then: python main.py
```

- **First run**: If no model exists, the app trains one on sample data (1–2 minutes), then opens the GUI.
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

---

## How to Test (full workflow)

### Option A: Same machine, no VM

1. **Install and open GUI (no root)**  
   `python main.py` → wait for model training (first time) → GUI opens.
2. **Verify detection logic (no root)**  
   `python tests/test_detection.py` → expect "All signature detection tests PASSED."
3. **Live capture (with root)**  
   `sudo python main.py` → Start Monitoring → generate traffic (browse, ping, etc.) → check alerts in the dashboard and export if needed.

### Option B: VirtualBox (two VMs)

Use two VMs when you want to test with real traffic between machines without affecting your host. **See [VM_SETUP.md](VM_SETUP.md)** for:

- **Recommended OS**: Ubuntu 22.04 LTS for both VMs (or Kali/Parrot for VM 2 if you prefer security tools preinstalled).
- Step-by-step VirtualBox setup (create VMs, network, install Python, run HybridGuard, generate traffic).

Summary:

1. **VM 1 – HybridGuard (monitor)**  
   - Install Python and dependencies; run: `sudo python main.py`.  
   - Start Monitoring (sniffer on default interface; use host-only or bridged so VM 2 is on same network).

2. **VM 2 – Traffic generator**  
   - Install `nmap`, `hping3`; run port scan: `nmap -sT <VM1_IP>`; optionally SYN flood: `sudo hping3 -S -p 80 --flood <VM1_IP>`.

3. **Observe**  
   Alerts appear in VM 1’s GUI and in `logs/alerts.log`.

### Option C: Single machine with PCAP

1. Capture traffic (e.g. Wireshark) while you browse or run tools.  
2. Save as `capture.pcap`.  
3. Run: `python tests/replay_pcap.py capture.pcap`.  
4. Check console output for alert counts and types.

---

## Quick Start (minimal)

1. **Install**: `uv sync` or `pip install -e .`
2. **Run**: `python main.py` (use `sudo python main.py` for live capture)
3. **Test without root**: `python tests/test_detection.py`

## Usage

### First-Time Setup

When you run the application for the first time:
1. The system will check for a trained model
2. If no model exists, it will automatically train one using sample data
3. Training takes 1-2 minutes and creates visualization of results
4. The trained model is saved to `models/isolation_forest_model.pkl`

### Using the GUI

1. **Start Monitoring**: Click "Start Monitoring" to begin packet capture
2. **View Alerts**: Alerts appear in real-time in the alerts table
3. **Filter Alerts**: Use the dropdown to filter by severity level
4. **Export Data**: Click "Export Alerts" to save alerts to JSON file
5. **Stop Monitoring**: Click "Stop Monitoring" to pause detection

### Training with CIC-IDS2017 Dataset

To use the real CIC-IDS2017 dataset:

1. Download the dataset from [Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html)
2. Place CSV files in `data/cic_ids_2017/` directory
3. Delete the existing model: `rm models/isolation_forest_model.pkl`
4. Run the application - it will retrain on the real dataset

## Project Structure

```
HybridGuard/
├── main.py                 # Application entry point
├── VM_SETUP.md             # VM testing guide (OS, VirtualBox, traffic generation)
├── src/
│   ├── config.py           # Paths, thresholds, live feature set
│   ├── data_loader.py      # Dataset loading and preprocessing
│   ├── model_trainer.py    # ML model training and evaluation
│   ├── packet_sniffer.py   # Real-time packet capture with Scapy
│   ├── signature_detector.py # Rule-based detection engine
│   ├── anomaly_detector.py # ML-based anomaly detection
│   ├── alert_manager.py    # Alert handling and logging
│   └── gui.py              # Tkinter GUI
├── tests/
│   ├── test_detection.py   # Test detection without root (simulated flows)
│   └── replay_pcap.py      # Replay PCAP through full pipeline
├── models/                 # Trained ML models
├── data/                   # Dataset storage (CIC-IDS2017 or generated)
└── logs/                   # Alert logs and exports
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

The system displays the following metrics after training:
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
- Sample data is generated automatically if CIC-IDS2017 is not available
- For production use, train with real network traffic data

⚠️ **Network Interface**:
- The system auto-selects the default network interface
- For specific interfaces, modify the `PacketSniffer` initialization in `main.py`

## Logs and Exports

- **Alert Logs**: `logs/alerts.log` - Real-time alert logging
- **Exported Alerts**: `logs/alerts_export_*.json` - Manual exports
- **Model Visualization**: `models/evaluation_results.png` - Training metrics

## Troubleshooting

### Packet Capture Not Working
- Ensure you have administrator/root privileges
- Check if another packet capture tool is running
- Verify network interface is available

### Model Training Fails
- Check if sufficient memory is available (>2GB recommended)
- Verify dataset files are not corrupted
- Check logs for specific error messages

### "Scaler/model expects 61 features" or ML errors in tests
- The app now trains on 21 features (same as live traffic). If you have an **old model** (trained with 61 features), delete it and restart so the app retrains with 21:  
  `rm -f models/isolation_forest_model.pkl models/isolation_forest_model_scaler.pkl` then run `python main.py` or `python tests/test_detection.py` again.

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
