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
- Python 3.8 or higher
- Administrator/root privileges (required for packet capture)

### Quick Start

1. **Install Dependencies**
   ```bash
   # Dependencies are already installed in this Replit environment
   ```

2. **Run the Application**
   ```bash
   python main.py
   ```

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
hybrid_ids/
├── main.py                 # Application entry point
├── src/
│   ├── __init__.py
│   ├── data_loader.py      # Dataset loading and preprocessing
│   ├── model_trainer.py    # ML model training and evaluation
│   ├── packet_sniffer.py   # Real-time packet capture with Scapy
│   ├── signature_detector.py # Rule-based detection engine
│   ├── anomaly_detector.py # ML-based anomaly detection
│   ├── alert_manager.py    # Alert handling and logging
│   └── gui.py             # Tkinter GUI
├── models/                 # Trained ML models
├── data/                   # Dataset storage
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
