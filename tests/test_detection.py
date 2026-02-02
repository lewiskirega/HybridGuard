#!/usr/bin/env python3
"""
Test HybridGuard detection without root or live packet capture.

Runs simulated flows through the same pipeline as live capture: signature rules
(SQLi, XSS, SYN flood, port scan) and ML anomaly detection (if model exists).
Useful for CI and for verifying detection logic before VM testing.

Run from project root: python tests/test_detection.py
"""

import sys
import os

# Ensure project root is on path so "from src.*" works
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.signature_detector import SignatureDetector
from src.anomaly_detector import AnomalyDetector
from src.alert_manager import AlertManager
from src.config import MODEL_PATH, get_scaler_path, LIVE_FEATURE_COLUMNS


def make_flow(**kwargs):
    """Build a flow feature dict with defaults matching PacketSniffer.compute_flow_features()."""
    defaults = {
        "Flow Duration": 100000,
        "Total Fwd Packets": 5,
        "Total Backward Packets": 3,
        "Total Length of Fwd Packets": 1500,
        "Total Length of Bwd Packets": 1200,
        "Fwd Packet Length Mean": 300,
        "Fwd Packet Length Std": 0,
        "Bwd Packet Length Mean": 400,
        "Bwd Packet Length Std": 0,
        "Flow Bytes/s": 5000,
        "Flow Packets/s": 80,
        "Packet Length Mean": 350,
        "Packet Length Std": 50,
        "Min Packet Length": 60,
        "Max Packet Length": 1500,
        "SYN Flag Count": 0,
        "ACK Flag Count": 5,
        "FIN Flag Count": 0,
        "RST Flag Count": 0,
        "PSH Flag Count": 2,
        "URG Flag Count": 0,
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "protocol": 6,
        "packets": [],
    }
    defaults.update(kwargs)
    return defaults


def run_tests():
    """Run signature and (if model exists) ML detection on simulated flows; report pass/fail."""
    alert_manager = AlertManager()
    signature_detector = SignatureDetector()
    anomaly_detector = AnomalyDetector()
    if os.path.exists(MODEL_PATH):
        if anomaly_detector.load_model():
            scaler_path = get_scaler_path()
            if os.path.exists(scaler_path):
                import joblib
                anomaly_detector.set_scaler(joblib.load(scaler_path))
        else:
            anomaly_detector = None
    else:
        anomaly_detector = None

    def process(flow):
        alerts = signature_detector.detect(flow)
        for a in alerts:
            alert_manager.add_alert(
                source=a.get("src_ip", "Unknown"),
                alert_type=a["type"],
                severity=a["severity"],
                description=a["description"],
            )
        if not alerts and anomaly_detector and anomaly_detector.model:
            res = anomaly_detector.predict(flow)
            if res and res["is_anomaly"]:
                alert_manager.add_alert(
                    source=flow.get("src_ip", "Unknown"),
                    alert_type="Anomaly Detected",
                    severity=res["severity"],
                    description=f"ML anomaly (score: {res['anomaly_score']:.3f})",
                )

    # 1) Normal flow – should not trigger signature rules
    process(make_flow(src_ip="192.168.1.10"))
    # 2) SQL injection pattern in payload
    process(
        make_flow(
            src_ip="192.168.1.50",
            packets=[
                {
                    "src_ip": "192.168.1.50",
                    "payload": b"id=1 union select * from users--",
                }
            ],
        )
    )
    # 3) XSS pattern
    process(
        make_flow(
            src_ip="192.168.1.51",
            packets=[
                {
                    "src_ip": "192.168.1.51",
                    "payload": b"q=<script>alert(1)</script>",
                }
            ],
        )
    )
    # 4) Many SYNs from same IP (flow-level SYN Flag Count is what signature detector uses)
    for _ in range(105):
        process(make_flow(src_ip="192.168.1.200", **{"SYN Flag Count": 1}))
    # 5) Port scan: many different dst ports from same IP (simulate 25 flows with different ports)
    for port in range(40000, 40025):
        process(
            make_flow(
                src_ip="192.168.1.201",
                packets=[{"src_ip": "192.168.1.201", "dst_port": port, "payload": b""}],
            )
        )

    stats = alert_manager.get_alert_statistics()
    # Use a large limit so signature alerts (SQLi, XSS) are not pushed out by many ML alerts
    all_alerts = alert_manager.get_recent_alerts(500)
    recent_display = all_alerts[:50]

    print("=== HybridGuard detection test (no root required) ===\n")
    print("Alerts generated:", stats.get("total", 0))
    print("By severity:", stats)
    for a in recent_display[:15]:
        print(f"  [{a['severity']}] {a['type']}: {a['description'][:70]}")
    if len(recent_display) > 15:
        print(f"  ... and {len(recent_display) - 15} more (showing first 50 of {len(all_alerts)})")

    checks = {
        "SQL Injection": any(a["type"] == "SQL Injection" for a in all_alerts),
        "XSS Attack": any(a["type"] == "XSS Attack" for a in all_alerts),
        "SYN Flood": any(a["type"] == "SYN Flood" for a in all_alerts),
        "Port Scan": any(a["type"] == "Port Scan" for a in all_alerts),
    }
    print("\n--- Signature checks ---")
    for name, ok in checks.items():
        print(f"  {name}: {'PASS' if ok else 'FAIL'}")

    all_pass = all(checks.values())
    if all_pass:
        print("\nAll signature detection tests PASSED.")
    else:
        print("\nSome signature tests FAILED.")
    return all_pass


if __name__ == "__main__":
    ok = run_tests()
    sys.exit(0 if ok else 1)
