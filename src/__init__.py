"""
HybridGuard: Hybrid Intrusion Detection System.

Combines signature-based rules (SYN flood, port scan, SQLi, XSS, ICMP flood)
with ML-based anomaly detection (Isolation Forest on flow features).
See main.py for entry point; VM_SETUP.md for VM testing guide.
"""

__version__ = "1.0.0"
__author__ = "Hybrid IDS Team"
