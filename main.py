"""
Main Application Entry Point for HybridGuard IDS.

HybridGuard is a hybrid intrusion detection system that combines:
  - Signature-based detection: rules for SYN flood, port scan, SQLi, XSS, ICMP flood.
  - ML-based detection: Isolation Forest on flow features (trained on normal traffic).

This module wires together the packet sniffer, signature detector, anomaly detector,
alert manager, and GUI. Run with root/sudo for live packet capture (see VM_SETUP.md).
"""

import tkinter as tk
from src.data_loader import DataLoader
from src.model_trainer import ModelTrainer
from src.packet_sniffer import PacketSniffer
from src.signature_detector import SignatureDetector
from src.anomaly_detector import AnomalyDetector
from src.alert_manager import AlertManager
from src.gui import IDSGUI
from src.config import (
    MODEL_PATH,
    get_scaler_path,
    LOG_DIR,
    FLOW_TIMEOUT_SEC,
    CLEANUP_STATS_EVERY_N_FLOWS,
    TRAIN_CONTAMINATION,
    TRAIN_N_ESTIMATORS,
)
import logging
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class IDSController:
    """
    Central controller for the IDS: initializes model/signatures, starts/stops
    the sniffer, and routes each flow through signature then ML detection.
    """

    def __init__(self):
        self.alert_manager = AlertManager()
        self.signature_detector = SignatureDetector()
        self.anomaly_detector = AnomalyDetector()
        self.packet_sniffer = None  # Created on start(); requires root for capture
        self.scaler = None  # Loaded with model; used to normalize flow features for ML
        self.packet_count = 0

    def initialize(self):
        """Load or train the ML model and scaler; prepare for monitoring."""
        logger.info("Initializing HybridGuard IDS...")
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        scaler_path = get_scaler_path()

        if not os.path.exists(MODEL_PATH):
            logger.info("Trained model not found. Training new model (using live feature set)...")
            if not self.train_model():
                logger.warning("Model training failed. Using signature-based detection only.")
                return False
        else:
            success = self.anomaly_detector.load_model()
            if success:
                if os.path.exists(scaler_path):
                    import joblib
                    self.scaler = joblib.load(scaler_path)
                    self.anomaly_detector.set_scaler(self.scaler)
                    logger.info("Model and scaler loaded successfully")
                else:
                    logger.warning("Scaler file not found. ML detection may not work correctly.")
            else:
                logger.warning("Could not load ML model. Using signature-based detection only.")

        logger.info("IDS initialization complete")
        return True
    
    def train_model(self):
        """Train the Isolation Forest on (normal) traffic; use 21 live features only."""
        try:
            logger.info("Loading and preprocessing dataset...")
            data_loader = DataLoader()
            
            df = data_loader.load_csv_files()
            X, y, features = data_loader.preprocess_data(df)
            
            X_train, X_test, y_train, y_test = data_loader.split_data(
                X, y, train_ratio=0.7, use_normal_only=True
            )
            
            X_train_scaled, X_test_scaled = data_loader.normalize_features(X_train, X_test)
            
            self.scaler = data_loader.get_scaler()
            self.anomaly_detector.set_scaler(self.scaler)
            
            logger.info("Training Isolation Forest model...")
            trainer = ModelTrainer(
                contamination=TRAIN_CONTAMINATION,
                n_estimators=TRAIN_N_ESTIMATORS,
            )
            trainer.train(X_train_scaled)
            results = trainer.evaluate(X_test_scaled, y_test)
            trainer.visualize_results(results)
            trainer.save_model(model_path=MODEL_PATH, scaler=self.scaler)
            
            logger.info("Model training completed successfully!")
            return True
            
        except Exception as e:
            logger.error(f"Error during model training: {e}")
            return False
    
    def process_flow(self, flow_features):
        """
        Run one flow through detection: signature rules first, then ML if no signature hit.
        Periodically clean signature detector state to avoid unbounded memory growth.
        """
        self.packet_count += 1
        if self.packet_count % CLEANUP_STATS_EVERY_N_FLOWS == 0:
            self.signature_detector.cleanup_old_stats()

        signature_alerts = self.signature_detector.detect(flow_features)

        for alert in signature_alerts:
            self.alert_manager.add_alert(
                source=alert.get('src_ip', 'Unknown'),
                alert_type=alert['type'],
                severity=alert['severity'],
                description=alert['description']
            )
            logger.warning(f"[SIGNATURE] {alert['type']}: {alert['description']}")
        
        # Only run ML when no signature matched (avoids duplicate alerts)
        if not signature_alerts:
            ml_result = self.anomaly_detector.predict(flow_features)

            if ml_result and ml_result['is_anomaly']:
                self.alert_manager.add_alert(
                    source=flow_features.get('src_ip', 'Unknown'),
                    alert_type='Anomaly Detected',
                    severity=ml_result['severity'],
                    description=f"ML-based anomaly detection (score: {ml_result['anomaly_score']:.3f})",
                    additional_data={'ml_result': ml_result}
                )
                logger.info(f"[ML] Anomaly detected: {flow_features.get('src_ip', 'Unknown')}")
    
    def start(self):
        """Start the IDS monitoring. Requires root/sudo on Linux for packet capture."""
        try:
            logger.info("Starting IDS monitoring...")
            self.packet_sniffer = PacketSniffer(interface=None, flow_timeout=FLOW_TIMEOUT_SEC)
            self.packet_sniffer.start(callback=self.process_flow)
            if not self.packet_sniffer.running:
                logger.error("Packet capture failed (often due to missing root/sudo).")
                return False
            logger.info("IDS monitoring started successfully")
            return True
        except Exception as e:
            logger.error(f"Error starting IDS: {e}")
            return False
    
    def stop(self):
        """Stop the IDS monitoring"""
        logger.info("Stopping IDS monitoring...")
        
        if self.packet_sniffer:
            self.packet_sniffer.stop()
        
        logger.info("IDS monitoring stopped")
    
    def get_recent_alerts(self, limit=50):
        """Get recent alerts"""
        return self.alert_manager.get_recent_alerts(limit)
    
    def get_statistics(self):
        """Get system statistics"""
        stats = self.alert_manager.get_alert_statistics()
        stats['packets'] = self.packet_count
        return stats
    
    def clear_alerts(self):
        """Clear all alerts"""
        self.alert_manager.clear_alerts()
        self.packet_count = 0
    
    def export_alerts(self):
        """Export alerts to file"""
        return self.alert_manager.save_alerts_to_file()


def main():
    """Start HybridGuard: load/train model, open GUI, run event loop."""
    logger.info("Starting Hybrid Intrusion Detection System...")
    
    controller = IDSController()
    
    if not controller.initialize():
        logger.warning("IDS initialization completed with warnings")
    
    root = tk.Tk()
    gui = IDSGUI(root, controller)
    
    def on_closing():
        gui.close()
        controller.stop()
        root.destroy()
        sys.exit(0)
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    logger.info("Launching GUI...")
    root.mainloop()


if __name__ == "__main__":
    main()
