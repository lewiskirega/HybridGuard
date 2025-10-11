"""
Main Application Entry Point for Hybrid IDS
Integrates all components and launches the system
"""

import tkinter as tk
from src.data_loader import DataLoader
from src.model_trainer import ModelTrainer
from src.packet_sniffer import PacketSniffer
from src.signature_detector import SignatureDetector
from src.anomaly_detector import AnomalyDetector
from src.alert_manager import AlertManager
from src.gui import IDSGUI
import logging
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class IDSController:
    def __init__(self):
        self.alert_manager = AlertManager()
        self.signature_detector = SignatureDetector()
        self.anomaly_detector = AnomalyDetector()
        self.packet_sniffer = None
        self.scaler = None
        self.packet_count = 0
        
    def initialize(self):
        """Initialize the IDS system"""
        logger.info("Initializing Hybrid IDS...")
        
        model_path = 'models/isolation_forest_model.pkl'
        
        if not os.path.exists(model_path):
            logger.info("Trained model not found. Training new model...")
            if not self.train_model():
                logger.warning("Model training failed. Using signature-based detection only.")
                return False
        
        success = self.anomaly_detector.load_model()
        if not success:
            logger.warning("Could not load ML model. Using signature-based detection only.")
        
        logger.info("IDS initialization complete")
        return True
    
    def train_model(self):
        """Train the Isolation Forest model"""
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
            trainer = ModelTrainer(contamination=0.1, n_estimators=100)
            trainer.train(X_train_scaled)
            
            results = trainer.evaluate(X_test_scaled, y_test)
            
            trainer.visualize_results(results)
            
            trainer.save_model()
            
            logger.info("Model training completed successfully!")
            return True
            
        except Exception as e:
            logger.error(f"Error during model training: {e}")
            return False
    
    def process_flow(self, flow_features):
        """Process a network flow through detection engines"""
        self.packet_count += 1
        
        signature_alerts = self.signature_detector.detect(flow_features)
        
        for alert in signature_alerts:
            self.alert_manager.add_alert(
                source=alert.get('src_ip', 'Unknown'),
                alert_type=alert['type'],
                severity=alert['severity'],
                description=alert['description']
            )
            logger.warning(f"[SIGNATURE] {alert['type']}: {alert['description']}")
        
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
        """Start the IDS monitoring"""
        try:
            logger.info("Starting IDS monitoring...")
            
            self.packet_sniffer = PacketSniffer(interface=None, flow_timeout=5)
            self.packet_sniffer.start(callback=self.process_flow)
            
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
    """Main application entry point"""
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
