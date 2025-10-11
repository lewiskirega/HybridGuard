"""
ML-based Anomaly Detection
Uses trained Isolation Forest model for anomaly detection
"""

import numpy as np
import joblib
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AnomalyDetector:
    def __init__(self, model_path='models/isolation_forest_model.pkl', scaler=None):
        self.model_path = model_path
        self.model = None
        self.scaler = scaler
        self.feature_columns = [
            'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
            'Fwd Packet Length Mean', 'Fwd Packet Length Std',
            'Bwd Packet Length Mean', 'Bwd Packet Length Std',
            'Flow Bytes/s', 'Flow Packets/s',
            'Packet Length Mean', 'Packet Length Std',
            'Min Packet Length', 'Max Packet Length',
            'SYN Flag Count', 'ACK Flag Count', 'FIN Flag Count',
            'RST Flag Count', 'PSH Flag Count', 'URG Flag Count'
        ]
    
    def load_model(self):
        """Load the trained Isolation Forest model"""
        if not os.path.exists(self.model_path):
            logger.warning(f"Model file not found: {self.model_path}")
            logger.warning("Please train the model first using the training module")
            return False
        
        try:
            self.model = joblib.load(self.model_path)
            logger.info(f"Model loaded successfully from {self.model_path}")
            return True
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return False
    
    def preprocess_features(self, flow_features):
        """Preprocess flow features to match training data format"""
        try:
            feature_vector = []
            
            for col in self.feature_columns:
                value = flow_features.get(col, 0)
                
                if isinstance(value, (int, float)):
                    if np.isnan(value) or np.isinf(value):
                        value = 0
                    feature_vector.append(float(value))
                else:
                    feature_vector.append(0.0)
            
            feature_array = np.array(feature_vector).reshape(1, -1)
            
            if self.scaler:
                feature_array = self.scaler.transform(feature_array)
            
            return feature_array
        
        except Exception as e:
            logger.error(f"Error preprocessing features: {e}")
            return None
    
    def predict(self, flow_features):
        """Predict if a flow is anomalous"""
        if self.model is None:
            logger.warning("Model not loaded. Call load_model() first.")
            return None
        
        feature_array = self.preprocess_features(flow_features)
        
        if feature_array is None:
            return None
        
        try:
            prediction = self.model.predict(feature_array)[0]
            
            anomaly_score = self.model.score_samples(feature_array)[0]
            
            is_anomaly = prediction == -1
            
            confidence = abs(anomaly_score)
            
            result = {
                'is_anomaly': is_anomaly,
                'prediction': 'Anomaly' if is_anomaly else 'Normal',
                'anomaly_score': float(anomaly_score),
                'confidence': float(confidence),
                'severity': self._calculate_severity(anomaly_score, is_anomaly)
            }
            
            return result
        
        except Exception as e:
            logger.error(f"Error during prediction: {e}")
            return None
    
    def _calculate_severity(self, anomaly_score, is_anomaly):
        """Calculate severity level based on anomaly score"""
        if not is_anomaly:
            return 'LOW'
        
        if anomaly_score < -0.5:
            return 'CRITICAL'
        elif anomaly_score < -0.3:
            return 'HIGH'
        elif anomaly_score < -0.1:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def set_scaler(self, scaler):
        """Set the scaler for feature normalization"""
        self.scaler = scaler
        logger.info("Scaler set successfully")
