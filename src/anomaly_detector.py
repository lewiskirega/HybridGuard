"""
ML-based Anomaly Detection.

Loads the trained Isolation Forest and scaler; for each flow feature dict,
builds a 21-feature vector (LIVE_FEATURE_COLUMNS), normalizes with the scaler,
and predicts anomaly + severity. If the loaded model/scaler have a different
feature count (e.g. old 61-feature model), they are ignored to avoid errors.
"""

import numpy as np
import joblib
import os
import logging

from src.config import MODEL_PATH, LIVE_FEATURE_COLUMNS

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Runs Isolation Forest on flow features; returns is_anomaly, severity, anomaly_score.
    Expects flow_features dict with keys matching LIVE_FEATURE_COLUMNS.
    """

    def __init__(self, model_path=None, scaler=None):
        self.model_path = model_path or MODEL_PATH
        self.model = None
        self.scaler = scaler  # Must match 21 features; set_scaler validates
        self.feature_columns = list(LIVE_FEATURE_COLUMNS)

    def load_model(self):
        """Load model from disk; set verbose=0 to avoid joblib output during predict."""
        if not os.path.exists(self.model_path):
            logger.warning(f"Model file not found: {self.model_path}")
            logger.warning("Please train the model first using the training module")
            return False
        
        try:
            self.model = joblib.load(self.model_path)
            if hasattr(self.model, "set_params"):
                self.model.set_params(verbose=0)
            elif hasattr(self.model, "verbose"):
                self.model.verbose = 0
            logger.info(f"Model loaded successfully from {self.model_path}")
            return True
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return False
    
    def preprocess_features(self, flow_features):
        """Build 21-dim vector from flow_features, then scale if scaler is set and matches."""
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
        """Return dict with is_anomaly, severity, anomaly_score; None if model/scaler mismatch or error."""
        if self.model is None:
            logger.warning("Model not loaded. Call load_model() first.")
            return None
        n_model_features = getattr(self.model, "n_features_in_", None)
        if n_model_features is not None and n_model_features != len(self.feature_columns):
            return None  # Model was trained with different feature set; skip ML (no log spam)
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
        """Set the scaler for feature normalization. If it was fitted with a different
        number of features (e.g. old 61-feature model), do not use it so we avoid transform errors.
        """
        if scaler is not None:
            n_expected = getattr(scaler, "n_features_in_", None)
            if n_expected is not None and n_expected != len(self.feature_columns):
                logger.warning(
                    "Scaler expects %d features but live pipeline uses %d. "
                    "Delete models/*.pkl and restart to retrain with 21 features.",
                    n_expected,
                    len(self.feature_columns),
                )
                self.scaler = None
                return
        self.scaler = scaler
        logger.info("Scaler set successfully")
