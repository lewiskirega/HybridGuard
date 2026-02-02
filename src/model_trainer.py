"""
Model Trainer for Isolation Forest.

Trains an Isolation Forest on (normal) flow features, evaluates with
accuracy/precision/recall/F1 and confusion matrix, saves model and scaler
for use by the anomaly detector at inference time.
"""

from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import matplotlib.pyplot as plt
import numpy as np
import joblib
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ModelTrainer:
    """
    Trains and evaluates Isolation Forest; saves/loads model and scaler.
    Expects X_train to have the same 21 features as LIVE_FEATURE_COLUMNS.
    """

    def __init__(self, contamination=0.1, n_estimators=100, random_state=42):
        self.contamination = contamination  # Expected fraction of anomalies
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model = None

    def train(self, X_train):
        """Fit Isolation Forest on (normal) flow feature matrix X_train."""
        logger.info(f"Training Isolation Forest with {self.n_estimators} estimators...")
        
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=-1,
            verbose=0,
        )
        
        self.model.fit(X_train)
        logger.info("Model training completed!")
        
        return self.model
    
    def evaluate(self, X_test, y_test):
        """Compute accuracy, precision, recall, F1, and confusion matrix (binary: normal vs anomaly)."""
        if self.model is None:
            raise ValueError("Model not trained yet. Call train() first.")
        
        logger.info("Evaluating model...")
        
        y_pred = self.model.predict(X_test)
        
        y_pred_binary = np.where(y_pred == 1, 0, 1)
        y_test_binary = np.where(y_test == 'BENIGN', 0, 1)
        
        accuracy = accuracy_score(y_test_binary, y_pred_binary)
        precision = precision_score(y_test_binary, y_pred_binary, zero_division=0)
        recall = recall_score(y_test_binary, y_pred_binary, zero_division=0)
        f1 = f1_score(y_test_binary, y_pred_binary, zero_division=0)
        
        logger.info(f"Accuracy: {accuracy:.4f}")
        logger.info(f"Precision: {precision:.4f}")
        logger.info(f"Recall: {recall:.4f}")
        logger.info(f"F1-Score: {f1:.4f}")
        
        cm = confusion_matrix(y_test_binary, y_pred_binary)
        logger.info(f"Confusion Matrix:\n{cm}")
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'confusion_matrix': cm,
            'predictions': y_pred
        }
    
    def visualize_results(self, results, save_path='models/evaluation_results.png'):
        """Visualize evaluation results"""
        metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
        values = [
            results['accuracy'],
            results['precision'],
            results['recall'],
            results['f1_score']
        ]
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
        
        ax1.bar(metrics, values, color=['#2ecc71', '#3498db', '#e74c3c', '#f39c12'])
        ax1.set_ylabel('Score')
        ax1.set_title('Model Performance Metrics')
        ax1.set_ylim(0, 1)
        
        for i, v in enumerate(values):
            ax1.text(i, v + 0.02, f'{v:.3f}', ha='center', fontweight='bold')
        
        cm = results['confusion_matrix']
        im = ax2.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
        ax2.set_title('Confusion Matrix')
        ax2.set_xlabel('Predicted Label')
        ax2.set_ylabel('True Label')
        
        tick_marks = np.arange(2)
        ax2.set_xticks(tick_marks)
        ax2.set_yticks(tick_marks)
        ax2.set_xticklabels(['Normal', 'Anomaly'])
        ax2.set_yticklabels(['Normal', 'Anomaly'])
        
        thresh = cm.max() / 2
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                ax2.text(j, i, format(cm[i, j], 'd'),
                        ha="center", va="center",
                        color="white" if cm[i, j] > thresh else "black")
        
        plt.tight_layout()
        plt.savefig(save_path, dpi=150, bbox_inches='tight')
        logger.info(f"Visualization saved to {save_path}")
        plt.close()
    
    def save_model(self, model_path='models/isolation_forest_model.pkl', scaler=None):
        """Save trained model and scaler to disk"""
        if self.model is None:
            raise ValueError("No model to save. Train the model first.")
        
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        joblib.dump(self.model, model_path)
        logger.info(f"Model saved to {model_path}")
        
        if scaler is not None:
            scaler_path = model_path.replace('.pkl', '_scaler.pkl')
            joblib.dump(scaler, scaler_path)
            logger.info(f"Scaler saved to {scaler_path}")
    
    def load_model(self, model_path='models/isolation_forest_model.pkl'):
        """Load trained model and scaler from disk"""
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")
        
        self.model = joblib.load(model_path)
        logger.info(f"Model loaded from {model_path}")
        
        scaler_path = model_path.replace('.pkl', '_scaler.pkl')
        scaler = None
        if os.path.exists(scaler_path):
            scaler = joblib.load(scaler_path)
            logger.info(f"Scaler loaded from {scaler_path}")
        else:
            logger.warning(f"Scaler file not found: {scaler_path}")
        
        return self.model, scaler
    
    def get_model(self):
        """Return the trained model"""
        return self.model
