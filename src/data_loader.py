"""
Data Loader for CIC-IDS2017 Dataset
Handles loading, preprocessing, and feature extraction
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DataLoader:
    def __init__(self, data_dir='data/cic_ids_2017'):
        self.data_dir = data_dir
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        
        self.feature_columns = [
            'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
            'Fwd Packet Length Mean', 'Fwd Packet Length Std',
            'Bwd Packet Length Mean', 'Bwd Packet Length Std',
            'Flow Bytes/s', 'Flow Packets/s',
            'Flow IAT Mean', 'Flow IAT Std',
            'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std',
            'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
            'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
            'Fwd Header Length', 'Bwd Header Length',
            'Fwd Packets/s', 'Bwd Packets/s',
            'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
            'Packet Length Std', 'Packet Length Variance',
            'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
            'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
            'CWE Flag Count', 'ECE Flag Count',
            'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
            'Avg Bwd Segment Size', 'Fwd Header Length.1',
            'Subflow Fwd Packets', 'Subflow Fwd Bytes',
            'Subflow Bwd Packets', 'Subflow Bwd Bytes',
            'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
            'act_data_pkt_fwd', 'min_seg_size_forward',
            'Active Mean', 'Active Std', 'Active Max', 'Active Min',
            'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
        ]
    
    def load_csv_files(self):
        """Load all CSV files from the dataset directory"""
        if not os.path.exists(self.data_dir):
            logger.warning(f"Dataset directory {self.data_dir} does not exist. Creating sample data...")
            return self._create_sample_data()
        
        csv_files = [f for f in os.listdir(self.data_dir) if f.endswith('.csv')]
        
        if not csv_files:
            logger.warning("No CSV files found. Creating sample data...")
            return self._create_sample_data()
        
        dataframes = []
        for csv_file in csv_files:
            file_path = os.path.join(self.data_dir, csv_file)
            logger.info(f"Loading {csv_file}...")
            try:
                df = pd.read_csv(file_path, encoding='utf-8', low_memory=False)
                dataframes.append(df)
            except Exception as e:
                logger.error(f"Error loading {csv_file}: {e}")
        
        if dataframes:
            combined_df = pd.concat(dataframes, ignore_index=True)
            logger.info(f"Total records loaded: {len(combined_df)}")
            return combined_df
        else:
            return self._create_sample_data()
    
    def _create_sample_data(self):
        """Create sample data for demonstration when dataset is not available"""
        logger.info("Creating sample training data...")
        np.random.seed(42)
        n_samples = 10000
        
        data = {
            'Flow Duration': np.random.exponential(100000, n_samples),
            'Total Fwd Packets': np.random.poisson(10, n_samples),
            'Total Backward Packets': np.random.poisson(8, n_samples),
            'Total Length of Fwd Packets': np.random.gamma(2, 500, n_samples),
            'Total Length of Bwd Packets': np.random.gamma(2, 400, n_samples),
            'Fwd Packet Length Mean': np.random.normal(400, 100, n_samples),
            'Fwd Packet Length Std': np.random.normal(50, 20, n_samples),
            'Bwd Packet Length Mean': np.random.normal(350, 80, n_samples),
            'Bwd Packet Length Std': np.random.normal(45, 15, n_samples),
            'Flow Bytes/s': np.random.exponential(5000, n_samples),
            'Flow Packets/s': np.random.exponential(50, n_samples),
            'Flow IAT Mean': np.random.exponential(10000, n_samples),
            'Flow IAT Std': np.random.exponential(5000, n_samples),
            'Fwd IAT Total': np.random.exponential(50000, n_samples),
            'Fwd IAT Mean': np.random.exponential(10000, n_samples),
            'Fwd IAT Std': np.random.exponential(5000, n_samples),
            'Bwd IAT Total': np.random.exponential(40000, n_samples),
            'Bwd IAT Mean': np.random.exponential(8000, n_samples),
            'Bwd IAT Std': np.random.exponential(4000, n_samples),
            'Fwd PSH Flags': np.random.binomial(1, 0.3, n_samples),
            'Bwd PSH Flags': np.random.binomial(1, 0.3, n_samples),
            'Fwd URG Flags': np.random.binomial(1, 0.01, n_samples),
            'Bwd URG Flags': np.random.binomial(1, 0.01, n_samples),
            'Fwd Header Length': np.random.normal(32, 8, n_samples),
            'Bwd Header Length': np.random.normal(32, 8, n_samples),
            'Fwd Packets/s': np.random.exponential(25, n_samples),
            'Bwd Packets/s': np.random.exponential(20, n_samples),
            'Min Packet Length': np.random.randint(40, 100, n_samples),
            'Max Packet Length': np.random.randint(1000, 1500, n_samples),
            'Packet Length Mean': np.random.normal(500, 100, n_samples),
            'Packet Length Std': np.random.normal(200, 50, n_samples),
            'Packet Length Variance': np.random.exponential(40000, n_samples),
            'FIN Flag Count': np.random.binomial(2, 0.5, n_samples),
            'SYN Flag Count': np.random.binomial(2, 0.5, n_samples),
            'RST Flag Count': np.random.binomial(1, 0.1, n_samples),
            'PSH Flag Count': np.random.binomial(5, 0.3, n_samples),
            'ACK Flag Count': np.random.binomial(10, 0.8, n_samples),
            'URG Flag Count': np.random.binomial(1, 0.01, n_samples),
            'CWE Flag Count': np.random.binomial(1, 0.05, n_samples),
            'ECE Flag Count': np.random.binomial(1, 0.05, n_samples),
            'Down/Up Ratio': np.random.uniform(0.5, 1.5, n_samples),
            'Average Packet Size': np.random.normal(500, 100, n_samples),
            'Avg Fwd Segment Size': np.random.normal(450, 90, n_samples),
            'Avg Bwd Segment Size': np.random.normal(400, 80, n_samples),
            'Fwd Header Length.1': np.random.normal(32, 8, n_samples),
            'Subflow Fwd Packets': np.random.poisson(10, n_samples),
            'Subflow Fwd Bytes': np.random.gamma(2, 500, n_samples),
            'Subflow Bwd Packets': np.random.poisson(8, n_samples),
            'Subflow Bwd Bytes': np.random.gamma(2, 400, n_samples),
            'Init_Win_bytes_forward': np.random.randint(8000, 65535, n_samples),
            'Init_Win_bytes_backward': np.random.randint(8000, 65535, n_samples),
            'act_data_pkt_fwd': np.random.poisson(5, n_samples),
            'min_seg_size_forward': np.random.randint(20, 60, n_samples),
            'Active Mean': np.random.exponential(100000, n_samples),
            'Active Std': np.random.exponential(50000, n_samples),
            'Active Max': np.random.exponential(200000, n_samples),
            'Active Min': np.random.exponential(10000, n_samples),
            'Idle Mean': np.random.exponential(500000, n_samples),
            'Idle Std': np.random.exponential(200000, n_samples),
            'Idle Max': np.random.exponential(1000000, n_samples),
            'Idle Min': np.random.exponential(100000, n_samples),
            'Label': ['BENIGN'] * n_samples
        }
        
        return pd.DataFrame(data)
    
    def preprocess_data(self, df):
        """Clean and preprocess the dataset"""
        logger.info("Preprocessing data...")
        
        df = df.copy()
        
        df.columns = df.columns.str.strip()
        
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        
        available_features = [col for col in self.feature_columns if col in df.columns]
        missing_features = [col for col in self.feature_columns if col not in df.columns]
        
        if missing_features:
            logger.warning(f"Missing features: {missing_features[:5]}...")
        
        for col in available_features:
            if df[col].dtype == 'object':
                df[col] = pd.to_numeric(df[col], errors='coerce')
            df[col] = df[col].fillna(df[col].median())
        
        X = df[available_features].values
        
        if 'Label' in df.columns:
            y = df['Label'].values
        else:
            y = np.array(['BENIGN'] * len(df))
        
        logger.info(f"Preprocessed data shape: {X.shape}")
        return X, y, available_features
    
    def split_data(self, X, y, train_ratio=0.7, use_normal_only=True):
        """Split data into training and testing sets"""
        if use_normal_only:
            normal_indices = np.where(y == 'BENIGN')[0]
            logger.info(f"Using {len(normal_indices)} normal traffic samples for training")
            
            np.random.shuffle(normal_indices)
            split_point = int(len(normal_indices) * train_ratio)
            
            train_indices = normal_indices[:split_point]
            test_indices = np.arange(len(X))
            
            X_train = X[train_indices]
            X_test = X[test_indices]
            y_train = y[train_indices]
            y_test = y[test_indices]
        else:
            indices = np.arange(len(X))
            np.random.shuffle(indices)
            split_point = int(len(indices) * train_ratio)
            
            train_indices = indices[:split_point]
            test_indices = indices[split_point:]
            
            X_train = X[train_indices]
            X_test = X[test_indices]
            y_train = y[train_indices]
            y_test = y[test_indices]
        
        logger.info(f"Train set: {len(X_train)} samples")
        logger.info(f"Test set: {len(X_test)} samples")
        
        return X_train, X_test, y_train, y_test
    
    def normalize_features(self, X_train, X_test=None):
        """Normalize features using StandardScaler"""
        logger.info("Normalizing features...")
        
        X_train_scaled = self.scaler.fit_transform(X_train)
        
        if X_test is not None:
            X_test_scaled = self.scaler.transform(X_test)
            return X_train_scaled, X_test_scaled
        
        return X_train_scaled
    
    def get_scaler(self):
        """Return the fitted scaler for use in real-time prediction"""
        return self.scaler
