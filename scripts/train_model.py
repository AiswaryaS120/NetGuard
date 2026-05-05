import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os

# Dataset Path
DATASET_DIR = r"data/nsl-kdd"
TRAIN_FILE = os.path.join(DATASET_DIR, "KDDTrain+.txt")
MODEL_FILE = "models/iforest_model.pkl"

def get_feature_indices():
    """
    Returns the list of 0-based indices for numerical features to use.
    Same 14 features used by Random Forest and live monitoring.
    """
    return [0, 4, 5, 22, 23, 28, 29, 31, 32, 33, 34, 35, 37, 38]

def train_model():
    if not os.path.exists(TRAIN_FILE):
        print(f"Error: Dataset file not found at {TRAIN_FILE}")
        return

    print("Loading dataset...")
    try:
        df = pd.read_csv(TRAIN_FILE, header=None)
        
        # --- FILTER NORMAL TRAFFIC ONLY ---
        # Column 41 contains the attack label
        # Isolation Forest should learn what "normal" looks like
        # so it can flag anything different as a potential zero-day.
        normal_mask = df.iloc[:, 41] == 'normal'
        df_normal = df[normal_mask]
        
        print(f"Total samples: {len(df)}")
        print(f"Normal samples (used for training): {len(df_normal)}")
        print(f"Attack samples (excluded): {len(df) - len(df_normal)}")
        
        feature_indices = get_feature_indices()
        X_train = df_normal.iloc[:, feature_indices].values
        
        # --- APPLY SAME SCALER AS RANDOM FOREST ---
        # Both models must see the same scaled features
        scaler_path = "models/scaler.pkl"
        if os.path.exists(scaler_path):
            scaler = joblib.load(scaler_path)
            X_train = scaler.transform(X_train)
            print(f"Applied existing scaler from {scaler_path}")
        else:
            print("WARNING: models/scaler.pkl not found. Train Random Forest first!")
            print("         Run: python train_supervised.py")
            return
        
        print(f"\nTraining data shape: {X_train.shape}")
        
        # --- TRAIN ISOLATION FOREST ---
        # contamination='auto' lets sklearn decide the threshold
        # n_estimators=200 for robust anomaly detection
        # max_samples=256 is optimal for Isolation Forest (per original paper)
        clf = IsolationForest(
            n_estimators=200, 
            max_samples=256, 
            contamination=0.01,  # Set lower contamination to reduce false positives
            random_state=42,
            n_jobs=-1
        )
        clf.fit(X_train)
        
        # Save model
        joblib.dump(clf, MODEL_FILE)
        print(f"\nIsolation Forest saved to {MODEL_FILE}")
        print("This model will flag traffic that deviates from normal patterns")
        print("as potential zero-day attacks.")
        
    except Exception as e:
        print(f"An error occurred during training: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    train_model()

