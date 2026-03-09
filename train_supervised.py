import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import cross_val_score
import joblib
import os

# Dataset Path
DATASET_DIR = r"nsl-kdd"
TRAIN_FILE = os.path.join(DATASET_DIR, "KDDTrain+.txt")
MODEL_FILE = "rf_model.pkl"

def get_feature_indices():
    """
    Returns the list of 0-based indices for numerical features to use.
    Same 14 features used in live monitoring (network_engine.py).
    """
    return [0, 4, 5, 22, 23, 28, 29, 31, 32, 33, 34, 35, 37, 38]

def train_supervised_model():
    if not os.path.exists(TRAIN_FILE):
        print(f"Error: Dataset file not found at {TRAIN_FILE}")
        return

    print("Loading dataset...")
    try:
        df = pd.read_csv(TRAIN_FILE, header=None)
        
        # Features — same 14 used by the live sniffer
        feature_indices = get_feature_indices()
        X_train = df.iloc[:, feature_indices].values
        
        # --- BINARY LABELS ---
        # Column 41 contains the attack label
        # Binary: 'normal' -> 0, all attacks -> 1
        y_raw = df.iloc[:, 41].values
        y_train = np.array([0 if label == 'normal' else 1 for label in y_raw])

        print(f"Training data shape: {X_train.shape}")
        print(f"Class distribution: Normal={np.sum(y_train == 0)}, Attack={np.sum(y_train == 1)}")
        
        # --- FEATURE SCALING ---
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        
        print("Training Random Forest Classifier (Binary, Tuned)...")
        clf = RandomForestClassifier(
            n_estimators=300,          # more trees for better generalisation
            max_depth=25,              # prevent overfitting on noise
            min_samples_split=5,       # require meaningful splits
            min_samples_leaf=2,        # no single-sample leaves
            class_weight='balanced',   # handle NSL-KDD class imbalance
            random_state=42,
            n_jobs=-1
        )
        clf.fit(X_train_scaled, y_train)
        
        # --- CROSS-VALIDATION ---
        print("Running 5-fold cross-validation...")
        cv_scores = cross_val_score(clf, X_train_scaled, y_train, cv=5, scoring='accuracy', n_jobs=-1)
        print(f"CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
        
        # Train accuracy
        train_acc = clf.score(X_train_scaled, y_train)
        print(f"Train Accuracy: {train_acc:.4f}")
        
        # Feature importance ranking
        feature_names = [
            'duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count',
            'same_srv_rate', 'diff_srv_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_serror_rate', 'dst_host_srv_serror_rate'
        ]
        importances = clf.feature_importances_
        sorted_idx = np.argsort(importances)[::-1]
        print("\nTop Feature Importances:")
        for i in range(min(5, len(sorted_idx))):
            idx = sorted_idx[i]
            print(f"  {feature_names[idx]}: {importances[idx]:.4f}")
        
        # --- SAVE ---
        joblib.dump(clf, MODEL_FILE)
        joblib.dump(scaler, "scaler.pkl")
        print(f"\nModel saved to {MODEL_FILE}")
        print("Scaler saved to scaler.pkl")
        
        # Also save a label encoder for backward compatibility with ml_engine.py
        # Binary: classes are [0='normal', 1='attack']
        label_encoder = LabelEncoder()
        label_encoder.classes_ = np.array(['normal', 'attack'])
        joblib.dump(label_encoder, "label_encoder.pkl")
        print("Label Encoder saved to label_encoder.pkl")
        
    except Exception as e:
        print(f"An error occurred during training: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    train_supervised_model()
