import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib
import os

# Dataset Path
DATASET_DIR = r"nsl-kdd"
TRAIN_FILE = os.path.join(DATASET_DIR, "KDDTrain+.txt")
MODEL_FILE = "rf_model.pkl"

def get_feature_indices():
    """
    Returns the list of 0-based indices for numerical features to use.
    Using same expanded feature set as Isolation Forest attempt.
    """
    return [0, 4, 5, 22, 23, 28, 29, 31, 32, 33, 34, 35, 37, 38]

def train_supervised_model():
    if not os.path.exists(TRAIN_FILE):
        print(f"Error: Dataset file not found at {TRAIN_FILE}")
        return

    print("Loading dataset...")
    try:
        df = pd.read_csv(TRAIN_FILE, header=None)
        
        # Features
        feature_indices = get_feature_indices()
        X_train = df.iloc[:, feature_indices].values
        
        # Labels (Column 41)
        # Use simple label encoding to handle multi-class targets
        y_raw = df.iloc[:, 41].values
        
        label_encoder = LabelEncoder()
        y_train = label_encoder.fit_transform(y_raw)

        print(f"Training data shape: {X_train.shape}")
        print(f"Classes found: {list(label_encoder.classes_)}")
        
        print("Training Random Forest Classifier (Multi-class)...")
        # Random Forest is a robust supervised model
        clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        clf.fit(X_train, y_train)
        
        # Save model and encoder
        joblib.dump(clf, MODEL_FILE)
        joblib.dump(label_encoder, "label_encoder.pkl")
        print(f"Supervised Model saved to {MODEL_FILE}")
        print("Label Encoder saved to label_encoder.pkl")
        
    except Exception as e:
        print(f"An error occurred during training: {e}")

if __name__ == "__main__":
    train_supervised_model()
