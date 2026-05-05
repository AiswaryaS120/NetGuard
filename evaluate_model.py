import pandas as pd
import numpy as np
import joblib
import os
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report

# Dataset Path
DATASET_DIR = r"nsl-kdd"
TEST_FILE = os.path.join(DATASET_DIR, "KDDTest+.txt")
MODEL_FILE = "rf_model.pkl"

def evaluate_model():
    print(f"Loading model from {MODEL_FILE}...")
    if not os.path.exists(MODEL_FILE):
        print(f"Error: Model file {MODEL_FILE} not found. Please train the model first.")
        return

    try:
        clf = joblib.load(MODEL_FILE)
    except Exception as e:
        print(f"Error loading model: {e}")
        return

    # Load scaler
    scaler = None
    if os.path.exists("scaler.pkl"):
        scaler = joblib.load("scaler.pkl")
        print("Scaler loaded.")
    else:
        print("Warning: scaler.pkl not found. Running without scaling.")

    print(f"Loading test dataset from {TEST_FILE}...")
    if not os.path.exists(TEST_FILE):
        print(f"Error: Test file {TEST_FILE} not found.")
        return

    try:
        # Read the dataset (no header)
        df = pd.read_csv(TEST_FILE, header=None)
        
        # Same 14 features used in training and live monitoring
        feature_indices = [0, 4, 5, 22, 23, 28, 29, 31, 32, 33, 34, 35, 37, 38]
        X_test = df.iloc[:, feature_indices].values
        
        # Apply scaler if available
        if scaler:
            X_test = scaler.transform(X_test)
        
        # Binary ground truth: 'normal' -> 0, all attacks -> 1
        y_true = np.array([0 if label == 'normal' else 1 for label in df.iloc[:, 41].values])
        
        print(f"Test data shape: {X_test.shape}")
        print(f"Test distribution: Normal={np.sum(y_true == 0)}, Attack={np.sum(y_true == 1)}")
        
        print("Running predictions...")
        y_pred = clf.predict(X_test)
        
        # Calculate metrics
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, pos_label=1, zero_division=0)
        recall = recall_score(y_true, y_pred, pos_label=1, zero_division=0)
        f1 = f1_score(y_true, y_pred, pos_label=1, zero_division=0)
        conf_matrix = confusion_matrix(y_true, y_pred)
        
        print("\n--- Evaluation Results ---")
        print(f"Accuracy:  {accuracy:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall:    {recall:.4f}")
        print(f"F1 Score:  {f1:.4f}")
        
        print("\nConfusion Matrix:")
        print("                  Predicted Normal (0)   Predicted Attack (1)")
        try:
            print(f"Actual Normal  (0)       {conf_matrix[0][0]:<20} {conf_matrix[0][1]}")
            print(f"Actual Attack  (1)       {conf_matrix[1][0]:<20} {conf_matrix[1][1]}")
        except IndexError:
             print("Confusion Matrix shape mismatch:")
             print(conf_matrix)
        
        print("\nClassification Report:")
        print(classification_report(y_true, y_pred, target_names=['Normal', 'Attack']))

        # Also test with predict_proba if available
        if hasattr(clf, 'predict_proba'):
            y_proba = clf.predict_proba(X_test)[:, 1]  # Probability of attack
            print(f"\nAttack probability stats:")
            print(f"  Mean:   {y_proba.mean():.4f}")
            print(f"  Median: {np.median(y_proba):.4f}")
            print(f"  Std:    {y_proba.std():.4f}")
        
    except Exception as e:
        print(f"An error occurred during evaluation: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    evaluate_model()
