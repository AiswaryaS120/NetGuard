import joblib
import numpy as np
import os
import time
from ml_engine import AnomalyDetector

def test_ml_predictions():
    print("Initializing AnomalyDetector...")
    detector = AnomalyDetector()
    detector.start_time = time.time() - 10  # Skip warmup
    
    if not detector.model:
        print("ERROR: Model not loaded")
        return

    # Extracted from KDDTrain+.txt
    
    # Line 1: Normal
    normal_vector = [0, 491, 0, 2, 2, 1.00, 0.00, 150, 25, 0.17, 0.03, 0.17, 0.00, 0.00]
    
    # Line 3: Neptune (DoS) — high count, high serror_rate
    neptune_vector = [0, 0, 0, 123, 6, 0.05, 0.07, 255, 26, 0.10, 0.05, 0.00, 1.00, 1.00]

    print(f"\nTesting NORMAL vector: {normal_vector}")
    pred_normal = detector.predict({'ml_features': normal_vector})
    print(f"Prediction: {pred_normal}")
    
    print(f"\nTesting NEPTUNE vector (Should be attack): {neptune_vector}")
    pred_neptune = detector.predict({'ml_features': neptune_vector})
    print(f"Prediction: {pred_neptune}")

    # Verify
    normal_ok = pred_normal == 'normal'
    attack_ok = pred_neptune != 'normal'  # Any attack label is fine
    
    print(f"\n{'='*40}")
    print(f"Normal prediction:  {'PASS' if normal_ok else 'FAIL'} (got: {pred_normal})")
    print(f"Attack prediction:  {'PASS' if attack_ok else 'FAIL'} (got: {pred_neptune})")
    
    if normal_ok and attack_ok:
        print("\nSUCCESS: Model correctly identifies normal traffic and attacks.")
    else:
        print("\nFAILURE: Model predictions were incorrect.")

if __name__ == "__main__":
    test_ml_predictions()
