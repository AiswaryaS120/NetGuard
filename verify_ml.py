import joblib
import numpy as np
import os
from ml_engine import AnomalyDetector

def test_ml_predictions():
    print("Initializing AnomalyDetector...")
    detector = AnomalyDetector()
    
    if not detector.model:
        print("ERROR: Model not loaded")
        return

    # Extracted from KDDTrain+.txt
    
    # Line 1: Normal
    normal_vector = [0, 491, 0, 2, 2, 1.00, 0.00, 150, 25, 0.17, 0.03, 0.17, 0.00, 0.00]
    
    # Line 3: Neptune (DoS)
    # 0,tcp,private,S0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,123,6,1.00,1.00,0.00,0.00,0.05,0.07,0.00,255,26,0.10,0.05,0.00,0.00,1.00,1.00,0.00,0.00,neptune,19
    neptune_vector = [0, 0, 0, 123, 6, 0.05, 0.07, 255, 26, 0.10, 0.05, 0.00, 1.00, 1.00]

    # Satan (Port Scan)
    # 0,udp,other,SF,146,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,13,1,0.00,0.00,0.00,0.00,0.08,0.15,0.00,255,1,0.00,0.60,0.88,0.00,0.00,0.00,0.00,0.00,normal,15
    # (Using a hypothetical satan vector based on knowledge - or just checking neptune mapping is enough for now)

    print(f"\nTesting NORMAL vector: {normal_vector}")
    pred_normal = detector.predict({'ml_features': normal_vector})
    print(f"Prediction: {pred_normal}")
    
    print(f"\nTesting NEPTUNE vector (Should be 'DoS Attack'): {neptune_vector}")
    pred_neptune = detector.predict({'ml_features': neptune_vector})
    print(f"Prediction: {pred_neptune}")

    if pred_normal == 'normal' and pred_neptune == 'DoS Attack':
        print("\nSUCCESS: Model correctly identified 'normal' and mapped 'neptune' to 'DoS Attack'.")
    else:
        print("\nFAILURE: Model predictions were incorrect.")

if __name__ == "__main__":
    test_ml_predictions()
