import joblib
import pandas as pd
from ml_engine import AnomalyDetector

def debug_model():
    print("Loading Random Forest Model...")
    detector = AnomalyDetector(model_path='rf_model.pkl')
    
    if not detector.model:
        print("[-] Model not found.")
        return

    # Simulate features for a flooding scenario
    # Features: [duration, src_bytes, dst_bytes, count, srv_count, ...]
    
    # Scene 1: Normal-ish (1 packet in 2s)
    feat_normal = [0, 60, 0, 1, 1, 1.0, 0.0, 1, 1, 1.0, 0.0, 1.0, 0.0, 0.0]
    
    # Scene 2: FLOOD! (200 packets in 2s)
    # NSL-KDD 'count' feature can go high during DoS.
    # Note: src_bytes might be small (SYN flood).
    feat_flood = [0, 40, 0, 200, 200, 1.0, 0.0, 200, 200, 1.0, 0.0, 1.0, 0.0, 0.0]
    
    # Scene 3: Port Scan (High count, different ports/services -> low srv_rate)
    feat_scan = [0, 40, 0, 100, 1, 0.01, 0.99, 100, 1, 0.01, 0.99, 0.0, 0.0, 0.0]

    print("\n--- DEBUG PREDICTIONS ---")
    
    pred_norm = detector.predict({'ml_features': feat_normal})
    print(f"Normal Features: Prediction = {pred_norm} ({'Normal' if pred_norm==1 else 'ANOMALY'})")
    
    pred_flood = detector.predict({'ml_features': feat_flood})
    print(f"Flood Features:  Prediction = {pred_flood} ({'Normal' if pred_flood==1 else 'ANOMALY'})")
    
    pred_scan = detector.predict({'ml_features': feat_scan})
    print(f"Scan Features:   Prediction = {pred_scan} ({'Normal' if pred_scan==1 else 'ANOMALY'})")

if __name__ == "__main__":
    debug_model()
