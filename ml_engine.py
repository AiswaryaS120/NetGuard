# ml_engine.py
import joblib
import os
import numpy as np
import time

# Attack Type Mappings using generic names as requested
ATTACK_MAPPING = {
    # Denial of Service (DoS)
    'neptune': 'DoS Attack', 'back': 'DoS Attack', 'land': 'DoS Attack', 
    'pod': 'DoS Attack', 'smurf': 'DoS Attack', 'teardrop': 'DoS Attack',
    'mailbomb': 'DoS Attack', 'apache2': 'DoS Attack', 'processtable': 'DoS Attack',
    'udpstorm': 'DoS Attack', 'worm': 'DoS Attack',

    # Probing / Port Scans
    'satan': 'Port Scan', 'ipsweep': 'Port Scan', 'nmap': 'Port Scan', 
    'portsweep': 'Port Scan', 'mscan': 'Port Scan', 'saint': 'Port Scan',

    # Malware / Remote Access (R2L)
    'guess_passwd': 'Brute Force/Malware', 'ftp_write': 'Brute Force/Malware', 
    'imap': 'Brute Force/Malware', 'phf': 'Brute Force/Malware', 
    'multihop': 'Brute Force/Malware', 'warezmaster': 'Brute Force/Malware', 
    'warezclient': 'Brute Force/Malware', 'spy': 'Brute Force/Malware', 
    'xlock': 'Brute Force/Malware', 'xsnoop': 'Brute Force/Malware', 
    'snmpevents': 'Brute Force/Malware', 'snmpgetattack': 'Brute Force/Malware', 
    'httptunnel': 'Brute Force/Malware', 'sendmail': 'Brute Force/Malware', 
    'named': 'Brute Force/Malware',

    # Privilege Escalation (U2R)
    'buffer_overflow': 'Privilege Escalation', 'loadmodule': 'Privilege Escalation', 
    'rootkit': 'Privilege Escalation', 'perl': 'Privilege Escalation', 
    'sqlattack': 'Privilege Escalation', 'xterm': 'Privilege Escalation', 
    'ps': 'Privilege Escalation',
    
    # Normal
    'normal': 'normal'
}

class AnomalyDetector:
    def __init__(self, model_path='rf_model.pkl', encoder_path='label_encoder.pkl'):
        self.model_path = model_path
        self.encoder_path = encoder_path
        self.model = None
        self.encoder = None
        self.start_time = time.time()  # Track initialization time
        self.load_model()

    def load_model(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                print(f"ML Model loaded: {self.model_path}")
                
                if os.path.exists(self.encoder_path):
                    self.encoder = joblib.load(self.encoder_path)
                    print(f"Label Encoder loaded: {self.encoder_path}")
            except Exception as e:
                print(f"Model loading failed: {e}")
                self.model = None
        else:
            print("No ML model found. Using simple heuristic fallback.")

    def predict(self, features_dict):
        # Warmup Phase: Ignore first 5 seconds to allow buffers to fill and stabilize
        if time.time() - self.start_time < 5.0:
            return "normal"

        ml_features = features_dict.get('ml_features', [])

        if len(ml_features) != 14:
            print(f"Warning: Expected 14 features, got {len(ml_features)}")
            return self.simple_heuristic(ml_features)

        if self.model:
            try:
                X = np.array([ml_features])
                pred_idx = self.model.predict(X)[0]
                
                if self.encoder:
                    specific_label = self.encoder.inverse_transform([pred_idx])[0]
                    # Map to generic category
                    generic_label = ATTACK_MAPPING.get(specific_label, f"Unknown ({specific_label})")
                    
                    # --- SAFETY THRESHOLD ---
                    count = ml_features[3]
                    
                    # Debug logic for visibility
                    if generic_label != 'normal':
                        status = "ALARM"
                        # Dynamic Threshold Logic
                        # Port Scans are low volume -> Trigger at 20
                        # Floods are high volume -> Trigger at 100
                        thresh = 20 if generic_label == 'Port Scan' else 100
                        
                        if count < thresh: status = f"SUPPRESSED (<{thresh})"
                        # print(f"[ML ENGINE] Model identified: {generic_label} | Count: {count}/2s | Action: {status}")

                    # Filter out noise
                    threshold = 20 if generic_label == 'Port Scan' else 100
                    if generic_label in ['DoS Attack', 'Port Scan', 'Brute Force/Malware', 'Privilege Escalation'] and count < threshold:
                         return "normal"
                    print(f"[ML] count={count}, label={generic_label}")

                    return generic_label
                else:
                    return pred_idx
            except Exception as e:
                print(f"[ML ERROR] Model prediction failed (using fallback): {e}")
                return self.simple_heuristic(ml_features)
        else:
            return self.simple_heuristic(ml_features)

    def simple_heuristic(self, features):
        if not features or len(features) < 4:
            return "normal"
        count = features[3]          # f_count
        srv_count = features[4]      # f_srv_count
        
        # Tuned Heuristic for lower volume tests
        # Original: count > 80
        if count > 20 or (count > 10 and srv_count / count < 0.15):
            # print(f"[ML HEURISTIC] Fallback detected DoS! (Count: {count})")
            return "DoS Attack"
        return "normal"