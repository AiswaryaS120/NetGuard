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
    def __init__(self, model_path='rf_model.pkl', encoder_path='label_encoder.pkl', scaler_path='scaler.pkl'):
        self.model_path = model_path
        self.encoder_path = encoder_path
        self.scaler_path = scaler_path
        self.model = None
        self.encoder = None
        self.scaler = None
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
                    
                if os.path.exists(self.scaler_path):
                    self.scaler = joblib.load(self.scaler_path)
                    print(f"Scaler loaded: {self.scaler_path}")
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
                
                # Apply scaler if available (effectively zero-cost: single multiply-subtract on 14 values)
                if self.scaler:
                    X = self.scaler.transform(X)
                
                # --- Binary model with confidence ---
                # predict_proba gives [P(normal), P(attack)]
                if hasattr(self.model, 'predict_proba'):
                    proba = self.model.predict_proba(X)[0]
                    attack_confidence = proba[1]  # P(attack)
                    
                    # Only flag as attack if confidence > 0.45 (balanced: high precision allows lower threshold)
                    if attack_confidence < 0.45:
                        return "normal"
                    
                    # It's an attack — now classify what type using heuristics
                    count = ml_features[3]           # feature index 3 = count
                    srv_count = ml_features[4]       # feature index 4 = srv_count
                    serror_rate = ml_features[12]     # dst_host_serror_rate
                    same_srv_rate = ml_features[5]   # same_srv_rate
                    diff_srv_rate = ml_features[6]   # diff_srv_rate
                    
                    # --- Attack type classification via feature patterns ---
                    generic_label = self._classify_attack_type(
                        count, srv_count, serror_rate, same_srv_rate, diff_srv_rate, attack_confidence
                    )
                    
                    # --- NOISE FILTER ---
                    # Suppress low-volume detections to reduce false positives in live monitoring
                    threshold = 20 if generic_label == 'Port Scan' else 100
                    if count < threshold:
                        return "normal"
                    
                    print(f"[ML] count={count}, label={generic_label}, confidence={attack_confidence:.2f}")
                    return generic_label
                else:
                    # Fallback: simple predict without proba
                    pred = self.model.predict(X)[0]
                    return "normal" if pred == 0 else "DoS Attack"
                    
            except Exception as e:
                print(f"[ML ERROR] Model prediction failed (using fallback): {e}")
                return self.simple_heuristic(ml_features)
        else:
            return self.simple_heuristic(ml_features)

    def _classify_attack_type(self, count, srv_count, serror_rate, same_srv_rate, diff_srv_rate, confidence):
        """
        Given that the binary model flagged this as an attack, use feature patterns
        to determine the specific attack category. This replaces the old label_encoder
        approach and is more robust for live traffic.
        """
        # High serror_rate + high count = DoS (SYN flood pattern)
        if serror_rate > 0.5 and count > 50:
            return "DoS Attack"
        
        # Many different services to same host = Port Scan
        if diff_srv_rate > 0.5 and count > 10:
            return "Port Scan"
        
        # Low srv_count relative to count = scanning behavior
        if count > 15 and srv_count < count * 0.2:
            return "Port Scan"
        
        # Brute force pattern: same service repeatedly, low serror, moderate count
        if same_srv_rate > 0.8 and serror_rate < 0.3 and count < 300:
            return "Brute Force/Malware"
        
        # Very high count + same service = DoS flood
        if count > 300 and same_srv_rate > 0.8:
            return "DoS Attack"
        
        # Very high confidence + high count = likely DoS
        if confidence > 0.85 and count > 100:
            return "DoS Attack"
        
        # Moderate confidence = possible brute force / malware
        if confidence > 0.5 and count > 10:
            return "Brute Force/Malware"
        
        # Catch-all for detected attacks
        return "DoS Attack"

    def simple_heuristic(self, features):
        if not features or len(features) < 4:
            return "normal"
        count = features[3]          # f_count
        srv_count = features[4]      # f_srv_count
        
        # Tuned Heuristic for lower volume tests
        if count > 20 or (count > 10 and srv_count / count < 0.15):
            return "DoS Attack"
        return "normal"