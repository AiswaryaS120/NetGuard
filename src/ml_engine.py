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
    def __init__(self, model_path='models/rf_model.pkl', encoder_path='models/label_encoder.pkl',
                 scaler_path='models/scaler.pkl', iforest_path='models/iforest_model.pkl'):
        self.model_path = model_path
        self.encoder_path = encoder_path
        self.scaler_path = scaler_path
        self.iforest_path = iforest_path
        self.model = None        # Random Forest (supervised)
        self.iforest = None      # Isolation Forest (unsupervised)
        self.encoder = None
        self.scaler = None
        self.start_time = time.time()
        self.load_model()

    def load_model(self):
        # --- Random Forest (known attack classification) ---
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                print(f"ML Model loaded: {self.model_path}")
            except Exception as e:
                print(f"RF model loading failed: {e}")
                self.model = None
        else:
            print("No RF model found. Using simple heuristic fallback.")

        # --- Isolation Forest (zero-day anomaly detection) ---
        if os.path.exists(self.iforest_path):
            try:
                self.iforest = joblib.load(self.iforest_path)
                print(f"Isolation Forest loaded: {self.iforest_path}")
            except Exception as e:
                print(f"Isolation Forest loading failed: {e}")
                self.iforest = None
        else:
            print("No Isolation Forest found. Zero-day detection disabled.")

        # --- Shared resources ---
        if os.path.exists(self.encoder_path):
            self.encoder = joblib.load(self.encoder_path)
            print(f"Label Encoder loaded: {self.encoder_path}")

        if os.path.exists(self.scaler_path):
            self.scaler = joblib.load(self.scaler_path)
            print(f"Scaler loaded: {self.scaler_path}")

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
                
                # Apply scaler if available
                if self.scaler:
                    X = self.scaler.transform(X)
                
                # ──────────────────────────────────────────────
                # STAGE 1: Random Forest — known attack check
                # ──────────────────────────────────────────────
                rf_label = "normal"
                attack_confidence = 0.0
                
                if hasattr(self.model, 'predict_proba'):
                    proba = self.model.predict_proba(X)[0]
                    attack_confidence = proba[1]  # P(attack)
                    
                    if attack_confidence >= 0.45:
                        count = ml_features[3]
                        srv_count = ml_features[4]
                        serror_rate = ml_features[12]
                        same_srv_rate = ml_features[5]
                        diff_srv_rate = ml_features[6]
                        
                        rf_label = self._classify_attack_type(
                            count, srv_count, serror_rate, same_srv_rate, diff_srv_rate, attack_confidence
                        )
                        
                        # Noise filter
                        threshold = 20 if rf_label == 'Port Scan' else 100
                        if count < threshold:
                            print(f"[ML DEBUG] Ignored low volume attack ({rf_label}): count={count} < threshold={threshold}. Confidence: {attack_confidence:.2f}")
                            rf_label = "normal"
                else:
                    pred = self.model.predict(X)[0]
                    if pred != 0:
                        rf_label = "DoS Attack"
                
                # ──────────────────────────────────────────────
                # STAGE 2: Isolation Forest — zero-day check
                # Only runs when RF says "normal" (no known attack)
                # ──────────────────────────────────────────────
                if rf_label != "normal":
                    # RF detected a known attack — report it
                    count = ml_features[3]
                    srv_count = ml_features[4]
                    print(f"[ML DETECTION REPORT] -----------------------\n"
                          f"  -> Prediction:  {rf_label}\n"
                          f"  -> Confidence:  {attack_confidence:.2f} (RF Certainty)\n"
                          f"  -> Total Pkts:  {count} (Recent IP activity)\n"
                          f"  -> Srv Pkts:    {srv_count}\n"
                          f"---------------------------------------------")
                    return rf_label
                
                # RF says normal — check Isolation Forest for anomaly
                if self.iforest:
                    # predict: 1 = normal (inlier), -1 = anomaly (outlier)
                    if_pred = self.iforest.predict(X)[0]
                    
                    if if_pred == -1:
                        # Anomaly score: more negative = more anomalous
                        anomaly_score = self.iforest.decision_function(X)[0]
                        count = ml_features[3]
                        
                        # Only flag as zero-day if there's meaningful traffic volume 
                        # AND the anomaly score is sufficiently negative (helps reduce false positives)
                        if count >= 50 and anomaly_score < -0.05:
                            print(f"[ZERO-DAY DETECTION] -----------------------\n"
                                  f"  -> Prediction:  Zero-Day Attack\n"
                                  f"  -> IF Score:    {anomaly_score:.4f} (lower = more anomalous)\n"
                                  f"  -> RF Conf:     {attack_confidence:.2f} (RF saw no known pattern)\n"
                                  f"  -> Total Pkts:  {count}\n"
                                  f"---------------------------------------------")
                            return "Zero-Day Attack"
                
                return "normal"
                    
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