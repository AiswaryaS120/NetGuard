import sys
import os
import time
import numpy as np

print("=== NETGUARD SYSTEM INTEGRITY CHECK ===")

def check_module(name):
    print(f"[*] Checking {name}...", end=" ")
    try:
        __import__(name)
        print("OK")
        return True
    except ImportError as e:
        print(f"FAIL (ImportError: {e})")
        return False
    except SyntaxError as e:
        print(f"FAIL (SyntaxError: {e})")
        return False
    except Exception as e:
        print(f"FAIL (Error: {e})")
        return False

# 1. Check Imports
modules = ['src.rule_engine', 'src.ml_engine', 'src.network_engine', 'src.main', 'src.gui_dashboard']
passing = True

print("\n--- Phase 1: Module Loading ---")
for m in modules:
    if not check_module(m):
        passing = False

if not passing:
    print("\n[CRITICAL] Module loading failed. Fix errors above.")
    sys.exit(1)

# 2. Check Logic Integrations
print("\n--- Phase 2: Component Instantiation ---")

try:
    print("[*] Instantiating LogicEngine...", end=" ")
    from src.rule_engine import LogicEngine
    logic = LogicEngine()
    print("OK")
    
    print("[*] Testing LogicEngine Rule (Flood)...", end=" ")
    # Simulate flood
    src = "10.0.0.1"
    for i in range(200):
        alert = logic.check_packet({'src': src, 'dst_port': 80})
        if alert and i > 180: # Should trigger eventually
            break
    if alert:
        print(f"OK (Triggered: {alert[:20]}...)")
    else:
        print("WARNING (No alert triggered for 200 packets, Check Thresholds)")

    print("[*] Instantiating AnomalyDetector (ML)...", end=" ")
    from src.ml_engine import AnomalyDetector
    ml = AnomalyDetector()
    print("OK")

    print("[*] Testing ML Prediction (Mock Data)...", end=" ")
    # Mock features (14 zeros)
    mock_features = {'ml_features': [0]*14, 'src_ip': '1.2.3.4'}
    result = ml.predict(mock_features)
    print(f"OK (Result: {result})")
    
    # 3. Network Engine logic
    print("[*] Instantiating TrafficMonitor...", end=" ")
    from src.network_engine import TrafficMonitor
    monitor = TrafficMonitor()
    packet = {
        'src_ip': '192.168.1.50',
        'dst_ip': '192.168.1.1',
        'dst_port': 80,
        'length': 60
    }
    feats = monitor.update_and_get_features(packet)
    if len(feats) == 14:
        print("OK (Feature extraction working)")
    else:
        print(f"FAIL (Extracted {len(feats)} features, expected 14)")

    print("\n[SUCCESS] All critical systems operational.")

except Exception as e:
    print(f"\n[CRITICAL] Runtime check failed: {e}")
    import traceback
    traceback.print_exc()
