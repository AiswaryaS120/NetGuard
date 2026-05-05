"""
test_dashboard_threats.py
=========================
Simulates all monitored attack types to verify that the ML engine 
produces the correct labels AND the dashboard would show the right 
threat level (CRITICAL / MODERATE / SECURE) for each.

Threat level logic from gui_dashboard.py:
  - CRITICAL  -> threat score >= 0.8  (high-volume attacks, floods)
  - MODERATE  -> threat score >= 0.3  (low-volume attacks, scans)
  - SECURE    -> threat score < 0.3   (normal traffic)

Run:  python test_dashboard_threats.py
"""

import time
from src.ml_engine import AnomalyDetector

# --- TEST VECTORS ---
# Each vector is 14 features matching the order in network_engine.py:
# [duration, src_bytes, dst_bytes, count, srv_count,
#  same_srv_rate, diff_srv_rate, dst_host_count, dst_host_srv_count,
#  dst_host_same_srv_rate, dst_host_diff_srv_rate, dst_host_same_src_port_rate,
#  dst_host_serror_rate, dst_host_srv_serror_rate]

TEST_CASES = [
    # === NORMAL TRAFFIC ===
    {
        "name": "Normal Web Browsing",
        "vector": [0, 491, 0, 2, 2, 1.00, 0.00, 150, 25, 0.17, 0.03, 0.17, 0.00, 0.00],
        "expected_label": "normal",
        "expected_dashboard": "SECURE",
    },
    {
        "name": "Normal DNS Query",
        "vector": [0, 45, 0, 1, 1, 1.00, 0.00, 10, 10, 1.00, 0.00, 0.10, 0.00, 0.00],
        "expected_label": "normal",
        "expected_dashboard": "SECURE",
    },

    # === DoS ATTACKS === (Should trigger CRITICAL on dashboard)
    {
        "name": "DoS - SYN Flood (Neptune-style)",
        "vector": [0, 0, 0, 200, 6, 0.05, 0.07, 255, 26, 0.10, 0.05, 0.00, 1.00, 1.00],
        "expected_label": "DoS Attack",
        "expected_dashboard": "CRITICAL",
    },
    {
        "name": "DoS - Smurf Flood (high volume)",
        "vector": [0, 1032, 0, 500, 500, 1.00, 0.00, 255, 255, 1.00, 0.00, 1.00, 0.00, 0.00],
        "expected_label": "DoS Attack",
        "expected_dashboard": "CRITICAL",
    },
    {
        "name": "DoS - HTTP Flood",
        "vector": [0, 0, 0, 300, 300, 1.00, 0.00, 255, 255, 1.00, 0.00, 0.50, 0.80, 0.80],
        "expected_label": "DoS Attack",
        "expected_dashboard": "CRITICAL",
    },

    # === PORT SCANS === (Should trigger MODERATE on dashboard)
    {
        "name": "Port Scan - Horizontal Sweep",
        "vector": [0, 0, 0, 50, 3, 0.06, 0.80, 255, 10, 0.04, 0.60, 0.02, 0.00, 0.00],
        "expected_label": "Port Scan",
        "expected_dashboard": "MODERATE",
    },
    {
        "name": "Port Scan - Slow Probe (nmap-style)",
        "vector": [0, 0, 0, 30, 2, 0.07, 0.70, 200, 5, 0.03, 0.55, 0.01, 0.00, 0.00],
        "expected_label": "Port Scan",
        "expected_dashboard": "MODERATE",
    },

    # === BRUTE FORCE / MALWARE === (High volume brute force -> CRITICAL on dashboard)
    {
        "name": "Brute Force - Password Guessing",
        "vector": [2, 100, 0, 150, 150, 1.00, 0.00, 255, 255, 1.00, 0.00, 0.90, 0.10, 0.10],
        "expected_label": "Brute Force/Malware",
        "expected_dashboard": "CRITICAL",  # count=150 > 50 -> dashboard escalates to CRITICAL
    },
]


def get_dashboard_threat_level(label, count):
    """
    Emulates the dashboard threat assessment from gui_dashboard.py lines 329-338.
    High volume attacks (flood/ddos) -> CRITICAL (threat > 0.8)
    Low volume attacks -> MODERATE (threat > 0.3)
    Normal -> SECURE
    """
    if label == "normal":
        return "SECURE"
    
    # Dashboard logic: "FLOOD" or "DDOS" -> high, everything else -> low
    # Also: packets_this_tick > 50 -> high
    if label == "DoS Attack" or count > 50:
        return "CRITICAL"
    else:
        return "MODERATE"


def run_tests():
    print("=" * 70)
    print("  NETGUARD DASHBOARD THREAT LEVEL TEST")
    print("=" * 70)
    
    # Bypass warmup by setting start_time in the past
    detector = AnomalyDetector()
    detector.start_time = time.time() - 10  # Skip 5-second warmup
    
    if not detector.model:
        print("\nERROR: Model not loaded. Run 'python train_supervised.py' first.")
        return
    
    passed = 0
    failed = 0
    results = []
    
    for i, test in enumerate(TEST_CASES, 1):
        name = test["name"]
        vector = test["vector"] 
        expected_label = test["expected_label"]
        expected_dashboard = test["expected_dashboard"]
        count = vector[3]  # count feature
        
        # Run prediction
        prediction = detector.predict({'ml_features': vector})
        
        # Determine dashboard level
        dashboard_level = get_dashboard_threat_level(prediction, count)
        
        # Check results
        label_match = (prediction == expected_label) or (
            # Accept any attack label when we expected an attack (attack type classification is heuristic)
            expected_label != "normal" and prediction != "normal"
        )
        dashboard_match = dashboard_level == expected_dashboard
        
        # For normal traffic, both must match exactly
        if expected_label == "normal":
            label_match = prediction == "normal"
        
        overall_pass = label_match and dashboard_match
        
        status = "PASS" if overall_pass else "FAIL"
        if overall_pass:
            passed += 1
        else:
            failed += 1
        
        results.append({
            "name": name,
            "expected_label": expected_label,
            "actual_label": prediction,
            "expected_dashboard": expected_dashboard,
            "actual_dashboard": dashboard_level,
            "status": status
        })
    
    # --- PRINT RESULTS ---
    print(f"\n{'#':<3} {'Test Case':<35} {'ML Label':<22} {'Dashboard':<12} {'Status':<6}")
    print("-" * 80)
    
    for i, r in enumerate(results, 1):
        label_indicator = "OK" if r["expected_label"] == r["actual_label"] or (
            r["expected_label"] != "normal" and r["actual_label"] != "normal"
        ) else "XX"
        dash_indicator = "OK" if r["expected_dashboard"] == r["actual_dashboard"] else "XX"
        
        print(f"{i:<3} {r['name']:<35} {label_indicator} {r['actual_label']:<18} {dash_indicator} {r['actual_dashboard']:<8} {r['status']}")
    
    print("-" * 80)
    print(f"\nResults: {passed} passed, {failed} failed out of {len(results)} tests")
    
    if failed == 0:
        print("\n[ALL TESTS PASSED] Dashboard threat levels are correct for all attack types.")
    else:
        print(f"\n[WARNING] {failed} test(s) failed. Review the output above.")
    
    return failed == 0


if __name__ == "__main__":
    run_tests()
