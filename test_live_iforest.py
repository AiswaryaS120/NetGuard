import joblib
import numpy as np

def main():
    scaler = joblib.load("scaler.pkl")
    iforest = joblib.load("iforest_model.pkl")

    print(f"Loaded Scaler & IForest")
    print(f"{'Count':<8} {'SameSrv%':<10} {'Srv%':<10} {'IF Score':<10} {'Prediction':<10}")
    print("-" * 50)

    # Simulate typical live traffic volumes: an HTTP download
    # Our live features:
    # 0 f_duration = 0.0
    # 1 f_src_bytes = 1400  (typical MTU)
    # 2 f_dst_bytes = 0.0   (we don't track stateful replies yet)
    # 3 f_count = scales from 1 to 500
    # 4 f_srv_count = same as f_count (user hitting one service)
    # 5 f_same_srv_rate = 1.0
    # 6 f_diff_srv_rate = 0.0
    # 7 f_dst_host_count = sum
    # 8 f_dst_host_srv_count = sum
    # 9 f_dst_host_same_srv_rate = 1.0
    # 10 f_dst_host_diff_srv_rate = 0.0
    # 11 f_dst_host_same_src_port_rate = 1.0 (approximated)
    # 12 f_dst_host_serror_rate = 0.0 (normal traffic)
    # 13 f_dst_host_srv_serror_rate = 0.0

    for count in [1, 10, 50, 100, 300, 500, 1000]:
        vector = [
            0.0,    # duration
            1400.0, # src_bytes
            0.0,    # dst_bytes
            count,  # count
            count,  # srv_count
            1.0,    # same_srv_rate
            0.0,    # diff_srv_rate
            count,  # dst_host_count
            count,  # dst_host_srv_count
            1.0,    # dst_host_same_srv_rate
            0.0,    # dst_host_diff_srv_rate
            1.0,    # same_src_port_rate
            0.0,    # serror_rate
            0.0     # srv_serror_rate
        ]
        
        X = np.array([vector])
        X_scaled = scaler.transform(X)
        score = iforest.decision_function(X_scaled)[0]
        pred = iforest.predict(X_scaled)[0]
        
        print(f"{count:<8} {1.0:<10} {1.0:<10} {score:<10.4f} {pred:<10}")

    print("\nSimulating a port scan (many single packets to different ports):")
    for count in [10, 50, 100, 300]:
        vector = [
            0.0,    # duration
            60.0,   # src_bytes (small SYN)
            0.0,    # dst_bytes
            count,  # count
            1,      # srv_count (each is different)
            1.0 / count, # same_srv_rate
            1.0 - (1.0/count), # diff_srv_rate
            count,  # dst_host_count
            1,      # dst_host_srv_count
            1.0 / count, # dst_host_same_srv_rate
            1.0 - (1.0/count), # dst_host_diff_srv_rate
            1.0,    # same_src_port_rate
            0.0,    # serror_rate (assume no SYN errors for simple test)
            0.0     # srv_serror_rate
        ]
        X = np.array([vector])
        X_scaled = scaler.transform(X)
        score = iforest.decision_function(X_scaled)[0]
        pred = iforest.predict(X_scaled)[0]
        
        print(f"{count:<8} {'Scannng':<10} {'diff':<10} {score:<10.4f} {pred:<10}")

if __name__ == "__main__":
    main()
