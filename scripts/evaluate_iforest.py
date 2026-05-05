# evaluate_iforest.py
# Evaluate the Isolation Forest model for false alerts (false positives on normal traffic)
# and missed detections (false negatives on attack traffic).

import pandas as pd
import numpy as np
import joblib
import os

DATASET_DIR = r"data/nsl-kdd"
TEST_FILE = os.path.join(DATASET_DIR, "KDDTest+.txt")
IFOREST_FILE = "models/iforest_model.pkl"
SCALER_FILE = "models/scaler.pkl"
RF_FILE = "models/rf_model.pkl"

FEATURE_INDICES = [0, 4, 5, 22, 23, 28, 29, 31, 32, 33, 34, 35, 37, 38]

# Index of the 'count' feature within the 14-feature vector (maps to column 22 = f_count)
COUNT_IDX = 3  # 0-based index within the 14 features

def main():
    # ── Load models ──────────────────────────────────────────────
    if not os.path.exists(IFOREST_FILE):
        print(f"Error: {IFOREST_FILE} not found. Train it first with train_model.py")
        return
    iforest = joblib.load(IFOREST_FILE)
    print(f"Loaded Isolation Forest from {IFOREST_FILE}")

    rf = None
    if os.path.exists(RF_FILE):
        rf = joblib.load(RF_FILE)
        print(f"Loaded Random Forest from {RF_FILE}")

    scaler = None
    if os.path.exists(SCALER_FILE):
        scaler = joblib.load(SCALER_FILE)
        print(f"Loaded scaler from {SCALER_FILE}")

    # ── Load test data ───────────────────────────────────────────
    if not os.path.exists(TEST_FILE):
        print(f"Error: {TEST_FILE} not found")
        return
    df = pd.read_csv(TEST_FILE, header=None)
    X_test = df.iloc[:, FEATURE_INDICES].values
    labels = df.iloc[:, 41].values  # attack name or 'normal'

    y_true = np.array([0 if l == 'normal' else 1 for l in labels])
    normal_mask = y_true == 0
    attack_mask = y_true == 1

    if scaler:
        X_scaled = scaler.transform(X_test)
    else:
        X_scaled = X_test.copy()

    print(f"\nTest set: {len(df)} samples  |  Normal: {normal_mask.sum()}  |  Attack: {attack_mask.sum()}")

    # ── Raw Isolation Forest predictions ─────────────────────────
    if_pred = iforest.predict(X_scaled)         # 1 = inlier, -1 = outlier
    if_scores = iforest.decision_function(X_scaled)  # lower = more anomalous

    anomaly_mask = if_pred == -1

    print("\n" + "=" * 60)
    print("  RAW ISOLATION FOREST RESULTS (no volume filter)")
    print("=" * 60)
    print(f"Total anomalies flagged: {anomaly_mask.sum()} / {len(df)}")

    # False Positives: IF says anomaly, but ground truth is normal
    fp_raw = anomaly_mask & normal_mask
    # True Positives: IF says anomaly, and ground truth is attack
    tp_raw = anomaly_mask & attack_mask
    # False Negatives: IF says normal, but ground truth is attack
    fn_raw = (~anomaly_mask) & attack_mask
    # True Negatives: IF says normal, and ground truth is normal
    tn_raw = (~anomaly_mask) & normal_mask

    print(f"\n  True Positives  (attacks caught):       {tp_raw.sum()}")
    print(f"  False Positives (normal flagged):        {fp_raw.sum()}  <-- FALSE ALERTS")
    print(f"  True Negatives  (normal passed):         {tn_raw.sum()}")
    print(f"  False Negatives (attacks missed):        {fn_raw.sum()}")

    fp_rate = fp_raw.sum() / max(1, normal_mask.sum()) * 100
    tp_rate = tp_raw.sum() / max(1, attack_mask.sum()) * 100
    print(f"\n  False Positive Rate (on normal):  {fp_rate:.2f}%")
    print(f"  Detection Rate (on attacks):      {tp_rate:.2f}%")

    # ── Show some false positive examples ────────────────────────
    if fp_raw.sum() > 0:
        fp_indices = np.where(fp_raw)[0]
        print(f"\n--- Sample False Positives (first 10) ---")
        print(f"{'Index':<8} {'Count':<8} {'IF Score':<12} {'Label':<15}")
        for idx in fp_indices[:10]:
            count_val = X_test[idx, COUNT_IDX]
            score = if_scores[idx]
            print(f"{idx:<8} {count_val:<8.0f} {score:<12.4f} {labels[idx]}")

    # ── With volume filter (count >= 15, matching ml_engine.py) ──
    count_vals = X_test[:, COUNT_IDX]
    volume_mask = count_vals >= 15

    print("\n" + "=" * 60)
    print("  WITH VOLUME FILTER (count >= 15, as in ml_engine.py)")
    print("=" * 60)

    filtered_anomaly = anomaly_mask & volume_mask
    fp_filtered = filtered_anomaly & normal_mask
    tp_filtered = filtered_anomaly & attack_mask

    print(f"Anomalies after volume filter: {filtered_anomaly.sum()}")
    print(f"  False Positives:  {fp_filtered.sum()}  <-- FALSE ALERTS")
    print(f"  True Positives:   {tp_filtered.sum()}")

    fp_rate_f = fp_filtered.sum() / max(1, normal_mask.sum()) * 100
    print(f"\n  Filtered False Positive Rate: {fp_rate_f:.2f}%")

    if fp_filtered.sum() > 0:
        fp_f_indices = np.where(fp_filtered)[0]
        print(f"\n--- Sample False Positives after filter (first 10) ---")
        print(f"{'Index':<8} {'Count':<8} {'IF Score':<12} {'Label':<15}")
        for idx in fp_f_indices[:10]:
            count_val = X_test[idx, COUNT_IDX]
            score = if_scores[idx]
            print(f"{idx:<8} {count_val:<8.0f} {score:<12.4f} {labels[idx]}")

    # -- With FULL pipeline simulation (RF normal -> IF anomaly) --
    if rf:
        print("\n" + "=" * 60)
        print("  FULL PIPELINE: RF says normal -> IF flags anomaly (count>=15)")
        print("=" * 60)

        if hasattr(rf, 'predict_proba'):
            rf_proba = rf.predict_proba(X_scaled)[:, 1]  # P(attack)
            rf_normal_mask = rf_proba < 0.45  # RF says normal
        else:
            rf_pred = rf.predict(X_scaled)
            rf_normal_mask = rf_pred == 0

        # Pipeline: RF says normal AND IF flags anomaly (score < -0.05) AND count >= 50
        pipeline_alert = rf_normal_mask & anomaly_mask & (count_vals >= 50) & (if_scores < -0.05)
        pipeline_fp = pipeline_alert & normal_mask
        pipeline_tp = pipeline_alert & attack_mask

        print(f"RF said normal:          {rf_normal_mask.sum()}")
        print(f"Pipeline zero-day alerts: {pipeline_alert.sum()}")
        print(f"  False Positives:        {pipeline_fp.sum()}  <-- FALSE ALERTS")
        print(f"  True Positives:         {pipeline_tp.sum()}  (real attacks RF missed, IF caught)")

        fp_rate_p = pipeline_fp.sum() / max(1, normal_mask.sum()) * 100
        print(f"\n  Pipeline False Positive Rate: {fp_rate_p:.2f}%")

        if pipeline_fp.sum() > 0:
            pf_indices = np.where(pipeline_fp)[0]
            print(f"\n--- Pipeline False Positives (first 15) ---")
            print(f"{'Index':<8} {'Count':<8} {'IF Score':<12} {'RF Prob':<10} {'Label':<15}")
            for idx in pf_indices[:15]:
                count_val = X_test[idx, COUNT_IDX]
                score = if_scores[idx]
                prob = rf_proba[idx] if hasattr(rf, 'predict_proba') else -1
                print(f"{idx:<8} {count_val:<8.0f} {score:<12.4f} {prob:<10.4f} {labels[idx]}")
        else:
            print("\n  [OK] No false positives in the full pipeline!")

        if pipeline_tp.sum() > 0:
            tp_indices = np.where(pipeline_tp)[0]
            # Show which attack types the IF is catching that RF missed
            caught_attacks = pd.Series(labels[tp_indices]).value_counts()
            print(f"\n--- Attack types caught by IF (that RF missed) ---")
            for attack_name, cnt in caught_attacks.items():
                print(f"  {attack_name}: {cnt}")

    # ── Score distribution analysis ──────────────────────────────
    print("\n" + "=" * 60)
    print("  ANOMALY SCORE DISTRIBUTION")
    print("=" * 60)
    print(f"{'Category':<20} {'Mean':<10} {'Median':<10} {'Std':<10} {'Min':<10} {'Max':<10}")
    for name, mask in [("Normal", normal_mask), ("Attack", attack_mask)]:
        scores = if_scores[mask]
        print(f"{name:<20} {scores.mean():<10.4f} {np.median(scores):<10.4f} "
              f"{scores.std():<10.4f} {scores.min():<10.4f} {scores.max():<10.4f}")

    print("\nDone.")

if __name__ == "__main__":
    main()
