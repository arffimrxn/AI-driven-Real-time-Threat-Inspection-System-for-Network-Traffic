import pandas as pd
import numpy as np
import joblib
import json
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# 1. Load your CIC-IDS2017 CSV here (Using a synthetic robust dataset for demonstration)
np.random.seed(42)
n_samples = 5000
# Features: [Packet_Length, Protocol_Encoded]
X = np.random.randint(20, 1500, size=(n_samples, 2))
X[:, 1] = np.random.randint(0, 5, size=(n_samples,))
# Labels: Flag large packets on unexpected protocols as threats
y = np.where((X[:, 0] > 1200) & (X[:, 1] != 0), 1, 0)

# 2. Split into Training and Evaluation sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# 3. Train Model
print("[*] Training A.R.T.I.S. Random Forest Classifier...")
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# 4. Generate Academic Evaluation Metrics
print("\n[*] Evaluating Model Performance...")
y_pred = clf.predict(X_test)
print(f"Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
print(f"Precision: {precision_score(y_test, y_pred, average='weighted', zero_division=0):.4f}")
print(f"Recall:    {recall_score(y_test, y_pred, average='weighted', zero_division=0):.4f}")
print(f"F1-Score:  {f1_score(y_test, y_pred, average='weighted', zero_division=0):.4f}")

import json
from sklearn.tree import DecisionTreeClassifier


# ==========================================
# BASELINE EVALUATION (DECISION TREE)
# ==========================================
print("\n[*] Training Baseline Model (Decision Tree)...")
dt_baseline = DecisionTreeClassifier(random_state=42)
dt_baseline.fit(X_train, y_train)

y_pred_baseline = dt_baseline.predict(X_test)
print("--- Baseline Metrics (Decision Tree) ---")
print(f"Accuracy:  {accuracy_score(y_test, y_pred_baseline):.4f}")
print(f"Precision: {precision_score(y_test, y_pred_baseline, average='weighted', zero_division=0):.4f}")
print(f"Recall:    {recall_score(y_test, y_pred_baseline, average='weighted', zero_division=0):.4f}")
print(f"F1-Score:  {f1_score(y_test, y_pred_baseline, average='weighted', zero_division=0):.4f}")

# ==========================================
# EXPORT METRICS FOR UI
# ==========================================
metrics_export = {
    "random_forest": {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred, average='weighted', zero_division=0), 4),
        "recall": round(recall_score(y_test, y_pred, average='weighted', zero_division=0), 4),
        "f1_score": round(f1_score(y_test, y_pred, average='weighted', zero_division=0), 4)
    },
    "baseline": {
        "accuracy": round(accuracy_score(y_test, y_pred_baseline), 4),
        "precision": round(precision_score(y_test, y_pred_baseline, average='weighted', zero_division=0), 4),
        "recall": round(recall_score(y_test, y_pred_baseline, average='weighted', zero_division=0), 4),
        "f1_score": round(f1_score(y_test, y_pred_baseline, average='weighted', zero_division=0), 4)
    }
}

with open("model_metrics.json", "w") as f:
    json.dump(metrics_export, f)
print("\n[+] model_metrics.json saved for dual UI integration!")