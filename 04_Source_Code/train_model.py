import os
import json
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report

# ==========================================
# 1. LOAD AND PREPROCESS REAL DATA
# ==========================================
print("[*] Loading CIC-IDS2017 dataset...")
# Looks one folder back to find the dataset
dataset_path = "../05_Dataset_Inputs/CIC-IDS2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

try:
    df = pd.read_csv(dataset_path)
except FileNotFoundError:
    print(f"[-] Error: Could not find {dataset_path}.")
    exit()

print("[*] Cleaning and preprocessing data...")
df.columns = df.columns.str.strip() 
labels = df['Label']

numeric_df = df.select_dtypes(include=[np.number])
numeric_df = numeric_df.replace([np.inf, -np.inf], np.nan).fillna(0)

y = labels.apply(lambda x: 0 if x == 'BENIGN' else 1).values
X = numeric_df.values

# ==========================================
# 2. TRAIN/TEST SPLIT
# ==========================================
print(f"[*] Total valid flow records: {len(df)}")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# ==========================================
# 3. TRAIN PRIMARY MODEL (RANDOM FOREST)
# ==========================================
print("\n[*] Training A.R.T.I.S. Random Forest Classifier...")
clf = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1) 
clf.fit(X_train, y_train)

# Saves the actual model file in the current folder for Django
joblib.dump(clf, "artis_rf_model.joblib")
print("[+] Model saved to artis_rf_model.joblib for Django integration")

print("[*] Evaluating Random Forest Performance...")
y_pred = clf.predict(X_test)
rf_report = classification_report(y_test, y_pred, digits=4)
print(rf_report)

# ==========================================
# 4. TRAIN BASELINE MODEL (DECISION TREE)
# ==========================================
print("\n[*] Training Baseline Model (Decision Tree)...")
dt_baseline = DecisionTreeClassifier(random_state=42)
dt_baseline.fit(X_train, y_train)

print("[*] Evaluating Decision Tree Performance...")
y_pred_baseline = dt_baseline.predict(X_test)
dt_report = classification_report(y_test, y_pred_baseline, digits=4)
print(dt_report)

# ==========================================
# 5. EXPORT METRICS FOR UI & REPORT
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

# Saves the JSON metrics in the current folder for Django
with open("model_metrics.json", "w") as f:
    json.dump(metrics_export, f)
print("[+] model_metrics.json saved for UI integration!")

# Saves the text report one folder back into the Results folder for GitHub
output_dir = "../06_Results"
os.makedirs(output_dir, exist_ok=True) 

file_path = os.path.join(output_dir, "Model_Evaluation_Reports.txt")
with open(file_path, "w") as f:
    f.write("A.R.T.I.S. Classification Reports (Real CIC-IDS2017 Data)\n")
    f.write("====================================================\n\n")
    f.write("1. RANDOM FOREST (PRIMARY MODEL)\n")
    f.write("----------------------------------------------------\n")
    f.write(rf_report)
    f.write("\n\n")
    f.write("2. DECISION TREE (BASELINE MODEL)\n")
    f.write("----------------------------------------------------\n")
    f.write(dt_report)

print(f"[+] Realistic classification report saved to {file_path}")