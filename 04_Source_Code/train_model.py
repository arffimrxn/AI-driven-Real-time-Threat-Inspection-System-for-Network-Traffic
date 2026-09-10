import os
import json
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report

# Get the directory where this script is located (04_Source_Code)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ==========================================
# 1. LOAD AND PREPROCESS REAL DATA
# ==========================================
print("[*] Loading CIC-IDS2017 dataset...")
dataset_path = os.path.join(BASE_DIR, "../05_Dataset_Inputs/CIC-IDS2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

try:
    df = pd.read_csv(dataset_path)
except FileNotFoundError:
    print(f"[-] Error: Could not find {dataset_path}.")
    exit()

print("[*] Cleaning and preprocessing data...")
# Clean up messy column headers
df.columns = df.columns.str.strip() 

# 1. Dynamically find the Protocol column (case-insensitive)
protocol_col = next((c for c in df.columns if 'protocol' in c.lower()), None)
if protocol_col:
    df['Protocol_Encoded'] = df[protocol_col].fillna(0)
else:
    print("[-] Warning: Protocol column not found. Defaulting to 0.")
    df['Protocol_Encoded'] = 0

# 2. Dynamically find the Length column (case-insensitive)
length_col = next((c for c in df.columns if 'length of fwd' in c.lower() or 'fwd packet length' in c.lower()), None)
if length_col:
    df['Packet_Length'] = df[length_col].fillna(0)
else:
    print("[-] Warning: Length column not found. Defaulting to 64.")
    df['Packet_Length'] = 64

# 3. Create our new X containing ONLY the 2 features we can easily extract from a PCAP
X = df[['Packet_Length', 'Protocol_Encoded']].values

# 4. Extract Labels
label_col = next((c for c in df.columns if 'label' in c.lower()), None)
if label_col:
    y = df[label_col].apply(lambda x: 0 if x == 'BENIGN' else 1).values
else:
    print("[-] Fatal Error: Could not find 'Label' column to train the model!")
    exit()

# ==========================================
# 2. TRAIN/TEST SPLIT
# ==========================================
print(f"[*] Total valid flow records: {len(df)}")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# ==========================================
# 3. TRAIN PRIMARY MODEL (RANDOM FOREST)
# ==========================================
print("\n[*] Training Primary Random Forest Classifier...")
clf = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1) 
clf.fit(X_train, y_train)

# Saves the actual model file in the correct folder for Django
model_path = os.path.join(BASE_DIR, "threat_detector_rf.joblib")
joblib.dump(clf, model_path)
print("[+] Model saved to threat_detector_rf.joblib for Django integration")

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

# Saves the JSON metrics in the exact directory of this script (04_Source_Code)
metrics_path = os.path.join(BASE_DIR, "model_metrics.json")
with open(metrics_path, "w") as f:
    json.dump(metrics_export, f)
print("[+] model_metrics.json saved for UI integration!")

# Saves the text report one folder back into the Results folder for GitHub
output_dir = os.path.join(BASE_DIR, "../06_Results")
os.makedirs(output_dir, exist_ok=True) 

file_path = os.path.join(output_dir, "Model_Evaluation_Reports.txt")
with open(file_path, "w") as f:
    f.write("Threat Inspection System Classification Reports (Real CIC-IDS2017 Data)\n")
    f.write("======================================================================\n\n")
    f.write("1. RANDOM FOREST (PRIMARY MODEL)\n")
    f.write("----------------------------------------------------\n")
    f.write(rf_report)
    f.write("\n\n")
    f.write("2. DECISION TREE (BASELINE MODEL)\n")
    f.write("----------------------------------------------------\n")
    f.write(dt_report)

print(f"[+] Realistic classification report saved to {file_path}")