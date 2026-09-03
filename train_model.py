import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

# 1. Create basic training data (Packet_Length, Protocol_Encoded)
# Protocol mapping: TCP=0, UDP=1, DNS=2, ICMP=3
X_train = pd.DataFrame({
    'Packet_Length': [64, 1200, 1500, 40, 80, 2500],
    'Protocol_Encoded': [0, 0, 1, 3, 2, 0] 
})

# 0 = Benign Traffic, 1 = Threat (e.g., large payloads)
y_train = [0, 1, 1, 0, 0, 1] 

# 2. Train the Random Forest Classifier
print("Training A.R.T.I.S. Random Forest model...")
clf = RandomForestClassifier(n_estimators=50, random_state=42)
clf.fit(X_train, y_train)

# 3. Overwrite the empty file with the trained model
joblib.dump(clf, 'threat_detector_rf.joblib')
print("[+] threat_detector_rf.joblib generated successfully!")