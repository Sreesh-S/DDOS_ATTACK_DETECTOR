import joblib
import json
import os
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

# Create dummy features matching CICIDS2017
features = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean",
    "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
    "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size",
    "Avg Bwd Segment Size", "Fwd Header Length.1", "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets",
    "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
    "min_seg_size_forward", "Active Mean", "Active Std", "Active Max",
    "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
]

def generate_realistic_data(n_samples=200):
    # Scale ranges based on typical network traffic
    data = {
        "Destination Port": np.random.randint(0, 65535, n_samples),
        "Flow Duration": np.random.randint(100, 10000000, n_samples),
        "Total Fwd Packets": np.random.randint(1, 100, n_samples),
        "Total Backward Packets": np.random.randint(0, 100, n_samples),
        # ... generate randoms for others ...
    }
    
    # Fill remaining columns with random scaled noise
    for feat in features:
        if feat not in data:
            data[feat] = np.random.rand(n_samples) * 1000

    df = pd.DataFrame(data)
    
    # Manually inject patterns for "Normal" vs "DDoS"
    labels = []
    for i in range(n_samples):
        # Rule-based synthetic logic for demo consistency
        if i % 2 == 0:
            labels.append("Normal")
            # Make it look normal
            df.at[i, "Flow Duration"] = np.random.randint(100, 5000)
            df.at[i, "Total Fwd Packets"] = np.random.randint(1, 10)
        else:
            if np.random.rand() > 0.5:
                labels.append("DDoS")
                # DDoS characteristics
                df.at[i, "Flow Duration"] = np.random.randint(10000, 1000000)
                df.at[i, "Total Fwd Packets"] = np.random.randint(50, 500)
            else:
                labels.append("DoS Hulk")
                
    return df, labels

print("Generating realistic dummy data...")
X_train, y_train = generate_realistic_data()

print("Training Dummy Random Forest...")
clf = RandomForestClassifier(n_estimators=50, random_state=42)
clf.fit(X_train[features], y_train)

# Ensure directory exists
os.makedirs('detection/ml', exist_ok=True)

# Save features
with open('detection/ml/features.json', 'w') as f:
    json.dump(features, f)

# Save model
joblib.dump(clf, 'detection/ml/model.pkl')

print("Improved dummy model generated in detection/ml/")
