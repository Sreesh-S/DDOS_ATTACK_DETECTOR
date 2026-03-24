import pandas as pd
import json

df_iter = pd.read_csv('cicids_dos_ddos_data.csv', chunksize=10000)
found_labels = set()
target_labels = ['DDoS', 'DoS GoldenEye', 'DoS Hulk', 'DoS Slowhttptest', 'DoS slowloris', 'Heartbleed', 'Normal']
payloads = {}

for chunk in df_iter:
    for label in target_labels:
        if label not in found_labels and label in chunk['Label'].values:
            row = chunk[chunk['Label'] == label].iloc[0].to_dict()
            # Remove purely identifying or non-feature columns
            row.pop('Label', None)
            row.pop('Timestamp', None)
            row.pop('Flow ID', None)
            row.pop('Source IP', None)
            row.pop('Destination IP', None)
            
            payloads[label] = row
            found_labels.add(label)
    if len(found_labels) == len(target_labels):
        break

with open('attack_payloads.json', 'w') as f:
    json.dump(payloads, f, indent=4)
print("Done extracting payloads. Found:", found_labels)
