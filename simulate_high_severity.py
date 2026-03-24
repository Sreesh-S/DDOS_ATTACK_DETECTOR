import requests
import time
import json
import logging

# Set up basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# This must point to the detector machine's API
API_URL = "http://10.115.17.46:8000/api/predict/"

# Loading exact attack payloads directly from the dataset that trained the model
HULK_PAYLOAD = {
    "Destination Port": 80,
    "Source IP": "10.115.17.99", # Simulated Attacker
    "Flow Duration": 1878,
    "Total Fwd Packets": 3,
    "Total Backward Packets": 6,
    "Total Length of Fwd Packets": 382,
    "Total Length of Bwd Packets": 11595,
    "Fwd Packet Length Max": 382,
    "Fwd Packet Length Min": 0,
    "Fwd Packet Length Mean": 127.3333333,
    "Fwd Packet Length Std": 220.5478028,
    "Bwd Packet Length Max": 4355,
    "Bwd Packet Length Min": 0,
    "Bwd Packet Length Mean": 1932.5,
    "Bwd Packet Length Std": 2182.468304,
    "Flow Bytes/s": 6377529.286,
    "Flow Packets/s": 4792.332268,
    "Flow IAT Mean": 234.75,
    "Flow IAT Std": 229.1298758,
    "Flow IAT Max": 577,
    "Flow IAT Min": 15,
    "Fwd IAT Total": 975,
    "Fwd IAT Mean": 487.5,
    "Fwd IAT Std": 265.1650429,
    "Fwd IAT Max": 675,
    "Fwd IAT Min": 300,
    "Bwd IAT Total": 1780,
    "Bwd IAT Mean": 356.0,
    "Bwd IAT Std": 399.7880689,
    "Bwd IAT Max": 950,
    "Bwd IAT Min": 15,
    "Fwd PSH Flags": 0,
    "Bwd PSH Flags": 0,
    "Fwd URG Flags": 0,
    "Bwd URG Flags": 0,
    "Fwd Header Length": 104,
    "Bwd Header Length": 200,
    "Fwd Packets/s": 1597.444089,
    "Bwd Packets/s": 3194.888179,
    "Min Packet Length": 0,
    "Max Packet Length": 4355,
    "Packet Length Mean": 1197.7,
    "Packet Length Std": 1886.332364,
    "Packet Length Variance": 3558249.789,
    "FIN Flag Count": 0,
    "SYN Flag Count": 0,
    "RST Flag Count": 0,
    "PSH Flag Count": 1,
    "ACK Flag Count": 0,
    "URG Flag Count": 0,
    "CWE Flag Count": 0,
    "ECE Flag Count": 0,
    "Down/Up Ratio": 2,
    "Average Packet Size": 1330.777778,
    "Avg Fwd Segment Size": 127.3333333,
    "Avg Bwd Segment Size": 1932.5,
    "Fwd Header Length.1": 104,
    "Fwd Avg Bytes/Bulk": 0,
    "Fwd Avg Packets/Bulk": 0,
    "Fwd Avg Bulk Rate": 0,
    "Bwd Avg Bytes/Bulk": 0,
    "Bwd Avg Packets/Bulk": 0,
    "Bwd Avg Bulk Rate": 0,
    "Subflow Fwd Packets": 3,
    "Subflow Fwd Bytes": 382,
    "Subflow Bwd Packets": 6,
    "Subflow Bwd Bytes": 11595,
    "Init_Win_bytes_forward": 29200,
    "Init_Win_bytes_backward": 235,
    "act_data_pkt_fwd": 1,
    "min_seg_size_forward": 32,
    "Active Mean": 0.0,
    "Active Std": 0.0,
    "Active Max": 0,
    "Active Min": 0,
    "Idle Mean": 0.0,
    "Idle Std": 0.0,
    "Idle Max": 0,
    "Idle Min": 0
}

def simulate_hulk_attack():
    logging.info(f"Targeting API Endpoint: {API_URL}")
    logging.info("Injecting actual 'DoS Hulk' features directly into ML Evaluation Pipeline...")
    
    # We send it 5 times quickly, which trips the frequency threshold in Django rate limiter AND hits the ML
    for i in range(5):
        try:
            # Create a Session to keep connection alive and improve speed
            with requests.Session() as s:
                s.headers.update({'Content-Type': 'application/json'})
                
                # Send the exact JSON representation of a DoS Hulk
                response = s.post(API_URL, json=HULK_PAYLOAD, timeout=5)
                
                if response.status_code == 200:
                    res_data = response.json()
                    
                    # Handle possible array response or single object
                    if isinstance(res_data, list) and len(res_data) > 0:
                        res = res_data[0]
                    else:
                        res = res_data
                        
                    pred = res.get('prediction', 'Unknown')
                    conf = res.get('confidence', 0.0)
                    sev = res.get('severity', 'Low')
                    blocked = res.get('blocked', False)
                    
                    logging.info(f"[{i+1}] Model Predicted: {pred} | Confidence: {conf}% | Severity: {sev}")
                    
                    if sev == 'High' or pred != 'Normal':
                        logging.warning(f"  --> SUCCESS! Payload detected as an ATTACK.")
                    if blocked:
                        logging.warning(f"  --> [BLOCKED] Attacker IP {HULK_PAYLOAD['Source IP']} has been successfully banned!")
                        
                elif response.status_code == 403:
                    logging.error(f"[{i+1}] Request Denied (403 Forbidden). The firewall successfully blocked the connection entirely.")
                else:
                    logging.error(f"[{i+1}] Connection Error: {response.text}")
                    
            time.sleep(0.5)
            
        except requests.exceptions.RequestException as e:
            logging.error(f"[{i+1}] Request failed to send: {e}")

if __name__ == "__main__":
    simulate_hulk_attack()
