import requests
import json
import time

url = "http://127.0.0.1:8000/api/predict/"
payload = {
    "Destination Port": 80,
    "Flow Duration": 1293792,
    "Total Fwd Packets": 3,
    "Total Backward Packets": 7,
    "Total Length of Fwd Packets": 26,
    "Total Length of Bwd Packets": 11607,
    "Fwd Packet Length Max": 20,
    "Fwd Packet Length Min": 0,
    "Source IP": "10.0.0.5",
    "Destination IP": "0.0.0.0"
}

print(f"Testing POST to {url}...")
try:
    start = time.time()
    response = requests.post(url, json=payload, timeout=10)
    print(f"Time taken: {time.time() - start:.2f}s")
    print("Status:", response.status_code)
    print("Response:", response.text)
except requests.exceptions.RequestException as e:
    print(f"Error: {e}")
