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

print(f"Testing 10 concurrent POSTs to {url}...")
import threading

def send_req(i):
    try:
        start = time.time()
        res = requests.post(url, json=payload, timeout=2.0)
        print(f"[{i}] {time.time()-start:.2f}s - {res.status_code}")
    except Exception as e:
        print(f"[{i}] Error: {e}")

threads = []
for i in range(10):
    t = threading.Thread(target=send_req, args=(i,))
    threads.append(t)
    t.start()
    time.sleep(0.1)

for t in threads:
    t.join()
