import json
import time
import random
import requests
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

import os
API_URL = os.environ.get("API_URL", "http://127.0.0.1:8000/api/predict/")
PAYLOADS_FILE = "attack_payloads.json"

def generate_random_ip():
    return f"{random.randint(10, 192)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def simulate():
    try:
        with open(PAYLOADS_FILE, 'r') as f:
            payloads = json.load(f)
    except Exception as e:
        logging.error(f"Failed to read {PAYLOADS_FILE}: {e}")
        return

    logging.info(f"Loaded {len(payloads)} scenarios: {list(payloads.keys())}")
    logging.info("Starting simulated real-time IDS traffic (No Npcap/Admin required).")
    logging.info("Press Ctrl+C to stop.")

    # Create a weighted list to simulate normal traffic more often, mixed with attacks
    choices = ["Normal"] * 5 + [k for k in payloads.keys() if k != "Normal"]

    try:
        while True:
            # Pick a scenario
            scenario_name = random.choice(choices)
            data = payloads[scenario_name].copy()
            
            # Dynamically add IP info for the API
            src_ip = generate_random_ip() if scenario_name != "Normal" else "192.168.1.50"
            data["Source IP"] = src_ip
            data["Destination IP"] = "10.0.0.5" # Web server

            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                response = requests.post(API_URL, json=data, timeout=2, verify=False)
                if response.status_code == 200:
                    resp_data = response.json()
                    pred = resp_data.get('prediction', 'Unknown')
                    conf = resp_data.get('confidence', 0.0)
                    sev = resp_data.get('severity', 'Low')
                    blocked = resp_data.get('blocked', False)
                    
                    block_str = "[BLOCKED]" if blocked else ""
                    if pred != "Normal":
                        logging.warning(f"Sent {scenario_name} from {src_ip} -> ALERT {block_str}: Detected {pred} (Confidence: {conf:.2f}%)")
                    else:
                        logging.info(f"Sent {scenario_name} from {src_ip} -> OK (Confidence: {conf:.2f}%)")
                elif response.status_code == 403:
                    logging.warning(f"Sent {scenario_name} from {src_ip} -> Traffic was blocked by firewall.")
                else:
                    logging.error(f"API Error: {response.status_code} - {response.text}")
                    
            except requests.exceptions.RequestException as e:
                logging.error(f"Failed to connect to Django API: {e}. Is the server running?")
            
            # Wait a random short duration to simulate real-time traffic
            time.sleep(random.uniform(0.01, 0.1))

    except KeyboardInterrupt:
        logging.info("Simulation stopped by user.")

if __name__ == "__main__":
    simulate()
