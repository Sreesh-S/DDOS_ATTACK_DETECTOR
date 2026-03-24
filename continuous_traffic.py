import requests
import random
import time
import json
import os
import sys

API_URL = "http://127.0.0.1:8000/api/predict/"

# Load dynamic payloads
try:
    # attack_payloads.json should be in the same directory
    payloads_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'attack_payloads.json')
    with open(payloads_file, 'r') as f:
        PAYLOADS = json.load(f)
except Exception as e:
    print(f"Error loading attack payloads: {e}")
    print("Please run 'python extract_payloads.py' first.")
    sys.exit(1)

def generate_random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

def simulate_continuous():
    print(f"Starting CONTINUOUS traffic simulation to {API_URL}...")
    print(f"Loaded {len(PAYLOADS)} attack profiles: {list(PAYLOADS.keys())}")
    print("Press Ctrl+C to stop.")
    
    count = 0
    attack_types = list(PAYLOADS.keys())
    
    while True:
        try:
            # 70% chance of Normal traffic, 30% chance of an attack (any type except Normal)
            is_normal = random.random() < 0.7
            
            if is_normal and "Normal" in PAYLOADS:
                attack_type = "Normal"
            else:
                attacks_only = [a for a in attack_types if a != "Normal"]
                if not attacks_only:
                    attack_type = "Normal"
                else:
                    attack_type = random.choice(attacks_only)
                    
            data = PAYLOADS[attack_type].copy()
            data["Source IP"] = generate_random_ip()
            
            # Minor variance to avoid exact caching duplicates
            if "Flow Duration" in data:
                data["Flow Duration"] += random.randint(-10, 100)
                
            response = requests.post(API_URL, json=data)
            
            if response.status_code == 200:
                res_json = response.json()
                status = "BLOCKED" if res_json.get('blocked') else "ALLOWED"
                pred = res_json.get('prediction')
                conf = res_json.get('confidence')
                sev = res_json.get('severity')
                
                print(f"[{count}] IP: {data['Source IP']} | Sent: {attack_type:<15} -> Predicted: {pred:<15} ({conf:.1f}%) | Severity: {sev} [{status}]")
            elif response.status_code == 403:
                res_json = response.json()
                print(f"[{count}] IP: {data['Source IP']} -> BLOCKED BY FIREWALL")
            else:
                print(f"Request failed: {response.status_code}")

            count += 1
            # Random delay between 0.5s and 2s for realism
            time.sleep(random.uniform(0.5, 2.0))
            
        except KeyboardInterrupt:
            print("\nSimulation stopped.")
            sys.exit(0)
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(2)

if __name__ == "__main__":
    simulate_continuous()
