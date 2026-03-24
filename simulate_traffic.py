import requests
import random
import time
import json

API_URL = "http://127.0.0.1:8000/api/predict/"

# Define some dummy feature sets for different scenarios
NORMAL_TRAFFIC = {
    "Source IP": "192.168.1.10",
    "Destination Port": 443,
    "Flow Duration": 500,
    "Total Fwd Packets": 5,
    "Total Backward Packets": 4,
    # Add other features as needed by the dummy model
}

DDOS_ATTACK = {
    "Source IP": "10.0.0.5",
    "Destination Port": 80,
    "Flow Duration": 100000,
    "Total Fwd Packets": 500,
    "Total Backward Packets": 0,
    # High packets, low duration -> likely DDoS in dummy model
}

SLOW_LORIS = {
    "Source IP": "10.0.0.6",
    "Destination Port": 80,
    "Flow Duration": 500000,
    "Total Fwd Packets": 10,
    "Total Backward Packets": 0,
}

def generate_random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

def simulate():
    print(f"Starting traffic simulation to {API_URL}...")
    print("Press Ctrl+C to stop manually if running in foreground.")
    
    scenarios = [
        ("Normal", NORMAL_TRAFFIC),
        ("Normal", NORMAL_TRAFFIC),
        ("Normal", NORMAL_TRAFFIC),
        ("DDoS Hulk", DDOS_ATTACK),
        ("DoS Slowloris", SLOW_LORIS),
    ]

    for i in range(20): # Run 20 requests
        scenario_name, data = random.choice(scenarios)
        
        # Randomize IP to test multiple sources
        current_data = data.copy()
        current_data["Source IP"] = generate_random_ip()
        
        try:
            response = requests.post(API_URL, json=current_data)
            if response.status_code == 200:
                print(f"[{i+1}/20] Sent {scenario_name} traffic from {current_data['Source IP']} -> Response: {response.json()['prediction']} (Blocked: {response.json().get('blocked')})")
            else:
                print(f"[{i+1}/20] Failed: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"Error connecting to API: {e}")
            print("Is the server running?")
            break
        
        time.sleep(0.5)

if __name__ == "__main__":
    simulate()
