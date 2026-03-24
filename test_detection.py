import requests
import json

# Test with attack payloads
with open('attack_payloads.json') as f:
    payloads = json.load(f)

api_url = 'http://127.0.0.1:8000/api/predict/'

scenarios = ['Normal', 'DDoS', 'DoS slowloris', 'DoS Slowhttptest', 'DoS Hulk', 'DoS GoldenEye', 'Heartbleed']

print("=" * 60)
print("DDoS DETECTION ACCURACY TEST RESULTS")
print("=" * 60)

correct_detections = 0
total_tests = len(scenarios)

for scenario in scenarios:
    resp = requests.post(api_url, json=payloads[scenario], timeout=5)
    data = resp.json()
    
    detected_as = data.get('prediction', '')
    confidence = data.get('confidence', 0)
    blocked_ip = data.get('blocked_ip') or data.get('ip')
    
    # Determine if detection was correct
    if scenario == "Normal":
        expected_type = "Normal"
        is_correct_attack_detection_for_normal_traffic_should_be_normal_or_something_similar
        
        
# Let me rewrite this more simply
