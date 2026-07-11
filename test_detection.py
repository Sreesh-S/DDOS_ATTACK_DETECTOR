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

for i, scenario in enumerate(scenarios):
    payload = payloads[scenario].copy()
    payload["Source IP"] = f"192.168.100.{i+1}"
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    resp = requests.post(api_url, json=payload, timeout=5, verify=False)
    
    if resp.status_code == 200:
        data = resp.json()
        detected_as = data.get('prediction', '')
        confidence = data.get('confidence', 0)
        blocked_ip = data.get('blocked_ip') or data.get('ip')
    elif resp.status_code == 403:
        detected_as = "BLOCKED (403)"
        confidence = 100
        blocked_ip = payloads[scenario].get("Source IP")
    else:
        detected_as = f"Error {resp.status_code}"
        confidence = 0
        blocked_ip = None
    
    # Determine if detection was correct
    if detected_as == scenario or (detected_as == "BLOCKED (403)" and scenario != "Normal"):
        correct_detections += 1
        status = "PASSED"
    else:
        status = "FAILED"
        
    print(f"Test: {scenario:<15} | Predicted: {detected_as:<15} | Confidence: {confidence}% | {status}")

print("=" * 60)
print(f"Accuracy: {correct_detections}/{total_tests} ({(correct_detections/total_tests)*100:.2f}%)")
print("=" * 60)
