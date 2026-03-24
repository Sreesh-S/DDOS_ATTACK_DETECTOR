import socket
import time
import random
import sys
import threading
import requests
import json
import os

API_URL = "http://127.0.0.1:8000/api/predict/"

def load_payloads():
    try:
        payloads_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'attack_payloads.json')
        with open(payloads_file, 'r') as f:
            return json.load(f)
    except:
        return {}

def generate_random_ip():
    return f"{random.randint(10, 200)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

def simulate_udp_flood(target_ip="127.0.0.1", target_port=80, duration=5, packet_count=20000):
    """
    Simulates a DoS UDP Flood attack against the target.
    Sends a burst of large UDP packets to spike the Network Traffic graphs.
    """
    print(f"[*] Starting UDP Flood (Bandwidth Spike) against {target_ip}:{target_port}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = random.randbytes(1024)
    start_time = time.time()
    sent = 0
    try:
        while time.time() - start_time < duration:
            sock.sendto(payload, (target_ip, target_port))
            sent += 1
            if sent % 100 == 0:
                time.sleep(0.01)
    except Exception as e:
        print(f"[-] UDP Flood error: {e}")
    finally:
        sock.close()
    print(f"[+] UDP Flood Complete! Sent {sent} packets.")

def simulate_api_alerts(duration=5):
    """
    Directly hits the backend AI API to simulate the sniffer detecting malicious flows.
    This guarantees the 'Attack Logs' and 'Alert Popups' trigger correctly even if 
    Npcap loopback capture is restricted.
    """
    print(f"[*] Starting API Injection (Dash Alerts) to {API_URL}")
    start_time = time.time()
    sent = 0
    
    payloads = load_payloads()
    attack_types = [k for k in payloads.keys() if k != "Normal"]
    if not attack_types:
        print("[-] No valid attack payloads found in attack_payloads.json")
        return

    try:
        while time.time() - start_time < duration:
            attack_type = random.choice(attack_types)
            current_payload = payloads[attack_type].copy()
            current_payload["Source IP"] = generate_random_ip()
            current_payload["Destination IP"] = "192.168.1.100"
            
            requests.post(API_URL, json=current_payload, timeout=2)
            sent += 1
            time.sleep(0.2) # ~5 alerts per second
    except Exception as e:
        print(f"[-] API Injection error: {e}")
        
    print(f"[+] API Injection Complete! Sent {sent} alerts.")

if __name__ == "__main__":
    duration = 5
    if len(sys.argv) > 1:
        try:
            duration = int(sys.argv[1])
        except ValueError:
            pass
            
    print(f"=== Starting Advanced Attack Simulation ({duration} seconds) ===")
    
    # Run both simultaneously: one for the charts, one for the alerts
    t1 = threading.Thread(target=simulate_udp_flood, kwargs={'duration': duration})
    t2 = threading.Thread(target=simulate_api_alerts, kwargs={'duration': duration})
    
    t1.start()
    t2.start()
    
    t1.join()
    t2.join()
    
    print("=== Simulation Complete! Check your Dashboard! ===")
    
