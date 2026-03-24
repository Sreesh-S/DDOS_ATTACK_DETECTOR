import time
import requests
import threading
import logging
from scapy.all import IP, TCP, UDP, send, conf
from realtime_sniffer import IDSEngine

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
API_URL = "http://127.0.0.1:8000/api/predict/"

def check_django_running():
    try:
        requests.get(API_URL.replace("predict/", ""), timeout=2)
        return True
    except requests.exceptions.ConnectionError:
        return False

def simulate_normal_traffic(target_ip, target_port):
    logging.info(f"[TEST] Sending Normal Traffic to {target_ip}:{target_port}")
    # Simulate a basic HTTP GET request flow
    src_port = 54321
    
    # SYN
    p1 = IP(dst=target_ip)/TCP(sport=src_port, dport=target_port, flags="S", seq=100)
    # ACK
    p2 = IP(dst=target_ip)/TCP(sport=src_port, dport=target_port, flags="A", seq=101, ack=200)
    # PSH, ACK (HTTP GET)
    payload = b"GET / HTTP/1.1\r\nHost: test\r\n\r\n"
    p3 = IP(dst=target_ip)/TCP(sport=src_port, dport=target_port, flags="PA", seq=101, ack=200)/payload
    # FIN, ACK
    p4 = IP(dst=target_ip)/TCP(sport=src_port, dport=target_port, flags="FA", seq=101+len(payload), ack=200)

    # Use a loopback routing workaround for Windows Scapy if needed, 
    # but send() generally works if routed properly.
    # For local testing, we might need to rely on the sniffer intercepting loopback, 
    # which Windows Pcap struggles with. Better to send to local external IP.
    for p in [p1, p2, p3, p4]:
        send(p, verbose=False)
        time.sleep(0.05)
    
def simulate_dos_syn_flood(target_ip, target_port, count=20):
    logging.info(f"[TEST] Sending DoS SYN Flood to {target_ip}:{target_port}")
    for i in range(count):
        src_port = 10000 + i
        p = IP(src=f"10.0.0.{i%254+1}", dst=target_ip)/TCP(sport=src_port, dport=target_port, flags="S", window=1024)
        send(p, verbose=False)
        time.sleep(0.05)

def simulate_hulk_dos(target_ip, target_port, count=20):
    logging.info(f"[TEST] Sending DoS Hulk (HTTP GET Flood) to {target_ip}:{target_port}")
    # Hulk does many HTTP requests with varying User-Agents and parameters from the same or spoofed IPs
    for i in range(count):
        src_port = 20000 + i
        payload = f"GET /?rand={i} HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: HulkTest\r\n\r\n".encode()
        
        # PSH, ACK
        p = IP(src="192.168.1.100", dst=target_ip)/TCP(sport=src_port, dport=target_port, flags="PA")/payload
        send(p, verbose=False)
        time.sleep(0.1)

def run_tests():
    if not check_django_running():
        logging.error("Django server is NOT running. Please start it with 'python manage.py runserver' before testing.")
        return

    logging.info("Django server is reachable.")

    # 1. Start the IDS Sniffer in a background thread
    # Use loopback 'Software Loopback Interface 1' or default if loopback not available
    # Windows loopback sniffing might require Npcap with loopback support installed.
    # For robust testing regardless of OS, we'll try to sniff all.
    ids = IDSEngine(timeout=2.0) # Fast timeout for testing
    ids_thread = threading.Thread(target=ids.start, daemon=True)
    ids_thread.start()

    time.sleep(2) # Give sniffer time to start

    # Target IP should ideally be the machines local IP, not 127.0.0.1 if on Windows, 
    # due to limitations in WinPcap/Npcap loopback capturing.
    # We will use 127.0.0.1 but note the limitation.
    target = "127.0.0.1"
    
    try:
        # Test 1: Normal Traffic
        simulate_normal_traffic(target, 80)
        time.sleep(3) # Wait for flow to timeout and be sent to Django

        # Test 2: DoS SYN Flood
        simulate_dos_syn_flood(target, 80, count=20)
        time.sleep(3)

        # Test 3: DoS Hulk
        simulate_hulk_dos(target, 80, count=20)
        time.sleep(4)

        logging.info("--- Tests Completed ---")
        logging.info("Check the Django dashboard or database for Prediction records and blocked IPs.")

    finally:
        ids.running = False
        ids_thread.join(timeout=2)
        print("Test script exiting.")

if __name__ == "__main__":
    run_tests()
