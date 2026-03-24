import socket
import time

def send_udp():
    target_ip = "127.0.0.1" # User original issue: 10.115.17.46, but we'll try loopback for testing
    port = 8000
    
    # Send some data
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"Sending 5 UDP packets to {target_ip}:{port}...")
    
    for i in range(5):
        sock.sendto(b"HELLODDOS_TEST_PAYLOAD", (target_ip, port))
        time.sleep(0.1)
        
    print("Done sending packets.")
    
if __name__ == "__main__":
    send_udp()
