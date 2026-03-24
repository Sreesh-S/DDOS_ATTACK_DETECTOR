from scapy.all import sniff, conf

print("Scanning for network interfaces with Npcap...")

# Show available interfaces
print(conf.ifaces)

def packet_callback(packet):
    print(f"Captured packet: {packet.summary()}")

print("\nAttempting to capture 3 packets using Npcap...")
try:
    sniff(count=3, prn=packet_callback, timeout=10)
    print("Success! Npcap is working and capturing packets.")
except Exception as e:
    print(f"Error: {e}")
