# IDS Real-Time Integration & Deployment Guide

This guide explains how to deploy, test, and demonstrate the new Real-Time Intrusion Detection System components for the Django backend.

## 1. Project Structure

The new real-time components have been placed in the root of your project:
- `feature_extractor.py`: The core logic converting raw Scapy packets into the 78 CICIDS2017 features.
- `flow_tracker.py`: Tracks IPs and ports, managing the sliding windows and timeouts.
- `realtime_sniffer.py`: The main background service sniffing packets and bridging them to the Django predicting API.
- `run_tests.py`: Evaluation script to simulate normal and malicious DOS traffic locally.

## 2. Dependencies

Ensure you have the required libraries installed. You will need `scapy` and `requests`.

```bash
pip install scapy requests numpy
```

*(Optional but Recommended for Windows)*: If Scapy warns about missing Npcap, download and install it from [nmap.org/npcap](https://nmap.org/npcap/). Ensure "Install Npcap in WinPcap API-compatible Mode" is selected during installation if you want loopback capture support.

## 3. How to Run the System

To fully run the system, you need two terminals.

### Terminal 1: The Django Backend
This is your normal backend running the API and dashboard.
```bash
cd "d:\mca main project\DDOS_ATTACK_DETECTOR"
python manage.py runserver 0.0.0.0:8000
```

### Terminal 2: The Real-Time Sniffer
This script requires **Administrator (Windows)** or **Root (Linux)** privileges to access the network interfaces.
```bash
cd "d:\mca main project\DDOS_ATTACK_DETECTOR"
python realtime_sniffer.py
```
*Note: You can pass a specific interface by modifying `SNIFF_INTERFACE = "Ethernet"` in `realtime_sniffer.py` if it picks the wrong one default.*

## 4. How to Test and Demonstrate (Jury Presentation)

1. Start Terminal 1 (Django `runserver`).
2. Start Terminal 2 (`python realtime_sniffer.py`).
3. Open a 3rd Terminal and run the test suite:
   ```bash
   python run_tests.py
   ```
4. **Expected Jury Demo Flow**:
   - Show the terminal running `run_tests.py`. It explicitly says "Sending Normal Traffic", "Sending DoS SYN Flood", etc.
   - Show the terminal running `realtime_sniffer.py`. You will see it naturally capture these, group them into a flow, process the 78 features, and output things like `[BLOCKED]: Detected DDoS (Confidence: 99.00%)`.
   - Open your Django Dashboard in the browser and show the new rows appearing in the UI and the IPs being added to the Blocked List.

## 5. Troubleshooting & Debugging

- **API Connection Errors**: If `realtime_sniffer.py` says `Failed to connect`, ensure Django is running on port 8000 and that `API_ENDPOINT` matches.
- **No Packets Captured**: On Windows, capturing on loopback (`127.0.0.1`) requires special Npcap support. If `run_tests.py` packets aren't showing up entirely, try changing the `target` IP in `run_tests.py` to your actual LAN IP (e.g., `192.168.1.5`).
- **Missing Features**: If your Random Forest model throws a mismatch error for feature sizes, verify that the order inside `realtime_sniffer.py` matches exactly what `features.json` dictates. The script `feature_extractor.py` enforces this rigorously via the `FEATURES_ORDER` array.
