import sys
import time
import requests
import json
import logging
import threading
import queue
from scapy.all import sniff, IP, TCP, UDP
from flow_tracker import FlowTracker

# Configuration
import os
API_ENDPOINT = os.environ.get("API_URL", "http://127.0.0.1:8000/api/predict/")
SNIFF_INTERFACE = None  # None means sniff on all interfaces, or define e.g., "Ethernet"
FLOW_TIMEOUT = 30.0      # Time in seconds to timeout an inactive flow (reduced for better real-time updates)
CHECK_INTERVAL = 5.0     # Time in seconds between checking for timed-out flows (reduced)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class IDSEngine:
    def __init__(self, api_url=API_ENDPOINT, interface=SNIFF_INTERFACE, timeout=FLOW_TIMEOUT):
        self.api_url = api_url
        self.interface = interface
        self.tracker = FlowTracker(flow_timeout=timeout, on_flow_complete=self.handle_flow_complete)
        self.running = False
        self.lock = threading.Lock()
        
        # Prevent API overload by queuing flows
        self.api_queue = queue.Queue(maxsize=2000)

    def handle_flow_complete(self, flow_metadata):
        """
        Callback from FlowTracker when a flow is finished/timed out.
        Submits the extracted features to the Django backend.
        """
        features = flow_metadata['features']
        
        # Add metadata for the API if needed (API views.py expects 'Source IP' / 'Destination IP')
        features['Source IP'] = flow_metadata['src_ip']
        features['Destination IP'] = flow_metadata['dst_ip']
        
        # Try to queue the flow for processing. Ignore if full to prevent freezing.
        try:
            self.api_queue.put_nowait(features)
        except queue.Full:
            logging.warning(f"API queue full! Dropping flow from {flow_metadata['src_ip']} to prevent server crash.")

    def _api_worker(self):
        """Background thread that sends HTTP requests to the Django API safely."""
        session = requests.Session()
        session.headers.update({'Content-Type': 'application/json'})
        
        while True:
            batch = []
            try:
                # Try to get the first item, blocking up to 1 second
                batch.append(self.api_queue.get(timeout=1.0))
                
                # Try to get up to 49 more items without blocking
                while len(batch) < 50:
                    try:
                        batch.append(self.api_queue.get_nowait())
                    except queue.Empty:
                        break
                        
                self._send_to_api(session, batch)
                
                for _ in range(len(batch)):
                    self.api_queue.task_done()
                    
            except queue.Empty:
                if not self.running:
                    break
        
        session.close()

    def _send_to_api(self, session, batch):
        if not batch:
            return
            
        try:
            # We add a timeout so stuck requests don't hang threads
            # Send the whole batch as a JSON list
            response = session.post(self.api_url, json=batch, timeout=15.0)
            
            if response.status_code == 200:
                data_list = response.json()
                if not isinstance(data_list, list):
                    data_list = [data_list]
                    
                for i, data in enumerate(data_list):
                    # In case of partial blocks returned as error dict
                    if "error" in data:
                        logging.warning(f"Traffic from Source IP {data.get('ip')} was blocked.")
                        continue
                        
                    pred = data.get('prediction', 'Unknown')
                    conf = data.get('confidence', 0.0)
                    sev = data.get('severity', 'Low')
                    blocked = data.get('blocked', False)
                    
                    block_str = "[BLOCKED]" if blocked else ""
                    
                    if pred != "Normal":
                        logging.warning(f"ALERT {block_str}: Detected {pred} (Confidence: {conf:.2f}%) - Severity: {sev}")
                    else:
                        logging.info(f"Normal traffic (Confidence: {conf:.2f}%)")
                        
            elif response.status_code == 403:
                 # Either the whole batch was blocked or it returned a single block response
                 try:
                     resp_data = response.json()
                     logging.warning(f"Traffic from Source IP {resp_data.get('ip', 'Unknown')} was blocked by firewall/API.")
                 except:
                     logging.warning(f"Batch traffic containing {len(batch)} flows was blocked by firewall/API.")
            else:
                logging.error(f"API Error: {response.status_code} - {response.text}")
                
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to connect to Django API: {e}")

    def process_packet(self, packet):
        """
        Callback for scapy.sniff.
        Extracts raw packet details and passes them to the flow tracker.
        """
        if IP not in packet:
            return

        ip_layer = packet[IP]
        if ip_layer.version != 4:
            return

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        length = ip_layer.len
        timestamp = float(packet.time)

        src_port = 0
        dst_port = 0
        header_length = ip_layer.ihl * 4
        tcp_flags = {}
        window_size = 0
        payload_size = 0

        # TCP Processing
        if TCP in packet:
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            header_length += tcp_layer.dataofs * 4 # TCP header length
            window_size = tcp_layer.window
            payload_size = len(tcp_layer.payload)
            
            # Scapy flags are string based like "SA", "PA", "F", etc.
            flags_str = str(tcp_layer.flags)
            tcp_flags = {
                'FIN': 'F' in flags_str,
                'SYN': 'S' in flags_str,
                'RST': 'R' in flags_str,
                'PSH': 'P' in flags_str,
                'ACK': 'A' in flags_str,
                'URG': 'U' in flags_str,
                'ECE': 'E' in flags_str,
                'CWE': 'C' in flags_str
            }
            
        # UDP Processing
        elif UDP in packet:
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            header_length += 8 # standard UDP header
            payload_size = len(udp_layer.payload)
            
        else:
            # We only really care about TCP/UDP for these specific features normally
            # but we can capture generic IP traffic just in case
            pass

        packet_info = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'timestamp': timestamp,
            'length': length,
            'header_length': header_length,
            'window_size': window_size,
            'payload_size': payload_size,
            'tcp_flags': tcp_flags
        }

        # Thread safe update
        with self.lock:
            self.tracker.process_packet(packet_info)

    def _timeout_loop(self):
        """
        Background thread that periodically cleans up stale flows.
        """
        while self.running:
            time.sleep(CHECK_INTERVAL)
            with self.lock:
                current_time = time.time()
                self.tracker.check_timeouts(current_time)

    def start(self):
        self.running = True
        
        # Start the timeout checker thread
        timeout_thread = threading.Thread(target=self._timeout_loop, daemon=True)
        timeout_thread.start()
        
        # Start API worker threads
        for _ in range(3):
            threading.Thread(target=self._api_worker, daemon=True).start()

        logging.info("Starting Real-Time Packet Sniffer...")
        if self.interface:
            logging.info(f"Listening on interface: {self.interface}")
        else:
            logging.info("Listening on all available interfaces.")
            
        logging.info("Press Ctrl+C to stop.")

        try:
            # Start sniffing (blocking call)
            sniff(
                prn=self.process_packet,
                store=False, # Don't keep packets in memory
                iface=self.interface
            )
        except KeyboardInterrupt:
            logging.info("Stopping sniffer...")
        except Exception as e:
            err_str = str(e).lower()
            if "winpcap is not installed" in err_str or "layer 2" in err_str:
                logging.error("\n" + "="*60 + "\nCRITICAL ERROR: Npcap/WinPcap is missing!\n"
                              "Scapy requires Npcap on Windows to sniff packets in real-time.\n"
                              "1. Install Npcap from https://nmap.org/npcap/ (enable WinPcap API compat).\n"
                              "2. Run this script as Administrator.\n"
                              "Alternatively, use 'python simulate_realtime_traffic.py' for offline testing.\n" + "="*60 + "\n")
            else:
                logging.error(f"Sniffer error: {e}")
        finally:
            self.running = False
            logging.info("Flushing remaining flows...")
            with self.lock:
                # Force checking everything as timed out
                self.tracker.check_timeouts(time.time() + FLOW_TIMEOUT * 2)
                
            queue_size = self.api_queue.qsize()
            if queue_size > 0:
                logging.info(f"Waiting for API workers to send remaining {queue_size} flows...")
                self.api_queue.join()
            
            logging.info("Sniffer stopped successfully.")

if __name__ == "__main__":
    engine = IDSEngine()
    engine.start()
