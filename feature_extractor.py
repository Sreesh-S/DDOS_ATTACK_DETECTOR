import numpy as np
import time
from typing import Dict, List, Any

# CICIDS2017 features definition order
FEATURES_ORDER = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean",
    "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
    "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward",
    "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean",
    "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
]

class CICIDSFeatureExtractor:
    """
    Extracts 78 flow-based features used in CICIDS2017 dataset from a sequence of packets.
    """
    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

        self.start_time = 0.0
        self.last_time = 0.0
        self.last_fwd_time = 0.0
        self.last_bwd_time = 0.0

        # Basic packet counts and lengths
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0

        self.fwd_pkt_lens = []
        self.bwd_pkt_lens = []
        self.all_pkt_lens = []

        # Inter-Arrival Times
        self.flow_iats = []
        self.fwd_iats = []
        self.bwd_iats = []

        # TCP Flags
        self.fwd_psh_flags = 0
        self.bwd_psh_flags = 0
        self.fwd_urg_flags = 0
        self.bwd_urg_flags = 0
        
        self.fin_flags = 0
        self.syn_flags = 0
        self.rst_flags = 0
        self.psh_flags = 0
        self.ack_flags = 0
        self.urg_flags = 0
        self.cwe_flags = 0
        self.ece_flags = 0

        # Headers and segments
        self.fwd_header_len = 0
        self.bwd_header_len = 0
        self.min_seg_size_fwd = -1

        self.init_win_bytes_fwd = -1
        self.init_win_bytes_bwd = -1
        self.act_data_pkt_fwd = 0

        # Active / Idle (Simple estimation based on IATs > 1 second threshold for idleness)
        self.active_times = []
        self.idle_times = []
        self.IDLE_THRESHOLD = 1000000.0 # 1 second in microseconds roughly
        
        self.current_active_start = 0.0

    def add_packet(self, packet_info: Dict[str, Any]):
        """
        packet_info should be a dictionary with at least:
        - timestamp: float (epoch)
        - length: int (packet length)
        - direction: 'fwd' or 'bwd'
        - header_length: int
        - tcp_flags: dict (e.g., {'FIN': bool, 'SYN': bool, ...})
        - window_size: int (for TCP)
        - payload_size: int
        """
        ts = packet_info['timestamp'] * 1e6 # Convert to microseconds to match CICIDS
        length = packet_info['length']
        direction = packet_info['direction']
        header_len = packet_info.get('header_length', 0)
        flags = packet_info.get('tcp_flags', {})
        win_size = packet_info.get('window_size', 0)
        payload_size = packet_info.get('payload_size', 0)

        # Initialize start time
        if self.start_time == 0.0:
            self.start_time = ts
            self.last_time = ts
            self.current_active_start = ts
            if direction == 'fwd':
                self.last_fwd_time = ts
            else:
                self.last_bwd_time = ts

        # IAT Calculations
        flow_iat = ts - self.last_time
        if self.last_time != ts and flow_iat > 0:
            self.flow_iats.append(flow_iat)
            
            # Active/Idle estimation
            if flow_iat > self.IDLE_THRESHOLD:
                self.idle_times.append(flow_iat)
                active_time = self.last_time - self.current_active_start
                if active_time > 0:
                    self.active_times.append(active_time)
                self.current_active_start = ts

        self.last_time = ts

        # Global features
        self.all_pkt_lens.append(length)

        # Flag counts
        if flags.get('FIN', False): self.fin_flags += 1
        if flags.get('SYN', False): self.syn_flags += 1
        if flags.get('RST', False): self.rst_flags += 1
        if flags.get('PSH', False): self.psh_flags += 1
        if flags.get('ACK', False): self.ack_flags += 1
        if flags.get('URG', False): self.urg_flags += 1
        if flags.get('CWE', False): self.cwe_flags += 1
        if flags.get('ECE', False): self.ece_flags += 1

        # Directional features
        if direction == 'fwd':
            self.fwd_packets += 1
            self.fwd_bytes += length
            self.fwd_pkt_lens.append(length)
            self.fwd_header_len += header_len
            
            if payload_size > 0:
                self.act_data_pkt_fwd += 1

            if self.min_seg_size_fwd == -1 or header_len < self.min_seg_size_fwd:
                self.min_seg_size_fwd = header_len

            if self.init_win_bytes_fwd == -1 and self.protocol == 6: # TCP
                self.init_win_bytes_fwd = win_size

            if self.last_fwd_time != 0.0:
                iat = ts - self.last_fwd_time
                if iat > 0:
                    self.fwd_iats.append(iat)
            self.last_fwd_time = ts

            if flags.get('PSH', False): self.fwd_psh_flags += 1
            if flags.get('URG', False): self.fwd_urg_flags += 1

        elif direction == 'bwd':
            self.bwd_packets += 1
            self.bwd_bytes += length
            self.bwd_pkt_lens.append(length)
            self.bwd_header_len += header_len

            if self.init_win_bytes_bwd == -1 and self.protocol == 6:
                self.init_win_bytes_bwd = win_size

            if self.last_bwd_time != 0.0:
                iat = ts - self.last_bwd_time
                if iat > 0:
                    self.bwd_iats.append(iat)
            self.last_bwd_time = ts

            if flags.get('PSH', False): self.bwd_psh_flags += 1
            if flags.get('URG', False): self.bwd_urg_flags += 1

    def finalize_active_time(self, current_ts=None):
        if current_ts is None:
            current_ts = self.last_time
        active_time = current_ts - self.current_active_start
        if active_time > 0:
            self.active_times.append(active_time)

    def _safe_mean(self, lst):
        return float(np.mean(lst)) if lst else 0.0

    def _safe_std(self, lst, ddof=0):
        return float(np.std(lst, ddof=ddof)) if len(lst) > 1 else 0.0

    def _safe_max(self, lst):
        return float(np.max(lst)) if lst else 0.0

    def _safe_min(self, lst):
        return float(np.min(lst)) if lst else 0.0

    def extract(self) -> Dict[str, Any]:
        """
        Computes all 78 features in the dictionary format.
        """
        self.finalize_active_time()

        flow_duration = self.last_time - self.start_time

        features = {}
        features["Destination Port"] = self.dst_port
        features["Flow Duration"] = flow_duration
        features["Total Fwd Packets"] = self.fwd_packets
        features["Total Backward Packets"] = self.bwd_packets
        features["Total Length of Fwd Packets"] = self.fwd_bytes
        features["Total Length of Bwd Packets"] = self.bwd_bytes
        
        features["Fwd Packet Length Max"] = self._safe_max(self.fwd_pkt_lens)
        features["Fwd Packet Length Min"] = self._safe_min(self.fwd_pkt_lens)
        features["Fwd Packet Length Mean"] = self._safe_mean(self.fwd_pkt_lens)
        features["Fwd Packet Length Std"] = self._safe_std(self.fwd_pkt_lens)
        
        features["Bwd Packet Length Max"] = self._safe_max(self.bwd_pkt_lens)
        features["Bwd Packet Length Min"] = self._safe_min(self.bwd_pkt_lens)
        features["Bwd Packet Length Mean"] = self._safe_mean(self.bwd_pkt_lens)
        features["Bwd Packet Length Std"] = self._safe_std(self.bwd_pkt_lens)
        
        dur_sec = flow_duration / 1e6 if flow_duration > 0 else 0
        features["Flow Bytes/s"] = (self.fwd_bytes + self.bwd_bytes) / dur_sec if dur_sec > 0 else 0.0
        features["Flow Packets/s"] = (self.fwd_packets + self.bwd_packets) / dur_sec if dur_sec > 0 else 0.0
        
        features["Flow IAT Mean"] = self._safe_mean(self.flow_iats)
        features["Flow IAT Std"] = self._safe_std(self.flow_iats)
        features["Flow IAT Max"] = self._safe_max(self.flow_iats)
        features["Flow IAT Min"] = self._safe_min(self.flow_iats)
        
        features["Fwd IAT Total"] = sum(self.fwd_iats)
        features["Fwd IAT Mean"] = self._safe_mean(self.fwd_iats)
        features["Fwd IAT Std"] = self._safe_std(self.fwd_iats)
        features["Fwd IAT Max"] = self._safe_max(self.fwd_iats)
        features["Fwd IAT Min"] = self._safe_min(self.fwd_iats)
        
        features["Bwd IAT Total"] = sum(self.bwd_iats)
        features["Bwd IAT Mean"] = self._safe_mean(self.bwd_iats)
        features["Bwd IAT Std"] = self._safe_std(self.bwd_iats)
        features["Bwd IAT Max"] = self._safe_max(self.bwd_iats)
        features["Bwd IAT Min"] = self._safe_min(self.bwd_iats)
        
        features["Fwd PSH Flags"] = self.fwd_psh_flags
        features["Bwd PSH Flags"] = self.bwd_psh_flags
        features["Fwd URG Flags"] = self.fwd_urg_flags
        features["Bwd URG Flags"] = self.bwd_urg_flags
        
        features["Fwd Header Length"] = self.fwd_header_len
        features["Bwd Header Length"] = self.bwd_header_len
        
        features["Fwd Packets/s"] = self.fwd_packets / dur_sec if dur_sec > 0 else 0.0
        features["Bwd Packets/s"] = self.bwd_packets / dur_sec if dur_sec > 0 else 0.0
        
        features["Min Packet Length"] = self._safe_min(self.all_pkt_lens)
        features["Max Packet Length"] = self._safe_max(self.all_pkt_lens)
        features["Packet Length Mean"] = self._safe_mean(self.all_pkt_lens)
        features["Packet Length Std"] = self._safe_std(self.all_pkt_lens)
        
        std_val = features["Packet Length Std"]
        features["Packet Length Variance"] = std_val * std_val
        
        features["FIN Flag Count"] = self.fin_flags
        features["SYN Flag Count"] = self.syn_flags
        features["RST Flag Count"] = self.rst_flags
        features["PSH Flag Count"] = self.psh_flags
        features["ACK Flag Count"] = self.ack_flags
        features["URG Flag Count"] = self.urg_flags
        features["CWE Flag Count"] = self.cwe_flags
        features["ECE Flag Count"] = self.ece_flags
        
        features["Down/Up Ratio"] = (self.bwd_packets / self.fwd_packets) if self.fwd_packets > 0 else 0.0
        
        features["Average Packet Size"] = self._safe_mean(self.all_pkt_lens)
        # Fix handling empty values for segment size
        features["Avg Fwd Segment Size"] = features["Fwd Packet Length Mean"]
        features["Avg Bwd Segment Size"] = features["Bwd Packet Length Mean"]
        
        features["Fwd Header Length.1"] = self.fwd_header_len
        
        features["Subflow Fwd Packets"] = self.fwd_packets
        features["Subflow Fwd Bytes"] = self.fwd_bytes
        features["Subflow Bwd Packets"] = self.bwd_packets
        features["Subflow Bwd Bytes"] = self.bwd_bytes
        
        features["Init_Win_bytes_forward"] = self.init_win_bytes_fwd if self.init_win_bytes_fwd != -1 else 0
        features["Init_Win_bytes_backward"] = self.init_win_bytes_bwd if self.init_win_bytes_bwd != -1 else 0
        
        features["act_data_pkt_fwd"] = self.act_data_pkt_fwd
        features["min_seg_size_forward"] = self.min_seg_size_fwd if self.min_seg_size_fwd != -1 else 0
        
        features["Fwd Avg Bytes/Bulk"] = 0
        features["Fwd Avg Packets/Bulk"] = 0
        features["Fwd Avg Bulk Rate"] = 0
        features["Bwd Avg Bytes/Bulk"] = 0
        features["Bwd Avg Packets/Bulk"] = 0
        features["Bwd Avg Bulk Rate"] = 0
        
        features["Active Mean"] = self._safe_mean(self.active_times)
        features["Active Std"] = self._safe_std(self.active_times)
        features["Active Max"] = self._safe_max(self.active_times)
        features["Active Min"] = self._safe_min(self.active_times)
        
        features["Idle Mean"] = self._safe_mean(self.idle_times)
        features["Idle Std"] = self._safe_std(self.idle_times)
        features["Idle Max"] = self._safe_max(self.idle_times)
        features["Idle Min"] = self._safe_min(self.idle_times)
        
        ordered_features = {k: float(features.get(k, 0.0)) for k in FEATURES_ORDER}
        return ordered_features

    def get_features_dict(self) -> Dict[str, Any]:
        """Alias for extract"""
        return self.extract()
