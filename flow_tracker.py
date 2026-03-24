import time
import logging
from typing import Dict, Any, Callable, Optional, Tuple
from feature_extractor import CICIDSFeatureExtractor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class FlowTracker:
    """
    Tracks network flows by 5-tuple and manages their lifecycle (creation, timeout, termination).
    """
    def __init__(self, flow_timeout: float = 120.0, on_flow_complete: Optional[Callable[[Dict[str, Any]], None]] = None):
        """
        :param flow_timeout: Timeout in seconds to consider a flow expired if inactive.
        :param on_flow_complete: Callback function to execute when a flow is completed/expired. 
                                 It will receive the extracted features dictionary.
        """
        self.flows: Dict[Tuple, CICIDSFeatureExtractor] = {}
        self.flow_timeout = flow_timeout
        self.on_flow_complete = on_flow_complete

    def get_flow_id(self, packet_info: Dict[str, Any]) -> Tuple[Tuple, str]:
        """
        Generates a unique 5-tuple for the flow and determines direction relative to the flow creator.
        """
        src_ip = packet_info['src_ip']
        dst_ip = packet_info['dst_ip']
        src_port = packet_info['src_port']
        dst_port = packet_info['dst_port']
        protocol = packet_info['protocol']

        forward_tuple = (src_ip, dst_ip, src_port, dst_port, protocol)
        backward_tuple = (dst_ip, src_ip, dst_port, src_port, protocol)

        if backward_tuple in self.flows:
            return backward_tuple, 'bwd'
        else:
            return forward_tuple, 'fwd'

    def process_packet(self, packet_info: Dict[str, Any]):
        """
        Updates the flow tracker with a new packet.
        """
        flow_id, direction = self.get_flow_id(packet_info)
        packet_info['direction'] = direction

        if flow_id not in self.flows:
            # New flow
            f_src_ip, f_dst_ip, f_src_port, f_dst_port, f_protocol = flow_id
            self.flows[flow_id] = CICIDSFeatureExtractor(
                src_ip=f_src_ip, dst_ip=f_dst_ip, 
                src_port=f_src_port, dst_port=f_dst_port, 
                protocol=f_protocol
            )

        extractor = self.flows[flow_id]
        extractor.add_packet(packet_info)

        # Immediate termination on FIN or RST (optional, but good for reducing memory in DoS)
        flags = packet_info.get('tcp_flags', {})
        total_packets = extractor.fwd_packets + extractor.bwd_packets
        if flags.get('FIN', False) or flags.get('RST', False) or total_packets >= 100:
            self._close_flow(flow_id)

    def _close_flow(self, flow_id: Tuple):
        """
        Extracts features, triggers callback, and removes the flow from memory.
        """
        if flow_id in self.flows:
            extractor = self.flows[flow_id]
            
            # Additional context to pass alongside features
            features = extractor.get_features_dict()
            metadata = {
                'features': features,
                'src_ip': extractor.src_ip,
                'dst_ip': extractor.dst_ip,
                'src_port': extractor.src_port,
                'dst_port': extractor.dst_port,
                'protocol': extractor.protocol,
                'timestamp': extractor.start_time / 1e6 # Convert back to seconds
            }

            if self.on_flow_complete:
                try:
                    self.on_flow_complete(metadata)
                except Exception as e:
                    logging.error(f"Error in on_flow_complete callback: {e}")

            del self.flows[flow_id]

    def check_timeouts(self, current_time: float):
        """
        Iterates over active flows and removes those that have timed out.
        Should be called periodically.
        """
        expired_flows = []
        for flow_id, extractor in self.flows.items():
            inactive_time_us = (current_time * 1e6) - extractor.last_time
            active_time_us = (current_time * 1e6) - extractor.start_time
            
            if inactive_time_us > (3.0 * 1e6): # 3s inactivity timeout
                expired_flows.append(flow_id)
            elif active_time_us > (5.0 * 1e6): # Active timeout 5 seconds for real-time reporting
                expired_flows.append(flow_id)

        for flow_id in expired_flows:
            self._close_flow(flow_id)
