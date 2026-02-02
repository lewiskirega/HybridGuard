"""
Real-time Packet Sniffer using Scapy.

Captures IP traffic on the given interface (or default), aggregates packets
into flows by (src_ip:src_port, dst_ip:dst_port, protocol), and when a flow
is idle for flow_timeout seconds, computes flow features and calls the
callback. Requires root/sudo for raw capture. Used by IDSController.
"""

from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP
import threading
import time
from collections import defaultdict
import numpy as np
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PacketSniffer:
    """
    Captures packets with Scapy, aggregates by flow, and invokes callback
    with flow features when a flow expires (no packets for flow_timeout sec).
    """

    def __init__(self, interface=None, flow_timeout=5):
        self.interface = interface  # None = default interface
        self.flow_timeout = flow_timeout  # Seconds of inactivity before flow is closed
        self.sniffer = None
        self.running = False
        # Per-flow state: packets, byte counts, TCP flags, etc.
        self.flows = defaultdict(lambda: {
            'packets': [],
            'start_time': None,
            'last_seen': None,
            'fwd_packets': 0,
            'bwd_packets': 0,
            'fwd_bytes': 0,
            'bwd_bytes': 0,
            'tcp_flags': defaultdict(int),
            'packet_lengths': []
        })
        self.flow_callback = None
        self.lock = threading.Lock()
        self.cleanup_thread = None
    
    def extract_packet_features(self, packet):
        """Parse IP/TCP/UDP fields and build a flow key; return dict or None if not IP."""
        if not packet.haslayer(IP):
            return None
        
        try:
            timestamp = float(packet.time)
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            packet_length = len(packet)
            
            src_port = 0
            dst_port = 0
            tcp_flags = 0
            
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                tcp_flags = packet[TCP].flags
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            
            flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            reverse_flow_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
            
            payload = bytes(packet[IP].payload) if packet.haslayer(IP) else b''
            
            return {
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'packet_length': packet_length,
                'tcp_flags': tcp_flags,
                'flow_key': flow_key,
                'reverse_flow_key': reverse_flow_key,
                'payload': payload
            }
        except Exception as e:
            logger.error(f"Error extracting packet features: {e}")
            return None
    
    def packet_handler(self, packet):
        """Called by Scapy for each packet; updates the corresponding flow under lock."""
        features = self.extract_packet_features(packet)
        if not features:
            return
        
        with self.lock:
            flow_key = features['flow_key']
            reverse_flow_key = features['reverse_flow_key']
            
            if flow_key in self.flows:
                flow = self.flows[flow_key]
                is_forward = True
            elif reverse_flow_key in self.flows:
                flow_key = reverse_flow_key
                flow = self.flows[flow_key]
                is_forward = False
            else:
                flow = self.flows[flow_key]
                flow['start_time'] = features['timestamp']
                is_forward = True
            
            flow['packets'].append(features)
            flow['last_seen'] = features['timestamp']
            flow['packet_lengths'].append(features['packet_length'])
            
            if is_forward:
                flow['fwd_packets'] += 1
                flow['fwd_bytes'] += features['packet_length']
            else:
                flow['bwd_packets'] += 1
                flow['bwd_bytes'] += features['packet_length']
            
            if features['tcp_flags']:
                flags = features['tcp_flags']
                if flags & 0x02:
                    flow['tcp_flags']['SYN'] += 1
                if flags & 0x10:
                    flow['tcp_flags']['ACK'] += 1
                if flags & 0x01:
                    flow['tcp_flags']['FIN'] += 1
                if flags & 0x04:
                    flow['tcp_flags']['RST'] += 1
                if flags & 0x08:
                    flow['tcp_flags']['PSH'] += 1
                if flags & 0x20:
                    flow['tcp_flags']['URG'] += 1
    
    def cleanup_flows(self):
        """Background loop: every 1s, close flows idle for flow_timeout and call flow_callback."""
        while self.running:
            time.sleep(1)
            current_time = time.time()
            
            with self.lock:
                expired_flows = []
                
                for flow_key, flow_data in list(self.flows.items()):
                    if flow_data['last_seen'] and (current_time - flow_data['last_seen']) > self.flow_timeout:
                        expired_flows.append(flow_key)
                
                for flow_key in expired_flows:
                    flow_features = self.compute_flow_features(flow_key)
                    if flow_features and self.flow_callback:
                        self.flow_callback(flow_features)
                    del self.flows[flow_key]
    
    def compute_flow_features(self, flow_key):
        """Build the 21-feature dict for one flow (matches LIVE_FEATURE_COLUMNS for ML)."""
        flow = self.flows[flow_key]
        
        if not flow['packets']:
            return None
        
        duration = flow['last_seen'] - flow['start_time'] if flow['last_seen'] and flow['start_time'] else 0
        duration = max(duration, 0.000001)
        
        packet_lengths = np.array(flow['packet_lengths']) if flow['packet_lengths'] else np.array([0])
        n_pl = len(packet_lengths)
        pl_mean = float(np.mean(packet_lengths))
        pl_std = float(np.std(packet_lengths)) if n_pl >= 2 else 0.0  # avoid NaN for single-packet flows

        features = {
            'Flow Duration': duration * 1000000,
            'Total Fwd Packets': flow['fwd_packets'],
            'Total Backward Packets': flow['bwd_packets'],
            'Total Length of Fwd Packets': flow['fwd_bytes'],
            'Total Length of Bwd Packets': flow['bwd_bytes'],
            'Fwd Packet Length Mean': flow['fwd_bytes'] / max(flow['fwd_packets'], 1),
            'Fwd Packet Length Std': 0,
            'Bwd Packet Length Mean': flow['bwd_bytes'] / max(flow['bwd_packets'], 1),
            'Bwd Packet Length Std': 0,
            'Flow Bytes/s': (flow['fwd_bytes'] + flow['bwd_bytes']) / duration,
            'Flow Packets/s': (flow['fwd_packets'] + flow['bwd_packets']) / duration,
            'Packet Length Mean': pl_mean,
            'Packet Length Std': pl_std,
            'Min Packet Length': np.min(packet_lengths),
            'Max Packet Length': np.max(packet_lengths),
            'SYN Flag Count': flow['tcp_flags'].get('SYN', 0),
            'ACK Flag Count': flow['tcp_flags'].get('ACK', 0),
            'FIN Flag Count': flow['tcp_flags'].get('FIN', 0),
            'RST Flag Count': flow['tcp_flags'].get('RST', 0),
            'PSH Flag Count': flow['tcp_flags'].get('PSH', 0),
            'URG Flag Count': flow['tcp_flags'].get('URG', 0),
            'flow_key': flow_key,
            'src_ip': flow['packets'][0]['src_ip'] if flow['packets'] else 'Unknown',
            'dst_ip': flow['packets'][0]['dst_ip'] if flow['packets'] else 'Unknown',
            'protocol': flow['packets'][0]['protocol'] if flow['packets'] else 0,
            'packets': flow['packets']
        }
        
        return features
    
    def start(self, callback=None):
        """Start packet capture"""
        if self.running:
            logger.warning("Sniffer already running")
            return
        
        self.flow_callback = callback
        self.running = True
        
        filter_str = "ip"
        
        try:
            logger.info(f"Starting packet capture on interface: {self.interface or 'default'}")
            self.sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self.packet_handler,
                filter=filter_str,
                store=False
            )
            self.sniffer.start()
            
            self.cleanup_thread = threading.Thread(target=self.cleanup_flows, daemon=True)
            self.cleanup_thread.start()
            
            logger.info("Packet capture started successfully")
            return True
        except Exception as e:
            logger.error(f"Error starting packet capture: {e}")
            logger.info("Note: Packet capture requires administrator/root privileges (e.g. sudo python main.py)")
            self.running = False
            return False

    def stop(self):
        """Stop packet capture"""
        if not self.running:
            return
        
        logger.info("Stopping packet capture...")
        self.running = False
        
        if self.sniffer:
            self.sniffer.stop()
        
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=2)
        
        logger.info("Packet capture stopped")
    
    def get_active_flows_count(self):
        """Get count of active flows"""
        with self.lock:
            return len(self.flows)
