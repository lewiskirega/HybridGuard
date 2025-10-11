"""
Signature-based Detection Engine
Implements rule-based detection for known attack patterns
"""

from collections import defaultdict
import time
import re
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SignatureDetector:
    def __init__(self):
        self.ip_stats = defaultdict(lambda: {
            'syn_packets': [],
            'ports': set(),
            'port_attempts': []
        })
        self.sql_injection_patterns = [
            r"(?i)(union\s+select)",
            r"(?i)(or\s+1\s*=\s*1)",
            r"(?i)(drop\s+table)",
            r"(?i)(insert\s+into)",
            r"(?i)(delete\s+from)",
            r"(?i)('\s+or\s+'1'\s*=\s*'1)",
            r"(?i)(--\s*$)",
            r"(?i)(;.*drop)",
        ]
        self.xss_patterns = [
            r"(?i)(<script.*?>)",
            r"(?i)(javascript:)",
            r"(?i)(onerror\s*=)",
            r"(?i)(onload\s*=)",
            r"(?i)(<iframe)",
            r"(?i)(eval\()",
        ]
    
    def detect_syn_flood(self, flow_features):
        """Detect SYN flood attacks"""
        src_ip = flow_features.get('src_ip', '')
        current_time = time.time()
        syn_count = flow_features.get('SYN Flag Count', 0)
        
        if syn_count > 0:
            self.ip_stats[src_ip]['syn_packets'].append(current_time)
        
        self.ip_stats[src_ip]['syn_packets'] = [
            t for t in self.ip_stats[src_ip]['syn_packets']
            if current_time - t < 10
        ]
        
        recent_syn_count = len(self.ip_stats[src_ip]['syn_packets'])
        
        if recent_syn_count > 100:
            return {
                'detected': True,
                'type': 'SYN Flood',
                'severity': 'HIGH',
                'description': f'Detected {recent_syn_count} SYN packets from {src_ip} in 10 seconds',
                'src_ip': src_ip
            }
        
        return {'detected': False}
    
    def detect_port_scan(self, flow_features):
        """Detect port scanning attacks"""
        src_ip = flow_features.get('src_ip', '')
        dst_port = flow_features.get('packets', [{}])[0].get('dst_port', 0) if flow_features.get('packets') else 0
        current_time = time.time()
        
        if dst_port:
            self.ip_stats[src_ip]['ports'].add(dst_port)
            self.ip_stats[src_ip]['port_attempts'].append(current_time)
        
        self.ip_stats[src_ip]['port_attempts'] = [
            t for t in self.ip_stats[src_ip]['port_attempts']
            if current_time - t < 30
        ]
        
        unique_ports = len(self.ip_stats[src_ip]['ports'])
        recent_attempts = len(self.ip_stats[src_ip]['port_attempts'])
        
        if unique_ports > 20 and recent_attempts > 20:
            return {
                'detected': True,
                'type': 'Port Scan',
                'severity': 'HIGH',
                'description': f'Detected port scan from {src_ip} - {unique_ports} unique ports in 30 seconds',
                'src_ip': src_ip
            }
        
        return {'detected': False}
    
    def detect_sql_injection(self, flow_features):
        """Detect SQL injection attempts in payload"""
        packets = flow_features.get('packets', [])
        
        for packet in packets:
            payload = packet.get('payload', b'')
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
                
                for pattern in self.sql_injection_patterns:
                    if re.search(pattern, payload_str):
                        return {
                            'detected': True,
                            'type': 'SQL Injection',
                            'severity': 'CRITICAL',
                            'description': f'SQL injection pattern detected from {packet.get("src_ip")}',
                            'src_ip': packet.get('src_ip', 'Unknown'),
                            'pattern': pattern
                        }
            except Exception as e:
                continue
        
        return {'detected': False}
    
    def detect_xss(self, flow_features):
        """Detect Cross-Site Scripting (XSS) attempts"""
        packets = flow_features.get('packets', [])
        
        for packet in packets:
            payload = packet.get('payload', b'')
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
                
                for pattern in self.xss_patterns:
                    if re.search(pattern, payload_str):
                        return {
                            'detected': True,
                            'type': 'XSS Attack',
                            'severity': 'HIGH',
                            'description': f'XSS pattern detected from {packet.get("src_ip")}',
                            'src_ip': packet.get('src_ip', 'Unknown'),
                            'pattern': pattern
                        }
            except Exception as e:
                continue
        
        return {'detected': False}
    
    def detect_icmp_flood(self, flow_features):
        """Detect ICMP flood attacks (large ICMP packets or high frequency)"""
        protocol = flow_features.get('protocol', 0)
        packet_length = flow_features.get('Max Packet Length', 0)
        packets_per_sec = flow_features.get('Flow Packets/s', 0)
        
        if protocol == 1:
            if packet_length > 1000:
                return {
                    'detected': True,
                    'type': 'ICMP Flood',
                    'severity': 'MEDIUM',
                    'description': f'Large ICMP packet detected ({packet_length} bytes)',
                    'src_ip': flow_features.get('src_ip', 'Unknown')
                }
            
            if packets_per_sec > 100:
                return {
                    'detected': True,
                    'type': 'ICMP Flood',
                    'severity': 'HIGH',
                    'description': f'High rate ICMP traffic detected ({packets_per_sec:.0f} pkt/s)',
                    'src_ip': flow_features.get('src_ip', 'Unknown')
                }
        
        return {'detected': False}
    
    def detect(self, flow_features):
        """Run all signature-based detection rules"""
        alerts = []
        
        detections = [
            self.detect_syn_flood(flow_features),
            self.detect_port_scan(flow_features),
            self.detect_sql_injection(flow_features),
            self.detect_xss(flow_features),
            self.detect_icmp_flood(flow_features)
        ]
        
        for detection in detections:
            if detection.get('detected', False):
                alerts.append(detection)
        
        return alerts
    
    def cleanup_old_stats(self, max_age=300):
        """Clean up old statistics to prevent memory issues"""
        current_time = time.time()
        
        for ip in list(self.ip_stats.keys()):
            if not self.ip_stats[ip]['syn_packets'] and not self.ip_stats[ip]['port_attempts']:
                del self.ip_stats[ip]
