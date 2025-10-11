"""
Alert Manager for IDS
Thread-safe alert handling, logging, and statistics
"""

import threading
from datetime import datetime
from collections import defaultdict
import json
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AlertManager:
    def __init__(self, log_dir='logs'):
        self.alerts = []
        self.lock = threading.Lock()
        self.log_dir = log_dir
        self.statistics = defaultdict(int)
        self.max_alerts = 1000
        
        os.makedirs(log_dir, exist_ok=True)
        
        self.alert_log_file = os.path.join(log_dir, 'alerts.log')
    
    def add_alert(self, source, alert_type, severity, description, additional_data=None):
        """Add a new alert to the system"""
        with self.lock:
            timestamp = datetime.now()
            
            alert = {
                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'source': source,
                'type': alert_type,
                'severity': severity,
                'description': description,
                'additional_data': additional_data or {}
            }
            
            self.alerts.append(alert)
            
            self.statistics[severity] += 1
            self.statistics['total'] += 1
            
            if len(self.alerts) > self.max_alerts:
                self.alerts = self.alerts[-self.max_alerts:]
            
            self._log_alert(alert)
            
            return alert
    
    def _log_alert(self, alert):
        """Write alert to log file"""
        try:
            with open(self.alert_log_file, 'a') as f:
                log_entry = f"{alert['timestamp']} | {alert['severity']:8s} | {alert['type']:20s} | {alert['source']:15s} | {alert['description']}\n"
                f.write(log_entry)
        except Exception as e:
            logger.error(f"Error writing to alert log: {e}")
    
    def get_recent_alerts(self, limit=50):
        """Get the most recent alerts"""
        with self.lock:
            return self.alerts[-limit:][::-1]
    
    def get_alert_statistics(self):
        """Get statistics about alerts"""
        with self.lock:
            return dict(self.statistics)
    
    def clear_alerts(self):
        """Clear all alerts (for testing or reset)"""
        with self.lock:
            self.alerts = []
            logger.info("All alerts cleared")
    
    def save_alerts_to_file(self, filename=None):
        """Save alerts to a JSON file"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = os.path.join(self.log_dir, f'alerts_export_{timestamp}.json')
        
        with self.lock:
            try:
                with open(filename, 'w') as f:
                    json.dump({
                        'export_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'total_alerts': len(self.alerts),
                        'statistics': dict(self.statistics),
                        'alerts': self.alerts
                    }, f, indent=2)
                
                logger.info(f"Alerts saved to {filename}")
                return filename
            except Exception as e:
                logger.error(f"Error saving alerts: {e}")
                return None
    
    def filter_alerts_by_severity(self, severity):
        """Filter alerts by severity level"""
        with self.lock:
            return [alert for alert in self.alerts if alert['severity'] == severity]
    
    def filter_alerts_by_type(self, alert_type):
        """Filter alerts by type"""
        with self.lock:
            return [alert for alert in self.alerts if alert['type'] == alert_type]
    
    def filter_alerts_by_source(self, source):
        """Filter alerts by source IP"""
        with self.lock:
            return [alert for alert in self.alerts if alert['source'] == source]
    
    def get_top_sources(self, limit=10):
        """Get top alert sources"""
        with self.lock:
            source_counts = defaultdict(int)
            for alert in self.alerts:
                source_counts[alert['source']] += 1
            
            sorted_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)
            return sorted_sources[:limit]
