"""
Alert Manager for IDS.

Thread-safe in-memory alert list, file logging (alerts.log), JSON export, and PDF report.
Used by IDSController to store signature and ML alerts; GUI reads via get_recent_alerts.
"""

import glob
import threading
from datetime import datetime
from collections import defaultdict
import json
import os
import logging

from src.config import LOG_DIR

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AlertManager:
    """
    Holds alerts in memory (capped at max_alerts), appends to alerts.log,
    and supports filter/export. All mutations are under self.lock.
    """

    def __init__(self, log_dir=None):
        self.alerts = []
        self.lock = threading.Lock()
        self.statistics = defaultdict(int)  # severity -> count, plus 'total'
        self.max_alerts = 1000  # Rotate oldest out when exceeded
        self.log_dir = log_dir or LOG_DIR

        os.makedirs(self.log_dir, exist_ok=True)

        self.alert_log_file = os.path.join(self.log_dir, 'alerts.log')

    def add_alert(self, source, alert_type, severity, description, additional_data=None):
        """Append one alert; update stats; write line to alerts.log."""
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
        """Clear all alerts (for testing or reset) and reset statistics."""
        with self.lock:
            self.alerts = []
            self.statistics = defaultdict(int)
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

    def clear_logs_to_disk(self):
        """Remove all non-essential log and export files from the logs directory."""
        removed = []
        try:
            for path in glob.glob(os.path.join(self.log_dir, "alerts.log")):
                os.remove(path)
                removed.append(path)
            for path in glob.glob(os.path.join(self.log_dir, "alerts_export_*.json")):
                os.remove(path)
                removed.append(path)
            if removed:
                logger.info(f"Cleared log files: {len(removed)} file(s)")
            return removed
        except Exception as e:
            logger.error(f"Error clearing logs: {e}")
            return []

    def save_alerts_to_pdf(self, filepath=None):
        """Save current alerts and statistics as a PDF report. Returns path or None."""
        try:
            from fpdf import FPDF
        except ImportError:
            logger.error("fpdf2 is required for PDF export. Install with: pip install fpdf2")
            return None
        if filepath is None:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            filepath = os.path.join(self.log_dir, f'HybridGuard_Report_{ts}.pdf')
        with self.lock:
            stats = dict(self.statistics)
            alerts = list(self.alerts)
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=10)
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "HybridGuard IDS Report", ln=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Summary", ln=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, f"Total alerts: {stats.get('total', 0)}  |  Critical: {stats.get('CRITICAL', 0)}  |  High: {stats.get('HIGH', 0)}  |  Medium: {stats.get('MEDIUM', 0)}  |  Low: {stats.get('LOW', 0)}", ln=True)
        pdf.ln(6)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Alerts", ln=True)
        pdf.set_font("Helvetica", "", 9)
        col_w = (28, 22, 32, 22, 86)  # Time, Source, Type, Severity, Description
        headers = ("Time", "Source", "Type", "Severity", "Description")
        for h in headers:
            pdf.cell(col_w[headers.index(h)], 7, h[:14], border=1, fill=True)
        pdf.ln()
        for alert in alerts[:200]:
            t = str(alert.get("timestamp", ""))[:18]
            src = str(alert.get("source", ""))[:18]
            typ = str(alert.get("type", ""))[:28]
            sev = str(alert.get("severity", ""))[:18]
            desc = str(alert.get("description", ""))[:82]
            pdf.cell(col_w[0], 6, t, border=1)
            pdf.cell(col_w[1], 6, src, border=1)
            pdf.cell(col_w[2], 6, typ, border=1)
            pdf.cell(col_w[3], 6, sev, border=1)
            pdf.cell(col_w[4], 6, desc, border=1)
            pdf.ln()
        if len(alerts) > 200:
            pdf.cell(0, 6, f"... and {len(alerts) - 200} more alerts.", ln=True)
        try:
            pdf.output(filepath)
            logger.info(f"PDF report saved to {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Error saving PDF: {e}")
            return None
