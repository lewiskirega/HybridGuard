"""
Tkinter GUI for HybridGuard IDS.

Dashboard: packet count, alert counts by severity, filterable alert table,
system log panel. Start/Stop Monitoring, Clear Alerts, Export Alerts.
Updates every second from a background thread via root.after().
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IDSGUI:
    """
    Main window: control panel, stats, alert table (filter by severity), log area.
    Binds to IDSController for start/stop, get_recent_alerts, get_statistics, export.
    """

    def __init__(self, root, ids_controller=None):
        self.root = root
        self.root.title("Hybrid Intrusion Detection System")
        self.root.geometry("1400x800")

        self.ids_controller = ids_controller
        self.monitoring = False
        self.update_thread = None
        self.running = True

        # Row background colors in alert table by severity
        self.severity_colors = {
            'CRITICAL': '#e74c3c',
            'HIGH': '#e67e22',
            'MEDIUM': '#f39c12',
            'LOW': '#3498db',
            'INFO': '#95a5a6'
        }
        
        self._create_widgets()
        self._setup_update_loop()
    
    def _create_widgets(self):
        """Build control panel, dashboard stats, alert treeview, and log text area."""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        control_frame = ttk.LabelFrame(main_frame, text="Control Panel", padding="10")
        control_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.start_button = ttk.Button(control_frame, text="Start Monitoring", command=self._start_monitoring)
        self.start_button.grid(row=0, column=0, padx=5)
        
        self.stop_button = ttk.Button(control_frame, text="Stop Monitoring", command=self._stop_monitoring, state='disabled')
        self.stop_button.grid(row=0, column=1, padx=5)
        
        ttk.Label(control_frame, text="Status:").grid(row=0, column=2, padx=(20, 5))
        self.status_label = ttk.Label(control_frame, text="Offline", foreground="red")
        self.status_label.grid(row=0, column=3, padx=5)
        
        ttk.Button(control_frame, text="Clear Alerts", command=self._clear_alerts).grid(row=0, column=4, padx=5)
        ttk.Button(control_frame, text="Export Alerts", command=self._export_alerts).grid(row=0, column=5, padx=5)
        
        dashboard_frame = ttk.LabelFrame(main_frame, text="Dashboard", padding="10")
        dashboard_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        stats_frame = ttk.Frame(dashboard_frame)
        stats_frame.pack(fill=tk.BOTH)
        
        self.packet_count_label = self._create_stat_widget(stats_frame, "Packets Analyzed", "0", 0)
        self.alert_count_label = self._create_stat_widget(stats_frame, "Total Alerts", "0", 1)
        self.critical_count_label = self._create_stat_widget(stats_frame, "Critical", "0", 2, fg='#e74c3c')
        self.high_count_label = self._create_stat_widget(stats_frame, "High", "0", 3, fg='#e67e22')
        self.medium_count_label = self._create_stat_widget(stats_frame, "Medium", "0", 4, fg='#f39c12')
        
        alerts_frame = ttk.LabelFrame(main_frame, text="Alerts", padding="10")
        alerts_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        alert_controls = ttk.Frame(alerts_frame)
        alert_controls.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(alert_controls, text="Filter:").pack(side=tk.LEFT, padx=(0, 5))
        self.filter_var = tk.StringVar(value="ALL")
        filter_combo = ttk.Combobox(alert_controls, textvariable=self.filter_var, 
                                    values=["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"], 
                                    state='readonly', width=15)
        filter_combo.pack(side=tk.LEFT, padx=(0, 10))
        filter_combo.bind('<<ComboboxSelected>>', lambda e: self._update_alerts_display())
        
        tree_frame = ttk.Frame(alerts_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar_y = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        
        scrollbar_x = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
        
        columns = ('Time', 'Source', 'Type', 'Severity', 'Description')
        self.alerts_tree = ttk.Treeview(tree_frame, columns=columns, show='headings',
                                       yscrollcommand=scrollbar_y.set,
                                       xscrollcommand=scrollbar_x.set)
        
        scrollbar_y.config(command=self.alerts_tree.yview)
        scrollbar_x.config(command=self.alerts_tree.xview)
        
        self.alerts_tree.heading('Time', text='Time')
        self.alerts_tree.heading('Source', text='Source IP')
        self.alerts_tree.heading('Type', text='Alert Type')
        self.alerts_tree.heading('Severity', text='Severity')
        self.alerts_tree.heading('Description', text='Description')
        
        self.alerts_tree.column('Time', width=150)
        self.alerts_tree.column('Source', width=130)
        self.alerts_tree.column('Type', width=150)
        self.alerts_tree.column('Severity', width=100)
        self.alerts_tree.column('Description', width=500)
        
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self._create_tags()
        
        log_frame = ttk.LabelFrame(main_frame, text="System Logs", padding="10")
        log_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, state='disabled')
        self.log_text.pack(fill=tk.BOTH, expand=True)
    
    def _create_stat_widget(self, parent, label, value, column, fg='black'):
        """Create a statistics widget"""
        frame = ttk.Frame(parent)
        frame.grid(row=0, column=column, padx=10, pady=5)
        
        ttk.Label(frame, text=label, font=('Arial', 9)).pack()
        value_label = ttk.Label(frame, text=value, font=('Arial', 16, 'bold'), foreground=fg)
        value_label.pack()
        
        return value_label
    
    def _create_tags(self):
        """Create tags for coloring alert rows"""
        for severity, color in self.severity_colors.items():
            self.alerts_tree.tag_configure(severity, background=color, foreground='white')
    
    def _start_monitoring(self):
        """Start IDS monitoring"""
        if self.ids_controller:
            success = self.ids_controller.start()
            if success:
                self.monitoring = True
                self.start_button.config(state='disabled')
                self.stop_button.config(state='normal')
                self.status_label.config(text="Online", foreground="green")
                self._log_message("Monitoring started")
            else:
                messagebox.showerror(
                    "Failed to start monitoring",
                    "Packet capture requires root/administrator privileges.\n\n"
                    "Linux/macOS: run in terminal:\n  sudo python main.py\n\n"
                    "Windows: run terminal as Administrator.\n\n"
                    "You can still test detection using: python tests/test_detection.py"
                )
        else:
            self._log_message("No IDS controller available")
    
    def _stop_monitoring(self):
        """Stop IDS monitoring"""
        if self.ids_controller:
            self.ids_controller.stop()
        
        self.monitoring = False
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.status_label.config(text="Offline", foreground="red")
        self._log_message("Monitoring stopped")
    
    def _clear_alerts(self):
        """Clear all alerts"""
        if messagebox.askyesno("Clear Alerts", "Are you sure you want to clear all alerts?"):
            if self.ids_controller:
                self.ids_controller.clear_alerts()
            
            for item in self.alerts_tree.get_children():
                self.alerts_tree.delete(item)
            
            self._log_message("Alerts cleared")
            self._update_statistics()
    
    def _export_alerts(self):
        """Export alerts to file"""
        if self.ids_controller:
            filename = self.ids_controller.export_alerts()
            if filename:
                self._log_message(f"Alerts exported to {filename}")
                messagebox.showinfo("Export Success", f"Alerts exported to:\n{filename}")
    
    def _update_alerts_display(self):
        """Update the alerts display"""
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        
        if not self.ids_controller:
            return
        
        alerts = self.ids_controller.get_recent_alerts()
        filter_severity = self.filter_var.get()
        
        for alert in alerts:
            if filter_severity != "ALL" and alert['severity'] != filter_severity:
                continue
            
            self.alerts_tree.insert('', 0, values=(
                alert['timestamp'],
                alert['source'],
                alert['type'],
                alert['severity'],
                alert['description']
            ), tags=(alert['severity'],))
    
    def _update_statistics(self):
        """Update dashboard statistics"""
        if not self.ids_controller:
            return
        
        stats = self.ids_controller.get_statistics()
        
        self.packet_count_label.config(text=str(stats.get('packets', 0)))
        self.alert_count_label.config(text=str(stats.get('total', 0)))
        self.critical_count_label.config(text=str(stats.get('CRITICAL', 0)))
        self.high_count_label.config(text=str(stats.get('HIGH', 0)))
        self.medium_count_label.config(text=str(stats.get('MEDIUM', 0)))
    
    def _log_message(self, message):
        """Add message to system log"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_entry = f"[{timestamp}] {message}\n"
        
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')
    
    def _setup_update_loop(self):
        """Start a daemon thread that refreshes alerts and stats every 1s while monitoring."""
        def update_loop():
            while self.running:
                if self.monitoring:
                    try:
                        self.root.after(0, self._update_alerts_display)
                        self.root.after(0, self._update_statistics)
                    except Exception as e:
                        logger.error(f"Error updating GUI: {e}")
                time.sleep(1)
        
        self.update_thread = threading.Thread(target=update_loop, daemon=True)
        self.update_thread.start()
    
    def close(self):
        """Clean up and close GUI"""
        self.running = False
        if self.monitoring:
            self._stop_monitoring()
        self.root.quit()
