import psutil
import time
from datetime import datetime
import logging
from collections import defaultdict
import requests
import matplotlib.pyplot as plt
import numpy as np
from scapy.all import *
from sklearn.ensemble import IsolationForest
import re
import json
import threading
from concurrent.futures import ThreadPoolExecutor

class AdvancedNetworkMonitor:
    def __init__(self):
        self.setup_basic_components()
        self.setup_ml_components()
        self.setup_threat_intelligence()
        self.setup_pattern_detection()
        
    def setup_basic_components(self):
        self.data_points = defaultdict(list)
        self.threat_levels = defaultdict(int)
        self.connection_fingerprints = {}
        self.blocked_ips = set()
        self.setup_logging()
        self.setup_visualization()
        
    def setup_ml_components(self):
        self.anomaly_detector = IsolationForest(contamination=0.1)
        self.behavioral_patterns = []
        
    def setup_threat_intelligence(self):
        self.threat_apis = {
            'virustotal': 'YOUR_API_KEY',
            'abuseipdb': 'YOUR_API_KEY',
            'alienvault': 'YOUR_API_KEY'
        }
        self.known_threats = self.load_threat_database()
        
    def setup_pattern_detection(self):
        self.data_patterns = {
            'credit_cards': re.compile(r'\d{4}-\d{4}-\d{4}-\d{4}'),
            'social_security': re.compile(r'\d{3}-\d{2}-\d{4}'),
            'api_keys': re.compile(r'[a-zA-Z0-9]{32}'),
            'passwords': re.compile(r'password=|pwd=|pass=', re.I)
        }
        
    def analyze_packet(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Deep packet inspection
            if Raw in packet:
                payload = str(packet[Raw].load)
                for pattern_name, pattern in self.data_patterns.items():
                    if pattern.search(payload):
                        self.handle_data_leak(pattern_name, src_ip, dst_ip)
                        
    def handle_data_leak(self, pattern_type, src_ip, dst_ip):
        threat_level = 8  # High priority
        self.log_incident(f"Data leak detected: {pattern_type} from {src_ip} to {dst_ip}")
        self.automated_response(threat_level, src_ip)
        
    def automated_response(self, threat_level, target_ip):
        if threat_level >= 8:
            self.block_ip(target_ip)
            self.send_alert("Critical", f"Blocked IP: {target_ip} due to high threat level")
            self.isolate_system()
        elif threat_level >= 5:
            self.log_incident(f"Warning: Suspicious activity from {target_ip}")
            self.increase_monitoring(target_ip)
            
    def analyze_behavior(self, process_info):
        suspicious_activities = []
        
        # Check process behavior
        if process_info['cpu_percent'] > 80:
            suspicious_activities.append('high_cpu_usage')
        if process_info['memory_percent'] > 70:
            suspicious_activities.append('high_memory_usage')
            
        # Check network behavior
        connections = process_info['connections']
        if len(connections) > self.threshold_connections:
            suspicious_activities.append('excessive_connections')
            
        return suspicious_activities
        
    def monitor_traffic(self):
        print("\033[92m=== Advanced Network Monitor Started ===\033[0m")
        print("\033[93mPress Ctrl+C to stop monitoring\033[0m")
        
        # Start packet capture in separate thread
        sniff_thread = threading.Thread(target=lambda: sniff(prn=self.analyze_packet, store=0))
        sniff_thread.start()
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            while True:
                try:
                    current_time = datetime.now()
                    connections = psutil.net_connections()
                    
                    # Parallel processing of connections
                    futures = []
                    for conn in connections:
                        if conn.status == 'ESTABLISHED':
                            futures.append(executor.submit(self.analyze_connection, conn))
                            
                    # Process results
                    for future in futures:
                        result = future.result()
                        if result['threat_detected']:
                            self.handle_threat(result)
                            
                    # Update visualizations
                    self.update_visualization()
                    time.sleep(1)
                    
                except KeyboardInterrupt:
                    print("\n\033[93mStopping monitor...\033[0m")
                    break
                    
    def analyze_connection(self, connection):
        try:
            process = psutil.Process(connection.pid)
            remote_ip = connection.raddr.ip if connection.raddr else None
            
            if remote_ip:
                # Geo-fencing check
                location = self.get_ip_location(remote_ip)
                if self.check_geofence(location['country']):
                    return {'threat_detected': True, 'type': 'restricted_country'}
                    
                # Threat intelligence check
                if self.check_threat_intelligence(remote_ip):
                    return {'threat_detected': True, 'type': 'known_threat'}
                    
                # Process behavior analysis
                process_info = self.get_process_info(process)
                suspicious_behaviors = self.analyze_behavior(process_info)
                
                if suspicious_behaviors:
                    return {
                        'threat_detected': True,
                        'type': 'suspicious_behavior',
                        'details': suspicious_behaviors
                    }
                    
            return {'threat_detected': False}
            
        except Exception as e:
            logging.error(f"Error analyzing connection: {str(e)}")
            return {'threat_detected': False}
            
    def handle_threat(self, threat_info):
        if threat_info['type'] == 'restricted_country':
            self.automated_response(7, threat_info.get('ip'))
        elif threat_info['type'] == 'known_threat':
            self.automated_response(9, threat_info.get('ip'))
        elif threat_info['type'] == 'suspicious_behavior':
            self.automated_response(6, threat_info.get('ip'))

if __name__ == "__main__":
    monitor = AdvancedNetworkMonitor()
    monitor.monitor_traffic()
