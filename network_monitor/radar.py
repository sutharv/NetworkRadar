import time
from datetime import datetime
from collections import defaultdict
import logging
import statistics
import numpy as np
from sklearn.ensemble import IsolationForest
from typing import Dict, List, Optional

from config import (
    KNOWN_MALICIOUS_ORGS,
    DATA_EXFILTRATION_THRESHOLD,
    RAPID_CONNECTIONS_THRESHOLD,
    THREAT_LEVEL_THRESHOLDS,
    SUSPICIOUS_PORTS
)

class NetworkRadar:
    def __init__(self):
        self.org_history = defaultdict(lambda: {
            'connections': 0,
            'data_transferred': 0,
            'timestamps': [],
            'blocked_attempts': 0,
            'events': [],
            'ports_accessed': set(),
            'ip_addresses': set()
        })
        self.setup_logging()
        self.anomaly_detector = None
        self.baseline_data = defaultdict(dict)

    def setup_logging(self):
        self.logger = logging.getLogger('NetworkRadar')
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler('radar_alerts.log')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def train_anomaly_detector(self):
        """Train anomaly detection model on historical traffic patterns"""
        if len(self.org_history) < 2:
            return
            
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        features = [
            [org['data_transferred'], len(org['timestamps'])] 
            for org in self.org_history.values()
        ]
        self.anomaly_detector.fit(features)

    def calculate_baseline(self, org_name: str, window_size: int = 24) -> Dict:
        """Calculate normal traffic baseline for organization"""
        org_data = self.org_history[org_name]
        hourly_traffic = defaultdict(list)
        
        for timestamp in org_data['timestamps']:
            hour = timestamp.hour
            hourly_traffic[hour].append(org_data['data_transferred'])
            
        self.baseline_data[org_name] = {
            hour: statistics.mean(traffic) if traffic else 0
            for hour, traffic in hourly_traffic.items()
        }
        return self.baseline_data[org_name]

    def detect_attack_pattern(self, org_name: str, timestamp: datetime) -> Dict:
        """Detect known attack patterns in traffic"""
        org_data = self.org_history[org_name]
        window = 300  # 5 minutes in seconds

        recent_connections = len([
            ts for ts in org_data['timestamps']
            if (timestamp - ts).total_seconds() < window
        ])

        patterns = {
            'dos_attack': recent_connections > RAPID_CONNECTIONS_THRESHOLD * 2,
            'port_scan': len(org_data['ports_accessed']) > 10,
            'brute_force': org_data['blocked_attempts'] > 5
        }
        return patterns

    def correlate_events(self, org_name: str, window_minutes: int = 5) -> float:
        """Correlate multiple security events within time window"""
        current_time = datetime.now()
        org_data = self.org_history[org_name]
        
        recent_events = [
            event for event in org_data['events']
            if (current_time - event['timestamp']).total_seconds() < window_minutes * 60
        ]
        
        if not recent_events:
            return 0.0
            
        return len(recent_events) / window_minutes

    def analyze_traffic(self, org_name: str, bytes_transferred: int, 
                       timestamp: datetime, port: Optional[int] = None,
                       ip_address: Optional[str] = None) -> Dict:
        """Enhanced traffic analysis with multiple detection methods"""
        org_data = self.org_history[org_name]
        org_data['connections'] += 1
        org_data['data_transferred'] += bytes_transferred
        org_data['timestamps'].append(timestamp)
        
        if port:
            org_data['ports_accessed'].add(port)
        if ip_address:
            org_data['ip_addresses'].add(ip_address)

        # Clean up old timestamps (older than 1 hour)
        org_data['timestamps'] = [
            ts for ts in org_data['timestamps']
            if (timestamp - ts).total_seconds() < 3600
        ]

        threat_assessment = {
            'threat_level': 0,
            'details': [],
            'recommendations': [],
            'confidence_score': 0.0
        }

        self._check_known_malicious(org_name, threat_assessment)
        self._check_data_exfiltration(bytes_transferred, org_name, threat_assessment)
        self._check_rapid_connections(org_data, timestamp, threat_assessment)
        self._check_suspicious_ports(port, threat_assessment)
        self._check_attack_patterns(org_name, timestamp, threat_assessment)
        self._check_anomalies(org_name, threat_assessment)

        threat_assessment['confidence_score'] = self._calculate_confidence_score(threat_assessment)

        if threat_assessment['threat_level'] >= THREAT_LEVEL_THRESHOLDS['HIGH']:
            org_data['blocked_attempts'] += 1
            org_data['events'].append({
                'timestamp': timestamp,
                'threat_level': threat_assessment['threat_level'],
                'details': threat_assessment['details']
            })
            self.logger.error(
                f"High threat level detected from {org_name}. "
                f"Total blocked attempts: {org_data['blocked_attempts']}"
            )

        return threat_assessment

    def _check_known_malicious(self, org_name: str, assessment: Dict):
        if org_name in KNOWN_MALICIOUS_ORGS:
            assessment['threat_level'] += THREAT_LEVEL_THRESHOLDS['HIGH']
            assessment['details'].append(f"Known suspicious organization: {org_name}")
            assessment['recommendations'].append("Block all traffic from this organization")

    def _check_data_exfiltration(self, bytes_transferred: int, org_name: str, assessment: Dict):
        if bytes_transferred > DATA_EXFILTRATION_THRESHOLD:
            assessment['threat_level'] += THREAT_LEVEL_THRESHOLDS['MEDIUM']
            assessment['details'].append(
                f"High data transfer: {bytes_transferred/1024/1024:.2f} MB"
            )
            assessment['recommendations'].append(
                "Monitor and potentially limit bandwidth for this connection"
            )

    def _check_rapid_connections(self, org_data: Dict, timestamp: datetime, assessment: Dict):
        recent_connections = len([
            t for t in org_data['timestamps']
            if (timestamp - t).total_seconds() < 60
        ])
        if recent_connections > RAPID_CONNECTIONS_THRESHOLD:
            assessment['threat_level'] += THREAT_LEVEL_THRESHOLDS['MEDIUM']
            assessment['details'].append(
                f"Rapid connections: {recent_connections} in last minute"
            )
            assessment['recommendations'].append("Implement connection rate limiting")

    def _check_suspicious_ports(self, port: Optional[int], assessment: Dict):
        if port and port in SUSPICIOUS_PORTS:
            assessment['threat_level'] += THREAT_LEVEL_THRESHOLDS['LOW']
            assessment['details'].append(f"Suspicious port detected: {port}")
            assessment['recommendations'].append(
                f"Consider blocking port {port} if not required"
            )

    def _check_attack_patterns(self, org_name: str, timestamp: datetime, assessment: Dict):
        patterns = self.detect_attack_pattern(org_name, timestamp)
        for pattern_name, detected in patterns.items():
            if detected:
                assessment['threat_level'] += THREAT_LEVEL_THRESHOLDS['HIGH']
                assessment['details'].append(f"Detected {pattern_name.replace('_', ' ')}")
                assessment['recommendations'].append(
                    f"Investigate potential {pattern_name.replace('_', ' ')}"
                )

    def _check_anomalies(self, org_name: str, assessment: Dict):
        if self.anomaly_detector and org_name in self.org_history:
            org_data = self.org_history[org_name]
            features = [[org_data['data_transferred'], len(org_data['timestamps'])]]
            if self.anomaly_detector.predict(features)[0] == -1:
                assessment['threat_level'] += THREAT_LEVEL_THRESHOLDS['MEDIUM']
                assessment['details'].append("Anomalous traffic pattern detected")

    def _calculate_confidence_score(self, assessment: Dict) -> float:
        evidence_points = len(assessment['details'])
        max_threat = max(THREAT_LEVEL_THRESHOLDS.values())
        return min(1.0, (evidence_points * assessment['threat_level']) / (max_threat * 2))

    def get_organization_stats(self, org_name: str) -> Optional[Dict]:
        """Returns enhanced statistical analysis for an organization"""
        if org_name not in self.org_history:
            return None

        org_data = self.org_history[org_name]
        return {
            'total_connections': org_data['connections'],
            'total_data_transferred': org_data['data_transferred'],
            'blocked_attempts': org_data['blocked_attempts'],
            'connection_frequency': len(org_data['timestamps']),
            'first_seen': min(org_data['timestamps']) if org_data['timestamps'] else None,
            'last_seen': max(org_data['timestamps']) if org_data['timestamps'] else None,
            'unique_ports': len(org_data['ports_accessed']),
            'unique_ips': len(org_data['ip_addresses']),
            'recent_events': len(org_data['events'])
        }
