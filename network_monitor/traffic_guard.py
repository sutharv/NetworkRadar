import psutil
import time
from collections import defaultdict

class TrafficGuard:
    def __init__(self):
        self.suspicious_patterns = {
            'high_volume': 5000000,  # 5MB/s threshold
            'unusual_ports': [6667, 6668, 6669, 4444, 31337],  # Known malicious ports
            'max_connections': 100,
            'blacklisted_ips': set()
        }
        self.connection_history = defaultdict(int)
        
    def load_blacklist(self):
        # Add known malicious IPs
        self.suspicious_patterns['blacklisted_ips'].update([
            '185.147.34.0/24',
            '192.168.0.100',
            # Add more IPs as needed
        ])

    def is_traffic_suspicious(self, bytes_sent, bytes_recv, connection):
        # Check for high volume transfers
        if bytes_sent > self.suspicious_patterns['high_volume'] or bytes_recv > self.suspicious_patterns['high_volume']:
            print("\033[91m[ALERT] Suspicious high volume traffic detected! Blocking transfer...\033[0m")
            return True

        # Check for suspicious ports
        if connection.raddr and connection.raddr.port in self.suspicious_patterns['unusual_ports']:
            print(f"\033[91m[ALERT] Suspicious port {connection.raddr.port} detected! Blocking connection...\033[0m")
            return True

        # Check connection frequency
        if connection.raddr:
            self.connection_history[connection.raddr.ip] += 1
            if self.connection_history[connection.raddr.ip] > self.suspicious_patterns['max_connections']:
                print(f"\033[91m[ALERT] Too many connections from {connection.raddr.ip}! Blocking...\033[0m")
                return True

        return False

    def block_connection(self, connection):
        try:
            process = psutil.Process(connection.pid)
            process.terminate()
            print(f"\033[92mBlocked suspicious connection from process: {process.name()}\033[0m")
            return True
        except:
            return False
