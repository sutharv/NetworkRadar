import psutil
import time
from datetime import datetime
import logging
import requests
import matplotlib.pyplot as plt
from collections import defaultdict

from radar import NetworkRadar
from traffic_guard import TrafficGuard
from network_analyzer import NetworkAnalyzer
from config import (
    BANDWIDTH_THRESHOLD,
    MONITORING_INTERVAL,
    GRAPH_UPDATE_INTERVAL,
    MAX_DATA_POINTS,
    FIGURE_SIZE,
    IP_GEOLOCATION_API,
    API_TIMEOUT,
    TRAFFIC_GRAPH_FILE
)

class NetworkMonitor:
    def __init__(self):
        self.data_points = {
            'time': [],
            'sent': [],
            'received': []
        }
        self.connection_history = defaultdict(int)
        
        # Initialize components
        self.radar = NetworkRadar()
        self.guard = TrafficGuard()
        self.analyzer = NetworkAnalyzer()
        
        self.setup_visualization()
        self.logger = logging.getLogger('NetworkMonitor')

    def setup_visualization(self):
        """Initialize matplotlib visualization"""
        try:
            plt.ion()  # Enable interactive mode
            self.fig, (self.ax1, self.ax2) = plt.subplots(2, 1, figsize=FIGURE_SIZE)
            self.fig.canvas.manager.set_window_title('Network Traffic Monitor')
        except Exception as e:
            self.logger.error(f"Failed to setup visualization: {str(e)}")
            print("\033[91mWarning: Running in headless mode - visualization disabled\033[0m")
            self.fig = None

    def get_ip_location(self, ip):
        """Get geolocation information for an IP address"""
        try:
            response = requests.get(
                f'{IP_GEOLOCATION_API}{ip}',
                timeout=API_TIMEOUT
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'latitude': data.get('lat', 0),
                    'longitude': data.get('lon', 0)
                }
        except requests.RequestException as e:
            self.logger.warning(f"Failed to get IP location for {ip}: {str(e)}")
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'org': 'Unknown',
            'isp': 'Unknown',
            'latitude': 0,
            'longitude': 0
        }

    def update_visualization(self):
        """Update the network traffic visualization"""
        if not self.fig:
            return

        try:
            self.ax1.clear()
            self.ax2.clear()
            
            # Plot network traffic
            self.ax1.plot(
                self.data_points['time'],
                self.data_points['sent'],
                label='Upload',
                color='green',
                linewidth=2
            )
            self.ax1.plot(
                self.data_points['time'],
                self.data_points['received'],
                label='Download',
                color='blue',
                linewidth=2
            )
            self.ax1.set_title('Network Traffic Monitor')
            self.ax1.set_ylabel('KB/s')
            self.ax1.grid(True)
            self.ax1.legend()
            
            # Limit data points for better visualization
            if len(self.data_points['time']) > MAX_DATA_POINTS:
                for key in self.data_points:
                    self.data_points[key] = self.data_points[key][-MAX_DATA_POINTS:]
            
            plt.tight_layout()
            plt.draw()
            plt.pause(0.1)
        except Exception as e:
            self.logger.error(f"Failed to update visualization: {str(e)}")

    def print_connection_info(self, connection_info, location_info, threat_data):
        """Print formatted connection information"""
        if not connection_info or not connection_info['process_info']:
            return

        process_info = connection_info['process_info']
        print(f"\033[97m{'='*50}")
        print(f"Process: {process_info['name']}")
        print(f"Remote IP: {connection_info['ip']}")
        print(f"Port: {connection_info['port']}")
        print(f"Hostname: {connection_info['hostname']}")
        print(f"Location: {location_info['city']}, {location_info['country']}")
        print(f"Organization: {location_info['org']}")
        print(f"ISP: {location_info['isp']}")
        print(f"CPU Usage: {process_info['cpu_percent']}%")
        print(f"Memory Usage: {process_info['memory_percent']:.1f}%\033[0m")
        
        if threat_data['threat_level'] > 0:
            print("\033[91m🚨 SUSPICIOUS ACTIVITY DETECTED 🚨")
            print(self.radar.generate_threat_report(
                location_info['org'],
                threat_data
            ))
            print("\033[0m")

    def monitor_traffic(self, duration):
        """Main monitoring loop"""
        start_time = time.time()
        previous_counter = psutil.net_io_counters()
        
        while time.time() - start_time < duration:
            try:
                time.sleep(MONITORING_INTERVAL)
                current_time = datetime.now().strftime('%H:%M:%S')
                current_counter = psutil.net_io_counters()

                # Calculate bandwidth
                bytes_sent = current_counter.bytes_sent - previous_counter.bytes_sent
                bytes_recv = current_counter.bytes_recv - previous_counter.bytes_recv

                # Update data points for visualization
                self.data_points['time'].append(current_time)
                self.data_points['sent'].append(bytes_sent/1024)
                self.data_points['received'].append(bytes_recv/1024)

                # Clear screen and print header
                print("\033[H\033[J")  # Clear screen
                print(f"\033[95m{'='*50}")
                print(f"Timestamp: {current_time}")
                print(f"Upload: {bytes_sent/1024:.2f} KB/s")
                print(f"Download: {bytes_recv/1024:.2f} KB/s")
                print(f"{'='*50}\033[0m")

                # Monitor active connections
                print("\n\033[96mActive Network Connections:\033[0m")
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status == 'ESTABLISHED':
                        # Get connection details
                        connection_info = self.analyzer.get_connection_info(conn)
                        if not connection_info:
                            continue

                        # Get location information
                        location_info = self.get_ip_location(connection_info['ip'])

                        # Check for suspicious activity
                        if self.guard.is_traffic_suspicious(
                            bytes_sent,
                            bytes_recv,
                            conn
                        ):
                            self.guard.block_connection(conn)
                            continue

                        # Analyze traffic with radar
                        threat_data = self.radar.analyze_traffic(
                            location_info['org'],
                            bytes_sent + bytes_recv,
                            datetime.now(),
                            connection_info['port']
                        )

                        # Print connection information
                        self.print_connection_info(
                            connection_info,
                            location_info,
                            threat_data
                        )

                # Update visualization
                self.update_visualization()
                
                # Log traffic data
                self.logger.info(
                    f"Upload: {bytes_sent/1024:.2f} KB/s, "
                    f"Download: {bytes_recv/1024:.2f} KB/s"
                )
                
                previous_counter = current_counter

            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {str(e)}")
                print(f"\033[91mError occurred: {str(e)}\033[0m")
                continue

        # Save final visualization
        if self.fig:
            try:
                plt.savefig(TRAFFIC_GRAPH_FILE)
                print(f"\n\033[92mFinal visualization saved as '{TRAFFIC_GRAPH_FILE}'\033[0m")
            except Exception as e:
                self.logger.error(f"Failed to save visualization: {str(e)}")
