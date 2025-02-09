import psutil
import socket
from collections import defaultdict

class NetworkAnalyzer:
    @staticmethod
    def get_process_info(pid):
        try:
            process = psutil.Process(pid)
            return {
                'name': process.name(),
                'cpu_percent': process.cpu_percent(),
                'memory_percent': process.memory_percent()
            }
        except:
            return None

    @staticmethod
    def get_connection_info(connection):
        if connection.status == 'ESTABLISHED':
            try:
                remote_ip = connection.raddr.ip
                remote_port = connection.raddr.port
                try:
                    hostname = socket.gethostbyaddr(remote_ip)[0]
                except:
                    hostname = "Unknown"
                
                process_info = NetworkAnalyzer.get_process_info(connection.pid)
                
                return {
                    'ip': remote_ip,
                    'port': remote_port,
                    'hostname': hostname,
                    'process_info': process_info
                }
            except:
                return None
        return None
