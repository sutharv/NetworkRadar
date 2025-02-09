# Network monitoring thresholds
BANDWIDTH_THRESHOLD = 5000000  # 5MB/s
MAX_CONNECTIONS_PER_IP = 100
MONITORING_INTERVAL = 1  # seconds
DEFAULT_DURATION = 3600  # 1 hour

# Visualization settings
GRAPH_UPDATE_INTERVAL = 1  # seconds
MAX_DATA_POINTS = 30
FIGURE_SIZE = (12, 8)

# Logging configuration
LOG_FILE = 'network_traffic.log'
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
TRAFFIC_GRAPH_FILE = 'network_traffic_final.png'

# Suspicious activity detection
SUSPICIOUS_PORTS = {
    20, 21,     # FTP
    22,         # SSH
    23,         # Telnet
    25,         # SMTP
    53,         # DNS
    67, 68,     # DHCP
    80, 443,    # HTTP/HTTPS
    445,        # SMB
    1433, 1434, # MSSQL
    3306,       # MySQL
    3389,       # RDP
    4444,       # Common backdoor
    5900,       # VNC
    6667, 6668, 6669,  # IRC
    8080, 8443, # Web proxies
    31337       # Back Orifice
}

# Network security settings
BLACKLISTED_IPS = [
    '0.0.0.0/0'  # Replace with your blacklisted IPs
]

KNOWN_MALICIOUS_ORGS = {
    'Example Malicious Org'  # Replace with your known malicious organizations
}

# High risk countries (ISO country codes)
HIGH_RISK_COUNTRIES = {
    'XX'  # Replace with your high risk country codes
}

# Threat detection thresholds
DATA_EXFILTRATION_THRESHOLD = 1048576  # 1MB/s
RAPID_CONNECTIONS_THRESHOLD = 50  # connections per minute
THREAT_LEVEL_THRESHOLDS = {
    'LOW': 1,
    'MEDIUM': 2,
    'HIGH': 3
}

# Machine Learning settings
ANOMALY_DETECTION = {
    'TRAINING_WINDOW': 24 * 60 * 60,  # 24 hours in seconds
    'CONTAMINATION': 0.1,
    'RANDOM_STATE': 42
}

# API Configuration
IP_GEOLOCATION_API = 'http://ip-api.com/json/'
API_TIMEOUT = 2  # seconds
MAX_RETRIES = 3

# Alert thresholds
ALERT_THRESHOLDS = {
    'CPU_USAGE': 80,  # percentage
    'MEMORY_USAGE': 85,  # percentage
    'DISK_USAGE': 90,  # percentage
    'NETWORK_LATENCY': 100  # milliseconds
}

# Performance monitoring
PERFORMANCE_METRICS = {
    'SAMPLE_INTERVAL': 60,  # seconds
    'HISTORY_SIZE': 1000,   # data points
    'ALERT_COOLDOWN': 300   # seconds
}

# Database settings
DB_CONFIG = {
    'HOST': 'localhost',
    'PORT': 5432,
    'NAME': 'network_monitor',
    'USER': 'your_username',
    'PASSWORD': 'your_password'
}

# Email notification settings
EMAIL_CONFIG = {
    'SMTP_SERVER': 'smtp.example.com',
    'SMTP_PORT': 587,
    'USE_TLS': True,
    'SENDER': 'alerts@example.com',
    'RECIPIENTS': ['admin@example.com']
}
