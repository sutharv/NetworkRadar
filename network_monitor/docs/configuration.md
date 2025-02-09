# Configuration Guide

The system's behavior can be customized through various settings in `config.py`.

## Network Thresholds

```python
BANDWIDTH_THRESHOLD = 5000000  # 5MB/s
MAX_CONNECTIONS_PER_IP = 100
MONITORING_INTERVAL = 1  # seconds
DEFAULT_DURATION = 3600  # 1 hour
```

## Security Settings

### Suspicious Ports
The system monitors connections on commonly exploited ports:
- FTP (20, 21)
- SSH (22)
- Telnet (23)
- SMTP (25)
- DNS (53)
- HTTP/HTTPS (80, 443)
- And more...

### Threat Detection

```python
DATA_EXFILTRATION_THRESHOLD = 1048576  # 1MB/s
RAPID_CONNECTIONS_THRESHOLD = 50  # connections per minute
THREAT_LEVEL_THRESHOLDS = {
    'LOW': 1,
    'MEDIUM': 2,
    'HIGH': 3
}
```

### Geographic Monitoring
```python
HIGH_RISK_COUNTRIES = {
    'NK',  # North Korea
    'IR',  # Iran
    'RU',  # Russia
    'CN',  # China
    'BY',  # Belarus
    'SY'   # Syria
}
```

## Visualization Settings

```python
GRAPH_UPDATE_INTERVAL = 1  # seconds
MAX_DATA_POINTS = 30
FIGURE_SIZE = (12, 8)
```

## Alert Configuration

```python
ALERT_THRESHOLDS = {
    'CPU_USAGE': 80,  # percentage
    'MEMORY_USAGE': 85,  # percentage
    'DISK_USAGE': 90,  # percentage
    'NETWORK_LATENCY': 100  # milliseconds
}
```

## Logging Configuration

```python
LOG_FILE = 'network_traffic.log'
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
```

## API Settings

```python
IP_GEOLOCATION_API = 'http://ip-api.com/json/'
API_TIMEOUT = 2  # seconds
MAX_RETRIES = 3
