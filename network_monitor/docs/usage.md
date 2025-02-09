# Usage Guide

## Basic Usage

1. Start the monitor:
```bash
python main.py
```

2. Monitor output includes:
   - Real-time traffic statistics
   - Active connections
   - Security alerts
   - System performance

## Reading the Display

### Traffic Statistics
```
==================================================
Timestamp: 14:30:45
Upload: 256.45 KB/s
Download: 1024.78 KB/s
==================================================
```

### Connection Information
For each active connection:
- Process name
- Remote IP
- Port number
- Geographic location
- Organization
- ISP
- Resource usage

### Security Alerts
Red alerts indicate suspicious activity:
```
🚨 SUSPICIOUS ACTIVITY DETECTED 🚨
- Threat Level: HIGH
- Details: Rapid connection attempts
- Recommendation: Implement rate limiting
```

## Visualization

The system provides real-time graphs:
1. Network Traffic Graph
   - Upload speed
   - Download speed
   - Time-based trends

2. Connection Analysis
   - Active connections
   - Geographic distribution
   - Traffic patterns

## Log Analysis

Logs are stored in `network_traffic.log`:
```bash
tail -f network_traffic.log
```

## Performance Monitoring

Monitor system resource usage:
- CPU utilization
- Memory consumption
- Disk activity
- Network interface statistics
