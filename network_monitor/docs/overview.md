# Network Monitor Overview

## System Architecture

The Network Monitor is a modular system composed of several specialized components that work together to provide comprehensive network monitoring and security analysis.

### Core Components

1. **NetworkMonitor** (network_monitor.py)
   - Main orchestrator class
   - Handles real-time traffic monitoring
   - Manages visualization
   - Coordinates between other components
   - Processes connection information

2. **NetworkRadar** (radar.py)
   - Advanced threat detection
   - Machine learning-based anomaly detection
   - Traffic pattern analysis
   - Organization tracking
   - Attack pattern recognition

3. **TrafficGuard** (traffic_guard.py)
   - Traffic filtering
   - Connection blocking
   - Suspicious activity detection
   - Threshold monitoring

4. **NetworkAnalyzer** (network_analyzer.py)
   - Process-level network analysis
   - Connection details extraction
   - System resource monitoring

## Data Flow

1. NetworkMonitor captures real-time network traffic
2. Traffic data is analyzed by NetworkAnalyzer for process information
3. TrafficGuard checks for suspicious patterns
4. NetworkRadar performs deep analysis and threat detection
5. Results are visualized and logged

## Visualization

The system provides real-time visualization of:
- Upload/Download speeds
- Connection patterns
- Traffic anomalies
- Geographic distribution of connections

## Logging

Comprehensive logging includes:
- Network traffic statistics
- Security alerts
- System events
- Performance metrics
- Threat detection results
