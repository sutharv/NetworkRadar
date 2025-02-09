import logging
from network_monitor import NetworkMonitor
from config import DEFAULT_DURATION, LOG_FILE, LOG_FORMAT

def setup_logging():
    """Setup logging configuration"""
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format=LOG_FORMAT
    )

def main():
    try:
        setup_logging()
        logging.info("Starting Network Monitor...")
        
        print("\033[92m=== Network Traffic Monitor ===\033[0m")
        print("\033[93mPress Ctrl+C to stop monitoring\033[0m")
        
        monitor = NetworkMonitor()
        monitor.monitor_traffic(duration=DEFAULT_DURATION)
        
    except KeyboardInterrupt:
        print("\n\033[93mMonitoring stopped by user\033[0m")
        logging.info("Monitoring stopped by user")
    except Exception as e:
        print(f"\033[91mError occurred: {str(e)}\033[0m")
        logging.error(f"Error occurred: {str(e)}")
    finally:
        print("\n\033[92mNetwork monitoring session ended\033[0m")
        logging.info("Network monitoring session ended")

if __name__ == "__main__":
    main()
