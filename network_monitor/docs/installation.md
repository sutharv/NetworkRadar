# Installation Guide

## System Requirements

- Python 3.7 or higher
- Sufficient permissions for network monitoring
- Windows, Linux, or macOS operating system

## Dependencies

The Network Monitor requires the following Python packages:
- psutil
- matplotlib
- numpy
- requests
- scikit-learn
- yara-python
- dnspython

## Installation Steps

1. Clone or download the repository:
```bash
git clone <repository-url>
cd network_monitor
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Configure settings:
   - Copy `config.py.example` to `config.py` (if applicable)
   - Update configuration values in `config.py`
   - Set appropriate permissions for log files

4. Verify installation:
```bash
python main.py --test
```

## Troubleshooting

### Common Issues

1. Permission Errors
```bash
# Linux/macOS
sudo python main.py
```

2. Missing Dependencies
```bash
pip install --upgrade -r requirements.txt
```

3. Visualization Issues
- Ensure matplotlib is properly installed
- Check for proper display server configuration
- Try running in headless mode if needed

### Platform-Specific Notes

#### Windows
- Run as Administrator for full functionality
- Install Visual C++ Build Tools if required

#### Linux
- Install python3-dev package
- Additional permissions may be needed for raw socket access

#### macOS
- Install Xcode Command Line Tools
- Use Homebrew for additional dependencies if needed

## Updating

To update to the latest version:
1. Pull latest changes
2. Reinstall dependencies
3. Check for configuration changes
