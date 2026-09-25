# CodeBlue Installation Guide for macOS

This guide provides step-by-step instructions for installing and running CodeBlue on macOS systems.

## System Requirements

- macOS 11 (Big Sur) or newer
- Python 3.8 or higher
- 4GB RAM minimum (8GB or more recommended)
- 2GB free disk space
- Administrator privileges (for installing dependencies)

## Installation Steps

### 1. Install Command Line Tools

First, install the Xcode Command Line Tools, which provide essential development tools:

```bash
xcode-select --install
```

Follow the prompts to complete the installation.

### 2. Install Homebrew (Package Manager)

Homebrew makes it easy to install the required dependencies:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

After installation, follow the instructions to add Homebrew to your PATH if needed.

### 3. Install Python and Required Tools

```bash
# Install Python
brew install python@3.10

# Install wkhtmltopdf (for PDF generation)
brew install wkhtmltopdf

# Install file command and other utilities
brew install file
```

Verify the Python installation:

```bash
python3 --version
```

You should see the Python version displayed (e.g., `Python 3.10.5`).

### 4. Download CodeBlue

#### Option 1: Using Git (Recommended)

```bash
# Install Git if not already installed
brew install git

# Clone the repository
git clone https://github.com/your-organization/codeblue.git
cd codeblue
```

#### Option 2: Download and Extract

1. Download the CodeBlue ZIP file
2. Extract the ZIP file to your desired location
3. Open Terminal and navigate to the extracted directory:
   ```bash
   cd path/to/codeblue
   ```

### 5. Run the Setup Script

Make the setup script executable and run it:

```bash
chmod +x setup.sh
./setup.sh
```

The script will:
- Check if Python is installed
- Install required system dependencies using Homebrew
- Create a virtual environment
- Install required Python packages
- Create necessary directories
- Generate a configuration file

If prompted to start the application, you can choose 'y' to start it immediately or 'n' to start it later.

### 6. Starting CodeBlue Manually

If you didn't start the application during setup or need to restart it later:

```bash
# Navigate to the CodeBlue directory (if not already there)
cd path/to/codeblue

# Activate the virtual environment
source venv/bin/activate

# Start the application
python app.py
```

### 7. Accessing CodeBlue

Once the application is running:

1. Open a web browser
2. Navigate to: http://localhost:5001

To access from other devices on your network:
1. Find your computer's IP address:
   ```bash
   ifconfig | grep "inet " | grep -v 127.0.0.1
   ```
2. Look for the IPv4 Address (e.g., 192.168.1.100)
3. Other devices can access CodeBlue at: http://YOUR_IP_ADDRESS:5001

## Troubleshooting

### Python Version Issues

If you need a specific Python version:

```bash
# Install a specific Python version
brew install python@3.9

# Use that specific version
/usr/local/opt/python@3.9/bin/python3 -m venv venv
```

### Package Installation Errors

If you encounter errors during package installation:

```bash
# Update pip
python3 -m pip install --upgrade pip

# Install packages with verbose output
python3 -m pip install -v -r requirements.txt
```

### wkhtmltopdf Issues

If PDF generation doesn't work:

```bash
# Check if wkhtmltopdf is installed
which wkhtmltopdf

# If not found, install it manually
brew install wkhtmltopdf
```

### Port Already in Use

If port 5001 is already in use:

```bash
# Find what's using the port
lsof -i :5001

# Edit the config.py file
nano config.py
# Change the PORT value to another port (e.g., 5002)

# Restart the application
```

### Homebrew Installation Issues

If you encounter issues with Homebrew:

```bash
# Update Homebrew
brew update

# Diagnose Homebrew issues
brew doctor
```

## Advanced Configuration

### Changing the Port

To change the default port:

```bash
# Edit config.py
nano config.py
# Find the PORT setting and change it to your desired port
# PORT = 8080  # Change to your desired port
```

### Enabling Debug Mode

For development purposes:

```bash
# Edit config.py
nano config.py
# Set DEBUG to True
# DEBUG = True
```

### Running as a Background Service

To run CodeBlue as a background service that starts automatically:

1. Create a launch agent plist file:

```bash
mkdir -p ~/Library/LaunchAgents
nano ~/Library/LaunchAgents/com.codeblue.app.plist
```

2. Add the following content (adjust paths as needed):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.codeblue.app</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/codeblue/venv/bin/python</string>
        <string>/path/to/codeblue/app.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>/path/to/codeblue</string>
    <key>StandardErrorPath</key>
    <string>/path/to/codeblue/error.log</string>
    <key>StandardOutPath</key>
    <string>/path/to/codeblue/output.log</string>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

3. Load the launch agent:

```bash
launchctl load ~/Library/LaunchAgents/com.codeblue.app.plist
```

4. To stop the service:

```bash
launchctl unload ~/Library/LaunchAgents/com.codeblue.app.plist
```

### Updating CodeBlue

To update to a newer version:

```bash
# Navigate to the CodeBlue directory
cd path/to/codeblue

# If using Git
git pull

# Run the setup script again
./setup.sh
```

## Uninstallation

To uninstall CodeBlue:

```bash
# Remove the CodeBlue directory
rm -rf path/to/codeblue

# If running as a launch agent, remove it
launchctl unload ~/Library/LaunchAgents/com.codeblue.app.plist
rm ~/Library/LaunchAgents/com.codeblue.app.plist

# Optionally uninstall dependencies if no longer needed
brew uninstall wkhtmltopdf
```

## Getting Help

If you encounter issues not covered in this guide:
1. Check the README.md file for additional information
2. Review the logs in the CodeBlue directory
3. Contact your system administrator or the CodeBlue support team

---

This installation guide was last updated on May 23, 2025.
