# CodeBlue Installation Guide for Linux

This guide provides step-by-step instructions for installing and running CodeBlue on Linux systems.

## System Requirements

- Linux distribution (Ubuntu 20.04+, Debian 11+, CentOS 8+, Fedora 34+, or similar)
- Python 3.8 or higher
- 4GB RAM minimum (8GB or more recommended)
- 2GB free disk space
- sudo privileges (for installing dependencies)

## Installation Steps

### 1. Install Python and Required Tools

Different Linux distributions use different package managers. Follow the instructions for your distribution:

#### For Ubuntu/Debian:

```bash
# Update package lists
sudo apt update

# Install Python and required tools
sudo apt install -y python3 python3-pip python3-venv git file binutils wkhtmltopdf
```

#### For CentOS/RHEL:

```bash
# Update package lists
sudo yum update -y

# Install Python and required tools
sudo yum install -y python3 python3-pip python3-devel git file binutils

# Install EPEL repository (needed for wkhtmltopdf)
sudo yum install -y epel-release
sudo yum install -y wkhtmltopdf
```

#### For Fedora:

```bash
# Update package lists
sudo dnf update -y

# Install Python and required tools
sudo dnf install -y python3 python3-pip python3-devel git file binutils wkhtmltopdf
```

#### For Arch Linux:

```bash
# Update package lists
sudo pacman -Syu

# Install Python and required tools
sudo pacman -S python python-pip git file binutils wkhtmltopdf
```

### 2. Download CodeBlue

#### Option 1: Using Git (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-organization/codeblue.git
cd codeblue
```

#### Option 2: Download and Extract

```bash
# Download the ZIP file (replace with actual URL)
wget https://example.com/codeblue.zip

# Install unzip if needed
sudo apt install unzip   # Ubuntu/Debian
# or
sudo yum install unzip   # CentOS/RHEL
# or
sudo dnf install unzip   # Fedora
# or
sudo pacman -S unzip     # Arch Linux

# Extract the ZIP file
unzip codeblue.zip
cd codeblue
```

### 3. Run the Setup Script

Make the setup script executable and run it:

```bash
chmod +x setup.sh
./setup.sh
```

The script will:
- Detect your Linux distribution
- Check if Python is installed
- Install required system dependencies
- Create a virtual environment
- Install required Python packages
- Create necessary directories
- Generate a configuration file

If prompted to start the application, you can choose 'y' to start it immediately or 'n' to start it later.

### 4. Starting CodeBlue Manually

If you didn't start the application during setup or need to restart it later:

```bash
# Navigate to the CodeBlue directory (if not already there)
cd path/to/codeblue

# Activate the virtual environment
source venv/bin/activate

# Start the application
python app.py
```

### 5. Accessing CodeBlue

Once the application is running:

1. Open a web browser
2. Navigate to: http://localhost:5001

To access from other devices on your network:
1. Find your computer's IP address:
   ```bash
   ip addr show
   # or
   hostname -I
   ```
2. Look for the IPv4 Address (e.g., 192.168.1.100)
3. Other devices can access CodeBlue at: http://YOUR_IP_ADDRESS:5001

### 6. Running as a Service (Optional)

To run CodeBlue as a system service that starts automatically:

1. Create a systemd service file:

```bash
sudo nano /etc/systemd/system/codeblue.service
```

2. Add the following content (adjust paths as needed):

```
[Unit]
Description=CodeBlue Security Analysis Platform
After=network.target

[Service]
User=YOUR_USERNAME
WorkingDirectory=/path/to/codeblue
ExecStart=/path/to/codeblue/venv/bin/python /path/to/codeblue/app.py
Restart=on-failure
Environment="PATH=/path/to/codeblue/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

[Install]
WantedBy=multi-user.target
```

3. Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable codeblue
sudo systemctl start codeblue
```

4. Check the service status:

```bash
sudo systemctl status codeblue
```

## Troubleshooting

### Python Version Issues

If your distribution has an older Python version:

```bash
# For Ubuntu/Debian
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install python3.9 python3.9-venv python3.9-dev

# Then use python3.9 instead of python3 in commands
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
# For Ubuntu/Debian:
sudo apt install -y wkhtmltopdf

# For CentOS/RHEL:
sudo yum install -y wkhtmltopdf

# For Fedora:
sudo dnf install -y wkhtmltopdf
```

### Port Already in Use

If port 5001 is already in use:

```bash
# Find what's using the port
sudo lsof -i :5001

# Edit the config.py file
nano config.py
# Change the PORT value to another port (e.g., 5002)

# Restart the application
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

### Firewall Configuration

If you're using a firewall, you'll need to open the port:

```bash
# For UFW (Ubuntu/Debian)
sudo ufw allow 5001/tcp

# For firewalld (CentOS/RHEL/Fedora)
sudo firewall-cmd --permanent --add-port=5001/tcp
sudo firewall-cmd --reload
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

# If running as a service, remove the service
sudo systemctl stop codeblue
sudo systemctl disable codeblue
sudo rm /etc/systemd/system/codeblue.service
sudo systemctl daemon-reload
```

## Getting Help

If you encounter issues not covered in this guide:
1. Check the README.md file for additional information
2. Review the logs in the CodeBlue directory
3. Contact your system administrator or the CodeBlue support team

---

This installation guide was last updated on May 23, 2025.
