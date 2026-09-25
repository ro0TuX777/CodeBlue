#!/bin/bash

# CodeBlue Setup Script
# This script sets up the CodeBlue application and its dependencies

# Log file for capturing output
LOGFILE="setup_log.txt"
echo "" > $LOGFILE  # Clear log file

# Print colored messages
print_message() {
    echo -e "\e[1;34m>> $1\e[0m" | tee -a $LOGFILE
}

print_success() {
    echo -e "\e[1;32m>> $1\e[0m" | tee -a $LOGFILE
}

print_error() {
    echo -e "\e[1;31m>> $1\e[0m" | tee -a $LOGFILE
}

print_message "Starting CodeBlue setup..."

# Ensure the script has execute permissions
chmod +x setup.sh

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    print_message "Detected Linux operating system"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    print_message "Detected macOS operating system"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    OS="windows"
    print_message "Detected Windows operating system"
else
    print_error "Unsupported operating system: $OSTYPE"
    exit 1
fi

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null
then
    print_error "Python3 could not be found. Please install Python3.8 or higher."
    exit 1
fi

# Check Python version
PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
print_message "Found Python $PY_VERSION"

if [[ $(echo "$PY_VERSION < 3.8" | bc -l) -eq 1 ]]; then
    print_error "Python 3.8 or higher is required. Found $PY_VERSION"
    exit 1
fi

# Create test directories
print_message "Creating test directories..."
mkdir -p test_binaries
mkdir -p analysis_results

print_message "Creating virtual environment..."
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
print_message "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Install system dependencies based on OS
print_message "Installing system dependencies..."

if [[ "$OS" == "linux" ]]; then
    # Detect Linux distribution
    if command -v apt-get &>/dev/null; then
        # Debian/Ubuntu
        print_message "Detected Debian/Ubuntu-based distribution"
        print_message "Installing required packages..."
        sudo apt-get update
        sudo apt-get install -y file binutils wkhtmltopdf
    elif command -v yum &>/dev/null; then
        # CentOS/RHEL
        print_message "Detected CentOS/RHEL-based distribution"
        print_message "Installing required packages..."
        sudo yum update -y
        sudo yum install -y file binutils wkhtmltopdf
    elif command -v dnf &>/dev/null; then
        # Fedora
        print_message "Detected Fedora-based distribution"
        print_message "Installing required packages..."
        sudo dnf update -y
        sudo dnf install -y file binutils wkhtmltopdf
    else
        print_error "Unsupported Linux distribution. Please install the following packages manually: file, binutils, wkhtmltopdf"
    fi

elif [[ "$OS" == "macos" ]]; then
    # Check if Homebrew is installed
    if ! command -v brew &>/dev/null; then
        print_message "Homebrew not found. Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi

    print_message "Installing required packages with Homebrew..."
    brew update
    brew install wkhtmltopdf

elif [[ "$OS" == "windows" ]]; then
    print_message "For Windows, please manually install wkhtmltopdf from: https://wkhtmltopdf.org/downloads.html"
    print_message "Make sure it's added to your PATH"
fi

# Optional: Install wkhtmltopdf if not already installed
if ! command -v wkhtmltopdf &>/dev/null; then
    print_message "wkhtmltopdf not found. This is required for PDF report generation."
    print_message "Please install wkhtmltopdf manually from: https://wkhtmltopdf.org/downloads.html"
fi

# Check for binary analysis tools
print_message "Checking for binary analysis tools..."

# Check for basic binary analysis tools
if [[ "$OS" == "linux" ]]; then
    if ! command -v file &>/dev/null || ! command -v readelf &>/dev/null || ! command -v nm &>/dev/null; then
        print_message "Some binary analysis tools are missing. Installing binutils package..."

        if command -v apt-get &>/dev/null; then
            sudo apt-get install -y binutils
        elif command -v yum &>/dev/null; then
            sudo yum install -y binutils
        elif command -v dnf &>/dev/null; then
            sudo dnf install -y binutils
        fi
    fi
elif [[ "$OS" == "macos" ]]; then
    if ! command -v file &>/dev/null; then
        print_message "Installing file command with Homebrew..."
        brew install file
    fi
fi

# Create configuration file if it doesn't exist
if [ ! -f "config.py" ]; then
    print_message "Creating default configuration file..."
    cat > config.py << EOL
# CodeBlue Configuration

# Server settings
HOST = '0.0.0.0'  # Bind to all interfaces
PORT = 5001       # Default port

# Security settings
DEBUG = True      # Set to False in production
SECRET_KEY = '$(python3 -c "import secrets; print(secrets.token_hex(16))")'

# Database settings
SQLALCHEMY_DATABASE_URI = 'sqlite:///codeblue.db'
SQLALCHEMY_TRACK_MODIFICATIONS = False

# Analysis settings
MAX_REPO_SIZE_MB = 500  # Maximum repository size in MB
ANALYSIS_TIMEOUT = 600   # Analysis timeout in seconds
EOL
    print_success "Configuration file created with secure random key"
fi

print_success "Setup completed successfully!"
print_message "To start the application, run: source venv/bin/activate && python app.py"
print_message "The application will be accessible at: http://0.0.0.0:5001"

# Ask if user wants to start the application now
read -p "Do you want to start the application now? (y/n): " start_app
if [[ $start_app == "y" || $start_app == "Y" ]]; then
    print_message "Starting CodeBlue application..."
    python app.py
else
    print_message "You can start the application later with: python app.py"
fi