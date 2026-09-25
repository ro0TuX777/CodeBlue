#!/bin/bash

# Script to install Capstone for CodeBlue

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

echo "Installing Capstone for CodeBlue..."

# Install Python dependencies
pip install capstone

# Check if installation was successful
if python -c "import capstone" 2>/dev/null; then
    echo "Capstone Python bindings installed successfully!"
else
    echo "Failed to install Capstone Python bindings. Trying to install from source..."
    
    # Create a temporary directory for building
    mkdir -p /tmp/capstone_install
    cd /tmp/capstone_install
    
    # Clone the Capstone repository
    echo "Cloning Capstone repository..."
    git clone https://github.com/capstone-engine/capstone.git
    cd capstone
    
    # Build and install Capstone
    echo "Building and installing Capstone..."
    ./make.sh
    ./make.sh install
    cd bindings/python
    python setup.py install
    
    # Check if installation was successful
    if python -c "import capstone" 2>/dev/null; then
        echo "Capstone installed successfully from source!"
    else
        echo "Failed to install Capstone. Please check the logs for errors."
        exit 1
    fi
fi

# Set environment variable for CodeBlue
echo "Setting up environment for CodeBlue..."
echo "export CAPSTONE_AVAILABLE=true" >> /etc/environment

echo "Capstone setup complete!"
echo "To use Capstone with CodeBlue, restart the CodeBlue container:"
echo "docker-compose down && docker-compose up -d"

exit 0
