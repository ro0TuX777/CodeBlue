#!/bin/bash
# Script to install binary analysis tools on Linux

echo "Installing binary analysis tools for Linux..."

# Detect package manager
if command -v apt-get &> /dev/null; then
    # Debian/Ubuntu
    echo "Detected Debian/Ubuntu system..."
    sudo apt-get update
    sudo apt-get install -y file binutils xxd procps lsof python3-pip python3-dev
    
    # Install Python packages
    echo "Installing Python packages for binary analysis..."
    pip3 install pefile pyelftools macholib capstone
    
elif command -v yum &> /dev/null; then
    # CentOS/RHEL
    echo "Detected CentOS/RHEL system..."
    sudo yum install -y file binutils util-linux procps lsof python3-pip python3-devel
    
    # Install Python packages
    echo "Installing Python packages for binary analysis..."
    pip3 install pefile pyelftools macholib capstone
    
elif command -v dnf &> /dev/null; then
    # Fedora
    echo "Detected Fedora system..."
    sudo dnf install -y file binutils util-linux procps lsof python3-pip python3-devel
    
    # Install Python packages
    echo "Installing Python packages for binary analysis..."
    pip3 install pefile pyelftools macholib capstone
    
else
    echo "Unsupported Linux distribution. Please install the required packages manually."
    exit 1
fi

# Install Radare2 if requested
read -p "Do you want to install Radare2? (y/n) " install_radare2
if [[ $install_radare2 == "y" ]]; then
    echo "Installing Radare2..."
    
    # Clone Radare2 repository
    git clone https://github.com/radareorg/radare2
    cd radare2
    
    # Install Radare2
    ./sys/install.sh
    
    cd ..
    rm -rf radare2
fi

# Install Ghidra if requested
read -p "Do you want to install Ghidra? (y/n) " install_ghidra
if [[ $install_ghidra == "y" ]]; then
    echo "Installing Ghidra..."
    
    # Check if Java is installed
    if ! command -v java &> /dev/null; then
        echo "Installing Java JDK..."
        
        if command -v apt-get &> /dev/null; then
            sudo apt-get install -y openjdk-11-jdk
        elif command -v yum &> /dev/null; then
            sudo yum install -y java-11-openjdk-devel
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y java-11-openjdk-devel
        fi
    fi
    
    # Create directory for Ghidra
    mkdir -p ~/Applications
    
    # Download and install Ghidra
    ghidra_url="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3.2_build/ghidra_10.3.2_PUBLIC_20230711.zip"
    ghidra_zip="/tmp/ghidra.zip"
    ghidra_dir="$HOME/Applications/Ghidra"
    
    # Download Ghidra
    wget "$ghidra_url" -O "$ghidra_zip"
    
    # Extract Ghidra
    unzip -q "$ghidra_zip" -d "$HOME/Applications"
    
    # Create symlink to Ghidra
    ghidra_bin_dir=$(find "$HOME/Applications" -name "ghidra_*" -type d | head -n 1)
    ln -sf "$ghidra_bin_dir" "$ghidra_dir"
    
    # Add to PATH
    echo "export PATH=\"$ghidra_dir:\$PATH\"" >> ~/.bashrc
    echo "Ghidra installed to $ghidra_dir"
fi

echo "Installation complete!"
echo "Please restart your terminal to ensure all tools are available in your PATH."
