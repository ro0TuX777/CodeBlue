#!/bin/bash
# Script to install binary analysis tools on macOS

echo "Installing binary analysis tools for macOS..."

# Check if Homebrew is installed
if ! command -v brew &> /dev/null; then
    echo "Installing Homebrew package manager..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    
    # Add Homebrew to PATH
    if [[ $(uname -m) == 'arm64' ]]; then
        echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
        eval "$(/opt/homebrew/bin/brew shellenv)"
    else
        echo 'eval "$(/usr/local/bin/brew shellenv)"' >> ~/.zprofile
        eval "$(/usr/local/bin/brew shellenv)"
    fi
fi

# Install Python packages
echo "Installing Python packages for binary analysis..."
pip3 install pefile pyelftools macholib capstone

# Install command-line tools
echo "Installing command-line tools for binary analysis..."
brew install binutils coreutils file

# Install Radare2 if requested
read -p "Do you want to install Radare2? (y/n) " install_radare2
if [[ $install_radare2 == "y" ]]; then
    echo "Installing Radare2..."
    brew install radare2
fi

# Install Ghidra if requested
read -p "Do you want to install Ghidra? (y/n) " install_ghidra
if [[ $install_ghidra == "y" ]]; then
    echo "Installing Ghidra..."
    
    # Check if Java is installed
    if ! command -v java &> /dev/null; then
        echo "Installing Java JDK..."
        brew install --cask temurin11
    fi
    
    # Create directory for Ghidra
    mkdir -p ~/Applications
    
    # Download and install Ghidra
    ghidra_url="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3.2_build/ghidra_10.3.2_PUBLIC_20230711.zip"
    ghidra_zip="/tmp/ghidra.zip"
    ghidra_dir="$HOME/Applications/Ghidra"
    
    # Download Ghidra
    curl -L "$ghidra_url" -o "$ghidra_zip"
    
    # Extract Ghidra
    unzip -q "$ghidra_zip" -d "$HOME/Applications"
    
    # Create symlink to Ghidra
    ghidra_bin_dir=$(find "$HOME/Applications" -name "ghidra_*" -type d | head -n 1)
    ln -sf "$ghidra_bin_dir" "$ghidra_dir"
    
    # Add to PATH
    echo "export PATH=\"$ghidra_dir:\$PATH\"" >> ~/.zprofile
    echo "Ghidra installed to $ghidra_dir"
fi

echo "Installation complete!"
echo "Please restart your terminal to ensure all tools are available in your PATH."
