#!/bin/bash

# Script to install binary analysis tools for CodeBlue

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Update package lists
echo "Updating package lists..."
apt-get update

# Install binary analysis tools
echo "Installing binary analysis tools..."
apt-get install -y --no-install-recommends \
  file \
  binutils \
  xxd \
  procps \
  lsof

# Clean up
apt-get clean
rm -rf /var/lib/apt/lists/*

echo "Binary analysis tools installed successfully!"
