#!/bin/bash

# Script to install Radare2 manually

# Create a temporary directory
mkdir -p /tmp/radare2_install
cd /tmp/radare2_install

# Install dependencies
apt-get update && apt-get install -y --no-install-recommends \
    git \
    make \
    gcc \
    g++ \
    pkg-config \
    libzip-dev \
    zlib1g-dev \
    libssl-dev \
    libmagic-dev

# Clone the repository
git clone https://github.com/radareorg/radare2.git
cd radare2

# Build and install
./sys/install.sh

# Clean up
cd /
rm -rf /tmp/radare2_install

# Set environment variable
echo "export RADARE2_AVAILABLE=true" >> /etc/environment

echo "Radare2 installed successfully!"
