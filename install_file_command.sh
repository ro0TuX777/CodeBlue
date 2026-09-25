#!/bin/bash

# Script to install the 'file' command manually

# Create a temporary directory
mkdir -p /tmp/file_install
cd /tmp/file_install

# Download the source code
wget https://astron.com/pub/file/file-5.45.tar.gz
tar -xzf file-5.45.tar.gz
cd file-5.45

# Configure, build, and install
./configure
make
make install

# Clean up
cd /
rm -rf /tmp/file_install

echo "File command installed successfully!"
