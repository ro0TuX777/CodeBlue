#!/bin/bash

# Script to install xxd manually

# Create a temporary directory
mkdir -p /tmp/xxd_install
cd /tmp/xxd_install

# Download the source code
wget https://github.com/vim/vim/archive/refs/tags/v9.0.2068.tar.gz
tar -xzf v9.0.2068.tar.gz
cd vim-9.0.2068/src/xxd

# Build and install
make
cp xxd /usr/local/bin/

# Clean up
cd /
rm -rf /tmp/xxd_install

echo "xxd command installed successfully!"
