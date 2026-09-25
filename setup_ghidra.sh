#!/bin/bash

# Script to set up Ghidra for CodeBlue

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Create analysis directory if it doesn't exist
mkdir -p analysis

# Build the Ghidra Docker image
echo "Building Ghidra Docker image..."
docker-compose -f docker-compose.ghidra.yml build

# Set environment variable for CodeBlue
echo "Setting up environment for CodeBlue..."
echo "export GHIDRA_PATH=/opt/ghidra" >> .env

echo "Ghidra setup complete!"
echo "To use Ghidra with CodeBlue, restart the CodeBlue container:"
echo "docker-compose down && docker-compose up -d"
echo ""
echo "To run Ghidra directly, use:"
echo "docker-compose -f docker-compose.ghidra.yml run ghidra /path/to/binary"
