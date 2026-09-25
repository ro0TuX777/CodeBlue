#!/bin/bash

# Script to set up Radare2 for CodeBlue

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

# Build the Radare2 Docker image
echo "Building Radare2 Docker image..."
docker-compose -f docker-compose.radare2.yml build

# Set environment variable for CodeBlue
echo "Setting up environment for CodeBlue..."
echo "export RADARE2_AVAILABLE=true" >> .env

echo "Radare2 setup complete!"
echo "To use Radare2 with CodeBlue, restart the CodeBlue container:"
echo "docker-compose down && docker-compose up -d"
