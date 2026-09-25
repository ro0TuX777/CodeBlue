#!/bin/bash

# Script to build and run BlueSpunge in Docker

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

# Check if .env file exists
if [ ! -f .env ]; then
    echo "Creating .env file..."
    echo "GITHUB_TOKEN=your_github_token" > .env
    echo "FLASK_SECRET_KEY=your_secure_secret_key" >> .env
    echo ".env file created. Please edit it with your GitHub token and secret key."
fi

# Check if dependencies directory exists
if [ ! -d "dependencies" ]; then
    echo "Dependencies directory not found. Downloading dependencies..."
    chmod +x download_dependencies.sh
    ./download_dependencies.sh
fi

# Create necessary directories
mkdir -p Untested
mkdir -p saved_repositories

# Set proper permissions
chmod -R 777 Untested saved_repositories

# Build and run with Docker Compose
echo "Building and starting BlueSpunge..."
docker-compose up -d

# Check if the container is running
if [ "$(docker-compose ps -q bluescrub)" ]; then
    echo "BlueSpunge is now running!"
    echo "Access the application at http://localhost:5001"
    echo ""
    echo "To view logs: docker-compose logs -f"
    echo "To stop: docker-compose down"
else
    echo "Failed to start BlueSpunge container. Check logs with: docker-compose logs"
fi
