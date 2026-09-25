#!/bin/bash

# Script to install BlueSpunge from local dependencies

echo "Installing BlueSpunge from local dependencies..."

# Check if dependencies directory exists
if [ ! -d "dependencies" ]; then
    echo "Error: dependencies directory not found."
    echo "Please run download_dependencies.sh first."
    exit 1
fi

# Create a virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python -m venv venv
fi

# Activate the virtual environment
source venv/bin/activate

# Install Python packages from local directory
echo "Installing Python packages from local directory..."
pip install --no-index --find-links=dependencies/python -r requirements.txt

# Install specific versions of Python tools
echo "Installing specific versions of Python tools..."
pip install --no-index --find-links=dependencies/python bandit==1.7.0
pip install --no-index --find-links=dependencies/python pylint==2.11.1
pip install --no-index --find-links=dependencies/python safety==1.10.3
pip install --no-index --find-links=dependencies/python semgrep==0.72.0
pip install --no-index --find-links=dependencies/python black==21.9b0
pip install --no-index --find-links=dependencies/python flake8==3.9.2
pip install --no-index --find-links=dependencies/python mypy==0.910
pip install --no-index --find-links=dependencies/python pyright==0.0.13
pip install --no-index --find-links=dependencies/python prospector==1.6.0
pip install --no-index --find-links=dependencies/python vulture==2.3
pip install --no-index --find-links=dependencies/python radon==5.1.0
pip install --no-index --find-links=dependencies/python dlint==0.12.0
pip install --no-index --find-links=dependencies/python flake8-django==1.1.2
pip install --no-index --find-links=dependencies/python flake8-docstrings==1.6.0
pip install --no-index --find-links=dependencies/python flake8-bugbear==21.9.2
pip install --no-index --find-links=dependencies/python flake8-comprehensions==3.6.1
pip install --no-index --find-links=dependencies/python flake8-return==1.1.3

# Install Node.js packages
echo "Installing Node.js packages..."
if command -v npm &> /dev/null; then
    npm install -g dependencies/node/eslint-*.tgz
    npm install -g dependencies/node/jshint-*.tgz
else
    echo "npm not found. Skipping Node.js packages installation."
fi

# Install binary tools
echo "Installing binary tools..."

# Install gitleaks
if [ "$(uname)" == "Darwin" ]; then
    # macOS
    tar -xzf dependencies/binaries/gitleaks_darwin.tar.gz -C /tmp
    chmod +x /tmp/gitleaks
    sudo mv /tmp/gitleaks /usr/local/bin/
elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
    # Linux
    tar -xzf dependencies/binaries/gitleaks_linux.tar.gz -C /tmp
    chmod +x /tmp/gitleaks
    sudo mv /tmp/gitleaks /usr/local/bin/
fi

# Install tfsec
if [ "$(uname)" == "Darwin" ]; then
    # macOS
    chmod +x dependencies/binaries/tfsec-darwin
    sudo mv dependencies/binaries/tfsec-darwin /usr/local/bin/tfsec
elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
    # Linux
    chmod +x dependencies/binaries/tfsec-linux
    sudo mv dependencies/binaries/tfsec-linux /usr/local/bin/tfsec
fi

# Install osv-scanner
if [ "$(uname)" == "Darwin" ]; then
    # macOS
    chmod +x dependencies/binaries/osv-scanner-darwin
    sudo mv dependencies/binaries/osv-scanner-darwin /usr/local/bin/osv-scanner
elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
    # Linux
    chmod +x dependencies/binaries/osv-scanner-linux
    sudo mv dependencies/binaries/osv-scanner-linux /usr/local/bin/osv-scanner
fi

echo "Installation complete!"
echo "To activate the virtual environment, run: source venv/bin/activate"
