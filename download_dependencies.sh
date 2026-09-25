#!/bin/bash

# Script to download all dependencies locally for BlueSpunge

echo "Downloading dependencies for offline installation..."

# Create directories if they don't exist
mkdir -p dependencies/python
mkdir -p dependencies/node
mkdir -p dependencies/go
mkdir -p dependencies/system
mkdir -p dependencies/binaries

# Download Python packages
echo "Downloading Python packages..."
pip download -r requirements.txt -d dependencies/python

# Download specific versions of Python tools
echo "Downloading specific versions of Python tools..."
pip download bandit==1.7.0 -d dependencies/python
pip download pylint==2.11.1 -d dependencies/python
pip download safety==1.10.3 -d dependencies/python
pip download semgrep==0.72.0 -d dependencies/python
pip download black==21.9b0 -d dependencies/python
pip download flake8==3.9.2 -d dependencies/python
pip download mypy==0.910 -d dependencies/python
pip download pyright==0.0.13 -d dependencies/python
pip download prospector==1.6.0 -d dependencies/python
pip download vulture==2.3 -d dependencies/python
pip download radon==5.1.0 -d dependencies/python
pip download dlint==0.12.0 -d dependencies/python
pip download flake8-django==1.1.2 -d dependencies/python
pip download flake8-docstrings==1.6.0 -d dependencies/python
pip download flake8-bugbear==21.9.2 -d dependencies/python
pip download flake8-comprehensions==3.6.1 -d dependencies/python
pip download flake8-return==1.1.3 -d dependencies/python

# Download Node.js packages
echo "Downloading Node.js packages..."
if command -v npm &> /dev/null; then
    npm pack eslint jshint
    mv eslint-*.tgz jshint-*.tgz dependencies/node/
else
    echo "npm not found. Skipping Node.js packages download."
fi

# Download Go packages
echo "Downloading Go packages..."
if command -v go &> /dev/null; then
    mkdir -p dependencies/go/src
    GOPATH=$(pwd)/dependencies/go go mod download github.com/securego/gosec/v2
    GOPATH=$(pwd)/dependencies/go go mod download github.com/golangci/golangci-lint
else
    echo "go not found. Skipping Go packages download."
fi

# Download binary tools
echo "Downloading binary tools..."

# Download gitleaks
if [ "$(uname)" == "Darwin" ]; then
    # macOS
    curl -L https://github.com/zricethezav/gitleaks/releases/download/v8.8.12/gitleaks_8.8.12_darwin_x64.tar.gz -o dependencies/binaries/gitleaks_darwin.tar.gz
elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
    # Linux
    curl -L https://github.com/zricethezav/gitleaks/releases/download/v8.8.12/gitleaks_8.8.12_linux_x64.tar.gz -o dependencies/binaries/gitleaks_linux.tar.gz
elif [ "$(expr substr $(uname -s) 1 10)" == "MINGW32_NT" ] || [ "$(expr substr $(uname -s) 1 10)" == "MINGW64_NT" ]; then
    # Windows
    curl -L https://github.com/zricethezav/gitleaks/releases/download/v8.8.12/gitleaks_8.8.12_windows_x64.zip -o dependencies/binaries/gitleaks_windows.zip
fi

# Download tfsec
if [ "$(uname)" == "Darwin" ]; then
    # macOS
    curl -L https://github.com/aquasecurity/tfsec/releases/download/v1.28.1/tfsec-darwin-amd64 -o dependencies/binaries/tfsec-darwin
elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
    # Linux
    curl -L https://github.com/aquasecurity/tfsec/releases/download/v1.28.1/tfsec-linux-amd64 -o dependencies/binaries/tfsec-linux
elif [ "$(expr substr $(uname -s) 1 10)" == "MINGW32_NT" ] || [ "$(expr substr $(uname -s) 1 10)" == "MINGW64_NT" ]; then
    # Windows
    curl -L https://github.com/aquasecurity/tfsec/releases/download/v1.28.1/tfsec-windows-amd64.exe -o dependencies/binaries/tfsec-windows.exe
fi

# Download osv-scanner
if [ "$(uname)" == "Darwin" ]; then
    # macOS
    curl -L https://github.com/google/osv-scanner/releases/download/v1.9.2/osv-scanner_darwin_amd64 -o dependencies/binaries/osv-scanner-darwin
elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
    # Linux
    curl -L https://github.com/google/osv-scanner/releases/download/v1.9.2/osv-scanner_linux_amd64 -o dependencies/binaries/osv-scanner-linux
elif [ "$(expr substr $(uname -s) 1 10)" == "MINGW32_NT" ] || [ "$(expr substr $(uname -s) 1 10)" == "MINGW64_NT" ]; then
    # Windows
    curl -L https://github.com/google/osv-scanner/releases/download/v1.9.2/osv-scanner_windows_amd64.exe -o dependencies/binaries/osv-scanner-windows.exe
fi

# Create a README file in the dependencies directory
cat > dependencies/README.md << 'EOF'
# Local Dependencies for BlueSpunge

This directory contains all the dependencies needed to install BlueSpunge without internet access.

## Directory Structure

- `python/`: Python packages (pip)
- `node/`: Node.js packages (npm)
- `go/`: Go packages
- `system/`: System dependencies
- `binaries/`: Binary tools (gitleaks, tfsec, osv-scanner, etc.)

## Installation

Use the provided installation scripts to install from these local dependencies:

- `install_from_local.sh` (Linux/macOS)
- `install_from_local.bat` (Windows)
EOF

echo "Dependencies downloaded successfully!"
echo "To install from local dependencies, use install_from_local.sh or install_from_local.bat"
