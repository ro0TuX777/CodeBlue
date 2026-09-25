@echo off
echo Downloading dependencies for offline installation...

REM Create directories if they don't exist
mkdir dependencies\python 2>nul
mkdir dependencies\node 2>nul
mkdir dependencies\go 2>nul
mkdir dependencies\system 2>nul
mkdir dependencies\binaries 2>nul

REM Download Python packages
echo Downloading Python packages...
pip download -r requirements.txt -d dependencies\python

REM Download specific versions of Python tools
echo Downloading specific versions of Python tools...
pip download bandit==1.7.0 -d dependencies\python
pip download pylint==2.11.1 -d dependencies\python
pip download safety==1.10.3 -d dependencies\python
pip download semgrep==0.72.0 -d dependencies\python
pip download black==21.9b0 -d dependencies\python
pip download flake8==3.9.2 -d dependencies\python
pip download mypy==0.910 -d dependencies\python
pip download pyright==0.0.13 -d dependencies\python
pip download prospector==1.6.0 -d dependencies\python
pip download vulture==2.3 -d dependencies\python
pip download radon==5.1.0 -d dependencies\python
pip download dlint==0.12.0 -d dependencies\python
pip download flake8-django==1.1.2 -d dependencies\python
pip download flake8-docstrings==1.6.0 -d dependencies\python
pip download flake8-bugbear==21.9.2 -d dependencies\python
pip download flake8-comprehensions==3.6.1 -d dependencies\python
pip download flake8-return==1.1.3 -d dependencies\python

REM Download Node.js packages
echo Downloading Node.js packages...
where npm >nul 2>nul
if %ERRORLEVEL% equ 0 (
    npm pack eslint jshint
    move eslint-*.tgz dependencies\node\
    move jshint-*.tgz dependencies\node\
) else (
    echo npm not found. Skipping Node.js packages download.
)

REM Download Go packages
echo Downloading Go packages...
where go >nul 2>nul
if %ERRORLEVEL% equ 0 (
    mkdir dependencies\go\src 2>nul
    set GOPATH=%cd%\dependencies\go
    go mod download github.com/securego/gosec/v2
    go mod download github.com/golangci/golangci-lint
) else (
    echo go not found. Skipping Go packages download.
)

REM Download binary tools
echo Downloading binary tools...

REM Download gitleaks
curl -L https://github.com/zricethezav/gitleaks/releases/download/v8.8.12/gitleaks_8.8.12_windows_x64.zip -o dependencies\binaries\gitleaks_windows.zip

REM Download tfsec
curl -L https://github.com/aquasecurity/tfsec/releases/download/v1.28.1/tfsec-windows-amd64.exe -o dependencies\binaries\tfsec-windows.exe

REM Download osv-scanner
curl -L https://github.com/google/osv-scanner/releases/download/v1.9.2/osv-scanner_windows_amd64.exe -o dependencies\binaries\osv-scanner-windows.exe

REM Create a README file in the dependencies directory
echo # Local Dependencies for BlueSpunge > dependencies\README.md
echo. >> dependencies\README.md
echo This directory contains all the dependencies needed to install BlueSpunge without internet access. >> dependencies\README.md
echo. >> dependencies\README.md
echo ## Directory Structure >> dependencies\README.md
echo. >> dependencies\README.md
echo - `python/`: Python packages (pip) >> dependencies\README.md
echo - `node/`: Node.js packages (npm) >> dependencies\README.md
echo - `go/`: Go packages >> dependencies\README.md
echo - `system/`: System dependencies >> dependencies\README.md
echo - `binaries/`: Binary tools (gitleaks, tfsec, osv-scanner, etc.) >> dependencies\README.md
echo. >> dependencies\README.md
echo ## Installation >> dependencies\README.md
echo. >> dependencies\README.md
echo Use the provided installation scripts to install from these local dependencies: >> dependencies\README.md
echo. >> dependencies\README.md
echo - `install_from_local.sh` (Linux/macOS) >> dependencies\README.md
echo - `install_from_local.bat` (Windows) >> dependencies\README.md

echo Dependencies downloaded successfully!
echo To install from local dependencies, use install_from_local.sh or install_from_local.bat
