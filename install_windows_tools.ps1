# PowerShell script to install binary analysis tools on Windows
# Run as Administrator: powershell -ExecutionPolicy Bypass -File install_windows_tools.ps1

Write-Host "Installing binary analysis tools for Windows..." -ForegroundColor Green

# Check if Chocolatey is installed
if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Chocolatey package manager..." -ForegroundColor Yellow
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    
    # Refresh environment variables
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
}

# Install Python packages
Write-Host "Installing Python packages for binary analysis..." -ForegroundColor Yellow
pip install pefile pyelftools macholib capstone

# Install binutils via Chocolatey
Write-Host "Installing binutils (includes objdump, strings, etc.)..." -ForegroundColor Yellow
choco install -y binutils

# Install Dependency Walker (alternative to ldd)
Write-Host "Installing Dependency Walker..." -ForegroundColor Yellow
$depwalkerUrl = "https://www.dependencywalker.com/depends22_x64.zip"
$depwalkerZip = "$env:TEMP\depends22_x64.zip"
$depwalkerDir = "$env:ProgramFiles\DependencyWalker"

# Download Dependency Walker
Invoke-WebRequest -Uri $depwalkerUrl -OutFile $depwalkerZip

# Create directory if it doesn't exist
if (!(Test-Path $depwalkerDir)) {
    New-Item -ItemType Directory -Path $depwalkerDir | Out-Null
}

# Extract Dependency Walker
Expand-Archive -Path $depwalkerZip -DestinationPath $depwalkerDir -Force

# Add to PATH
$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if (!($currentPath -like "*$depwalkerDir*")) {
    [Environment]::SetEnvironmentVariable("Path", $currentPath + ";$depwalkerDir", "Machine")
    Write-Host "Added Dependency Walker to PATH" -ForegroundColor Green
}

# Install Sysinternals Suite (includes sigcheck)
Write-Host "Installing Sysinternals Suite..." -ForegroundColor Yellow
choco install -y sysinternals

# Install Ghidra if requested
$installGhidra = Read-Host "Do you want to install Ghidra? (y/n)"
if ($installGhidra -eq 'y') {
    Write-Host "Installing Ghidra..." -ForegroundColor Yellow
    
    # Check if Java is installed
    if (!(Get-Command java -ErrorAction SilentlyContinue)) {
        Write-Host "Installing Java JDK..." -ForegroundColor Yellow
        choco install -y openjdk11
    }
    
    # Download and install Ghidra
    $ghidraUrl = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3.2_build/ghidra_10.3.2_PUBLIC_20230711.zip"
    $ghidraZip = "$env:TEMP\ghidra.zip"
    $ghidraDir = "$env:ProgramFiles\Ghidra"
    
    # Download Ghidra
    Invoke-WebRequest -Uri $ghidraUrl -OutFile $ghidraZip
    
    # Create directory if it doesn't exist
    if (!(Test-Path $ghidraDir)) {
        New-Item -ItemType Directory -Path $ghidraDir | Out-Null
    }
    
    # Extract Ghidra
    Expand-Archive -Path $ghidraZip -DestinationPath $ghidraDir -Force
    
    # Add to PATH
    $ghidraBinDir = (Get-ChildItem -Path $ghidraDir -Directory | Select-Object -First 1).FullName
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if (!($currentPath -like "*$ghidraBinDir*")) {
        [Environment]::SetEnvironmentVariable("Path", $currentPath + ";$ghidraBinDir", "Machine")
        Write-Host "Added Ghidra to PATH" -ForegroundColor Green
    }
}

# Install Radare2 if requested
$installRadare2 = Read-Host "Do you want to install Radare2? (y/n)"
if ($installRadare2 -eq 'y') {
    Write-Host "Installing Radare2..." -ForegroundColor Yellow
    choco install -y radare2
}

Write-Host "Installation complete!" -ForegroundColor Green
Write-Host "Please restart your terminal or computer to ensure all tools are available in your PATH." -ForegroundColor Yellow
