@echo off
echo Installing BlueSpunge from local dependencies...

REM Check if dependencies directory exists
if not exist dependencies (
    echo Error: dependencies directory not found.
    echo Please run download_dependencies.bat first.
    exit /b 1
)

REM Create a virtual environment if it doesn't exist
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate the virtual environment
call venv\Scripts\activate.bat

REM Install Python packages from local directory
echo Installing Python packages from local directory...
pip install --no-index --find-links=dependencies\python -r requirements.txt

REM Install specific versions of Python tools
echo Installing specific versions of Python tools...
pip install --no-index --find-links=dependencies\python bandit==1.7.0
pip install --no-index --find-links=dependencies\python pylint==2.11.1
pip install --no-index --find-links=dependencies\python safety==1.10.3
pip install --no-index --find-links=dependencies\python semgrep==0.72.0
pip install --no-index --find-links=dependencies\python black==21.9b0
pip install --no-index --find-links=dependencies\python flake8==3.9.2
pip install --no-index --find-links=dependencies\python mypy==0.910
pip install --no-index --find-links=dependencies\python pyright==0.0.13
pip install --no-index --find-links=dependencies\python prospector==1.6.0
pip install --no-index --find-links=dependencies\python vulture==2.3
pip install --no-index --find-links=dependencies\python radon==5.1.0
pip install --no-index --find-links=dependencies\python dlint==0.12.0
pip install --no-index --find-links=dependencies\python flake8-django==1.1.2
pip install --no-index --find-links=dependencies\python flake8-docstrings==1.6.0
pip install --no-index --find-links=dependencies\python flake8-bugbear==21.9.2
pip install --no-index --find-links=dependencies\python flake8-comprehensions==3.6.1
pip install --no-index --find-links=dependencies\python flake8-return==1.1.3

REM Install Node.js packages
echo Installing Node.js packages...
where npm >nul 2>nul
if %ERRORLEVEL% equ 0 (
    for %%f in (dependencies\node\eslint-*.tgz) do npm install -g %%f
    for %%f in (dependencies\node\jshint-*.tgz) do npm install -g %%f
) else (
    echo npm not found. Skipping Node.js packages installation.
)

REM Install binary tools
echo Installing binary tools...

REM Install gitleaks
powershell -Command "Expand-Archive -Path 'dependencies\binaries\gitleaks_windows.zip' -DestinationPath 'C:\Windows\System32' -Force"

REM Install tfsec
copy dependencies\binaries\tfsec-windows.exe C:\Windows\System32\tfsec.exe

REM Install osv-scanner
copy dependencies\binaries\osv-scanner-windows.exe C:\Windows\System32\osv-scanner.exe

echo Installation complete!
echo To activate the virtual environment, run: venv\Scripts\activate.bat
