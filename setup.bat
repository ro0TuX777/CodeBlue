@echo off
REM CodeBlue Setup Script for Windows
REM This script sets up the CodeBlue application and its dependencies

echo [34m>> Starting CodeBlue setup...[0m

REM Create log file
set LOGFILE=setup_log.txt
echo. > %LOGFILE%

REM Check Python version
echo [34m>> Checking Python version...[0m
python --version > NUL 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [31m>> Python not found. Please install Python 3.8 or higher.[0m
    echo [31m>> Python not found. Please install Python 3.8 or higher.[0m >> %LOGFILE%
    exit /b 1
)

REM Get Python version
for /f "tokens=2" %%V in ('python --version 2^>^&1') do set PYVER=%%V
echo [34m>> Found Python %PYVER%[0m
echo Found Python %PYVER% >> %LOGFILE%

REM Create test directories
echo [34m>> Creating test directories...[0m
if not exist test_binaries mkdir test_binaries
if not exist analysis_results mkdir analysis_results

REM Create virtual environment
echo [34m>> Creating virtual environment...[0m
python -m venv venv
if %ERRORLEVEL% NEQ 0 (
    echo [31m>> Failed to create virtual environment.[0m
    echo Failed to create virtual environment. >> %LOGFILE%
    exit /b 1
)

REM Activate virtual environment
echo [34m>> Activating virtual environment...[0m
call venv\Scripts\activate.bat

REM Install dependencies
echo [34m>> Installing dependencies...[0m
python -m pip install --upgrade pip
if %ERRORLEVEL% NEQ 0 (
    echo [31m>> Failed to upgrade pip.[0m
    echo Failed to upgrade pip. >> %LOGFILE%
    exit /b 1
)

echo [34m>> Installing requirements from requirements.txt...[0m
pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
    echo [31m>> Failed to install requirements.[0m
    echo Failed to install requirements. >> %LOGFILE%
    exit /b 1
)

REM Check for wkhtmltopdf
echo [34m>> Checking for wkhtmltopdf...[0m
wkhtmltopdf --version > NUL 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [33m>> wkhtmltopdf not found. This is required for PDF report generation.[0m
    echo [33m>> Please install wkhtmltopdf manually from: https://wkhtmltopdf.org/downloads.html[0m
    echo wkhtmltopdf not found. Please install manually. >> %LOGFILE%
)

REM Create configuration file if it doesn't exist
if not exist config.py (
    echo [34m>> Creating default configuration file...[0m
    echo # CodeBlue Configuration > config.py
    echo. >> config.py
    echo # Server settings >> config.py
    echo HOST = '0.0.0.0'  # Bind to all interfaces >> config.py
    echo PORT = 5001       # Default port >> config.py
    echo. >> config.py
    echo # Security settings >> config.py
    
    REM Generate random secret key
    for /f "tokens=*" %%a in ('python -c "import secrets; print(secrets.token_hex(16))"') do set SECRET_KEY=%%a
    echo DEBUG = True      # Set to False in production >> config.py
    echo SECRET_KEY = '%SECRET_KEY%' >> config.py
    echo. >> config.py
    echo # Database settings >> config.py
    echo SQLALCHEMY_DATABASE_URI = 'sqlite:///codeblue.db' >> config.py
    echo SQLALCHEMY_TRACK_MODIFICATIONS = False >> config.py
    echo. >> config.py
    echo # Analysis settings >> config.py
    echo MAX_REPO_SIZE_MB = 500  # Maximum repository size in MB >> config.py
    echo ANALYSIS_TIMEOUT = 600   # Analysis timeout in seconds >> config.py
    
    echo [32m>> Configuration file created with secure random key[0m
    echo Configuration file created with secure random key >> %LOGFILE%
)

echo [32m>> Setup completed successfully![0m
echo [34m>> To start the application, run: venv\Scripts\activate.bat ^& python app.py[0m
echo [34m>> The application will be accessible at: http://0.0.0.0:5001[0m

REM Ask if user wants to start the application now
set /p start_app="Do you want to start the application now? (y/n): "
if /i "%start_app%"=="y" (
    echo [34m>> Starting CodeBlue application...[0m
    python app.py
) else (
    echo [34m>> You can start the application later with: python app.py[0m
)
