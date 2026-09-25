@echo off
echo Building and running BlueSpunge in Docker...

REM Check if Docker is installed
where docker >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Docker is not installed. Please install Docker first.
    exit /b 1
)

REM Check if Docker Compose is installed
where docker-compose >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Docker Compose is not installed. Please install Docker Compose first.
    exit /b 1
)

REM Check if .env file exists
if not exist .env (
    echo Creating .env file...
    echo GITHUB_TOKEN=your_github_token > .env
    echo FLASK_SECRET_KEY=your_secure_secret_key >> .env
    echo .env file created. Please edit it with your GitHub token and secret key.
)

REM Check if dependencies directory exists
if not exist dependencies (
    echo Dependencies directory not found. Downloading dependencies...
    call download_dependencies.bat
)

REM Create necessary directories
if not exist Untested mkdir Untested
if not exist saved_repositories mkdir saved_repositories

REM Build and run with Docker Compose
echo Building and starting BlueSpunge...
docker-compose up -d

REM Check if the container is running
docker-compose ps | findstr "bluescrub" >nul
if %ERRORLEVEL% equ 0 (
    echo BlueSpunge is now running!
    echo Access the application at http://localhost:5001
    echo.
    echo To view logs: docker-compose logs -f
    echo To stop: docker-compose down
) else (
    echo Failed to start BlueSpunge container. Check logs with: docker-compose logs
)
