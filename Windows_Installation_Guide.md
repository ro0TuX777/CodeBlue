# CodeBlue Installation Guide for Windows

This guide provides step-by-step instructions for installing and running CodeBlue on Windows systems.

## System Requirements

- Windows 10 or Windows 11 (64-bit recommended)
- Python 3.8 or higher
- 4GB RAM minimum (8GB or more recommended)
- 2GB free disk space
- Administrator privileges (for installing dependencies)

## Installation Steps

### 1. Install Python

If you don't have Python installed:

1. Download the latest Python installer from [python.org](https://www.python.org/downloads/windows/)
2. Run the installer
3. **Important**: Check the box that says "Add Python to PATH"
4. Select "Install Now" (recommended) or "Customize installation"
5. Wait for the installation to complete

Verify the installation by opening Command Prompt and typing:
```
python --version
```

You should see the Python version displayed (e.g., `Python 3.10.5`).

### 2. Install Required Tools

#### 2.1 Install wkhtmltopdf (Required for PDF Report Generation)

1. Download the installer from [wkhtmltopdf.org](https://wkhtmltopdf.org/downloads.html)
2. Run the installer and follow the prompts
3. Make sure to add wkhtmltopdf to your PATH during installation

#### 2.2 Install Git (Optional but Recommended)

1. Download Git from [git-scm.com](https://git-scm.com/download/win)
2. Run the installer with default options
3. This will be useful if you want to clone repositories directly

### 3. Download CodeBlue

#### Option 1: Using Git (Recommended)

If you installed Git:

1. Open Command Prompt
2. Navigate to the directory where you want to install CodeBlue
3. Clone the repository:
   ```
   git clone https://github.com/your-organization/codeblue.git
   cd codeblue
   ```

#### Option 2: Download ZIP File

1. Download the CodeBlue ZIP file
2. Extract the ZIP file to your desired location
3. Open Command Prompt and navigate to the extracted directory:
   ```
   cd path\to\codeblue
   ```

### 4. Run the Setup Script

1. In the CodeBlue directory, run the setup script:
   ```
   setup.bat
   ```

2. The script will:
   - Check if Python is installed
   - Create a virtual environment
   - Install required Python packages
   - Check for required system tools
   - Create necessary directories
   - Generate a configuration file

3. If prompted to start the application, you can choose 'y' to start it immediately or 'n' to start it later

### 5. Starting CodeBlue Manually

If you didn't start the application during setup or need to restart it later:

1. Open Command Prompt
2. Navigate to the CodeBlue directory
3. Activate the virtual environment:
   ```
   venv\Scripts\activate.bat
   ```
4. Start the application:
   ```
   python app.py
   ```

### 6. Accessing CodeBlue

Once the application is running:

1. Open a web browser
2. Navigate to: http://localhost:5001

To access from other devices on your network:
1. Find your computer's IP address:
   ```
   ipconfig
   ```
2. Look for the IPv4 Address (e.g., 192.168.1.100)
3. Other devices can access CodeBlue at: http://YOUR_IP_ADDRESS:5001

## Troubleshooting

### Python Not Found

If you get "Python not found" errors:
1. Make sure Python is installed
2. Check if Python is in your PATH:
   - Open System Properties > Advanced > Environment Variables
   - Add Python's installation directory to the PATH variable

### Package Installation Errors

If you encounter errors during package installation:
1. Make sure you have internet access
2. Try updating pip:
   ```
   python -m pip install --upgrade pip
   ```
3. Install packages individually to identify problematic packages

### wkhtmltopdf Not Found

If PDF generation doesn't work:
1. Make sure wkhtmltopdf is installed
2. Add the wkhtmltopdf installation directory to your PATH:
   - Open System Properties > Advanced > Environment Variables
   - Add the wkhtmltopdf bin directory to the PATH variable

### Port Already in Use

If port 5001 is already in use:
1. Edit the config.py file
2. Change the PORT value to another port (e.g., 5002)
3. Restart the application

## Advanced Configuration

### Changing the Port

To change the default port:
1. Open config.py in a text editor
2. Find the PORT setting and change it to your desired port:
   ```python
   PORT = 8080  # Change to your desired port
   ```
3. Save the file and restart the application

### Enabling Debug Mode

For development purposes:
1. Open config.py
2. Set DEBUG to True:
   ```python
   DEBUG = True
   ```
3. Save the file and restart the application

### Updating CodeBlue

To update to a newer version:
1. Backup your data and configuration
2. Download or pull the latest version
3. Run the setup script again:
   ```
   setup.bat
   ```

## Uninstallation

To uninstall CodeBlue:
1. Delete the CodeBlue directory
2. Optionally uninstall Python if no longer needed

## Getting Help

If you encounter issues not covered in this guide:
1. Check the README.md file for additional information
2. Review the logs in the CodeBlue directory
3. Contact your system administrator or the CodeBlue support team

---

This installation guide was last updated on May 23, 2025.
