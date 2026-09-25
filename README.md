# CodeBlue

CodeBlue is a comprehensive security analysis platform designed to scan GitHub repositories for potential security issues, suspicious network connections, and compliance with security standards. It incorporates multiple security tools to provide detailed reports and visualizations, and includes advanced binary analysis capabilities.

## Features

1. **Hook File Inspection**
   - Lists and inspects Git hooks for suspicious commands or URLs.

2. **Network Connection Search**
   - Searches through the repository files for suspicious network connections.

3. **Git Clone Search**
   - Identifies untrusted git clone commands within the repository.

4. **Security Tools Integration**

   **Python Static Analysis Tools:**
   - **Bandit**: Analyzes Python code for security issues.
   - **Pylint**: Analyzes Python code for quality and potential issues.
   - **Safety**: Checks for known security vulnerabilities in dependencies.
   - **Semgrep**: Scans code for security issues using customizable rules.
   - **Black**: Checks Python code formatting.
   - **Flake8**: Enforces coding standards and detects potential errors.
   - **Mypy**: Performs static type checking for Python code.
   - **Pyright**: Microsoft's static type checker for Python.
   - **Prospector**: Meta-tool that runs multiple analyzers with a unified interface.
   - **Pyre**: Facebook's type checker and static analyzer.
   - **Vulture**: Finds dead code in Python applications.
   - **Radon**: Analyzes code complexity metrics.
   - **Dlint**: Security-focused linter for Python code.

   **Secret Detection Tools:**
   - **GitLeaks**: Detects secrets like passwords and API keys in code.
   - **TruffleHog**: Searches for secrets across the repository.

   **Software Composition Analysis:**
   - **OSV-Scanner**: Checks dependency manifests/lockfiles (requirements.txt, package-lock.json, go.sum, Cargo.lock, etc.) against the OSV vulnerability database, covering ecosystems beyond Python.

   **License Compliance:**
   - **License Check**: Flags copyleft licenses (GPL/AGPL/LGPL/MPL/...) found in the repository's declared LICENSE file or per-file SPDX-License-Identifier headers.

5. **Compliance Checks**
   - Ensures data compliance with GDPR, HIPAA, and PCI-DSS standards.
   - Encrypts and decrypts data using Fernet encryption.

6. **Infrastructure as Code (IaC) Scanning**
   - **TFSec**: Scans Terraform code for security vulnerabilities.
   - **Checkov**: Scans IaC tools like Terraform and Ansible for security issues.

7. **Binary Analysis** (Cross-Platform Support)
   - **Basic Analysis**: Uses command-line tools like `file`, `strings`, `readelf`, `nm`, and `objdump` to analyze binaries.
   - **Ghidra**: Integrates with NSA's Ghidra software reverse engineering framework for advanced binary analysis.
   - **Radare2**: Integrates with Radare2, a powerful open-source reverse engineering framework.
   - **Capstone**: Uses the Capstone disassembly framework for detailed binary code analysis.
   - **Advanced Hex Viewer**: Interactive hex viewer with search functionality, byte selection, and multiple export formats.
   - **Binary Structure Visualization**: Visual representation of binary file structure and sections.
   - **Comprehensive Report Generation**: Customizable reports in PDF and HTML formats with selectable sections.
   - **Data Export Options**: Export binary data in various formats (raw binary, hexdump, C array, Python bytes, text).
   - Extracts metadata, symbols, imports, and libraries from binary files.
   - Performs security checks on binaries to identify potential vulnerabilities.
   - Analyzes ELF (Linux), PE (Windows), and Mach-O (macOS) binary formats.
   - Identifies potentially dangerous functions and security issues in binaries.
   - Works across Windows, Linux, and macOS with platform-specific optimizations.

8. **Reporting and Visualization**
   - Generates detailed HTML reports summarizing the findings.
   - Visualizes results using Plotly.

## Prerequisites

Ensure you have the following installed on your system:

- Python 3.7 or higher
- Homebrew (for installing some dependencies)

## Setup Instructions

### Option 1: Using Docker (Recommended)

1. **Clone the repository:**

   ```sh
   git clone <repository_url>
   cd <repository_directory>
   ```

2. **Set up environment variables:**

   Create a `.env` file in the root directory with the following content:
   ```
   GITHUB_TOKEN=your_github_token
   FLASK_SECRET_KEY=your_secure_secret_key
   ```

3. **Build and run with Docker:**

   Using the provided scripts:

   For macOS/Linux:
   ```sh
   chmod +x docker-run.sh
   ./docker-run.sh
   ```

   For Windows:
   ```sh
   docker-run.bat
   ```

   Or manually with Docker Compose:
   ```sh
   docker-compose up -d
   ```

   The application will be available at http://localhost:7842 and also accessible on your network via your machine's IP address (e.g., http://192.168.1.x:7842)

4. **View logs:**

   ```sh
   docker-compose logs -f
   ```

5. **Stop the application:**

   ```sh
   docker-compose down
   ```

### Option 2: Manual Installation

1. **Clone the repository:**

   ```sh
   git clone <repository_url>
   cd <repository_directory>
   ```

2. **Install dependencies:**

   For macOS/Linux:
   ```sh
   chmod +x install_python_tools.sh
   ./install_python_tools.sh
   ```

   For Windows:
   ```sh
   install_python_tools.bat
   ```

3. **Activate the virtual environment:**

   For macOS/Linux:
   ```sh
   source venv/bin/activate
   ```

   For Windows:
   ```sh
   venv\Scripts\activate.bat
   ```

4. **Run the application:**

   ```sh
   python app.py
   ```

   The application will be available at http://127.0.0.1:5001 by default. To make it accessible on your network, set the CODEBLUE_HOST and CODEBLUE_PORT environment variables in your .env file.

## Docker Benefits

Running BlueSpunge in a Docker container provides several advantages:

1. **Consistent Environment**: All static analysis tools are pre-installed and configured correctly.
2. **Isolation**: The application runs in an isolated environment, preventing conflicts with system packages.
3. **Portability**: Works the same way across different operating systems (Windows, macOS, Linux).
4. **Easy Updates**: Simply rebuild the Docker image to update the application and its dependencies.
5. **Resource Management**: Docker allows you to limit CPU and memory usage if needed.
6. **Offline Installation**: All dependencies are stored locally, allowing for installation without internet access.

## Local Dependencies

BlueSpunge supports offline installation by storing all dependencies locally:

1. **Download Dependencies**:
   ```sh
   # For macOS/Linux
   chmod +x download_dependencies.sh
   ./download_dependencies.sh

   # For Windows
   download_dependencies.bat
   ```

2. **Install from Local Dependencies**:
   ```sh
   # For macOS/Linux
   chmod +x install_from_local.sh
   ./install_from_local.sh

   # For Windows
   install_from_local.bat
   ```

The dependencies are stored in the `dependencies` directory with the following structure:
- `python/`: Python packages (pip)
- `node/`: Node.js packages (npm)
- `go/`: Go packages
- `system/`: System dependencies
- `binaries/`: Binary tools (gitleaks, tfsec, etc.)

## Setting Up Ghidra

CodeBlue integrates with [Ghidra](https://github.com/NationalSecurityAgency/ghidra), NSA's software reverse engineering framework, for advanced binary analysis.

### Option 1: Using Docker (Recommended)

1. **Run the setup script:**

   ```sh
   chmod +x setup_ghidra.sh
   ./setup_ghidra.sh
   ```

   This will:
   - Build a Docker container with Ghidra installed
   - Set up the necessary environment variables
   - Create the required directories

2. **Restart CodeBlue:**

   ```sh
   docker-compose down && docker-compose up -d
   ```

3. **Use Ghidra in CodeBlue:**
   - Navigate to the Binary Analysis page
   - Upload a binary file
   - Select "Ghidra" as the analysis tool

### Option 2: Manual Installation

1. **Download and install Ghidra** from the [official repository](https://github.com/NationalSecurityAgency/ghidra/releases)

2. **Set the environment variable:**

   ```sh
   # For Linux/macOS
   export GHIDRA_PATH=/path/to/ghidra

   # For Windows
   set GHIDRA_PATH=C:\path\to\ghidra
   ```

3. **Add to your .env file:**

   ```
   GHIDRA_PATH=/path/to/ghidra
   ```

## Setting Up Radare2

CodeBlue integrates with [Radare2](https://github.com/radareorg/radare2), a powerful open-source reverse engineering framework, for advanced binary analysis.

### Option 1: Using Docker (Recommended)

1. **Run the setup script:**

   ```sh
   chmod +x setup_radare2.sh
   ./setup_radare2.sh
   ```

   This will:
   - Build a Docker container with Radare2 installed
   - Set up the necessary environment variables
   - Create the required directories

2. **Restart CodeBlue:**

   ```sh
   docker-compose down && docker-compose up -d
   ```

3. **Use Radare2 in CodeBlue:**
   - Navigate to the Binary Analysis page
   - Upload a binary file
   - Select "Radare2" as the analysis tool

### Option 2: Manual Installation

1. **Install Radare2** from the [official repository](https://github.com/radareorg/radare2):

   ```sh
   git clone https://github.com/radareorg/radare2.git
   cd radare2
   sys/install.sh
   ```

2. **Set the environment variable:**

   ```sh
   # For Linux/macOS
   export RADARE2_AVAILABLE=true

   # For Windows
   set RADARE2_AVAILABLE=true
   ```

3. **Add to your .env file:**

   ```
   RADARE2_AVAILABLE=true
   ```

## Setting Up Binary Analysis Tools

CodeBlue includes comprehensive binary analysis capabilities that work across different operating systems. Here's how to set up the required tools:

### Option 1: Using Docker (Recommended)

When using Docker, all binary analysis tools are pre-installed and ready to use. This is the recommended approach for most users.

### Option 2: Manual Installation

#### For Windows:

1. **Run the Windows installation script:**

   ```powershell
   # Run as Administrator
   powershell -ExecutionPolicy Bypass -File install_windows_tools.ps1
   ```

   This script will:
   - Install Chocolatey package manager if not already installed
   - Install Python packages for binary analysis (pefile, pyelftools, macholib, capstone)
   - Install binutils (includes objdump, strings, etc.)
   - Install Dependency Walker (alternative to ldd)
   - Install Sysinternals Suite (includes sigcheck)
   - Optionally install Ghidra and Radare2

2. **Restart your terminal** to ensure all tools are available in your PATH.

#### For macOS:

1. **Run the macOS installation script:**

   ```sh
   chmod +x install_macos_tools.sh
   ./install_macos_tools.sh
   ```

   This script will:
   - Install Homebrew package manager if not already installed
   - Install Python packages for binary analysis (pefile, pyelftools, macholib, capstone)
   - Install command-line tools (binutils, coreutils, file)
   - Optionally install Ghidra and Radare2

2. **Restart your terminal** to ensure all tools are available in your PATH.

#### For Linux:

1. **Run the Linux installation script:**

   ```sh
   chmod +x install_linux_tools.sh
   sudo ./install_linux_tools.sh
   ```

   This script will:
   - Detect your Linux distribution (Debian/Ubuntu, CentOS/RHEL, Fedora)
   - Install appropriate packages for your distribution
   - Install Python packages for binary analysis (pefile, pyelftools, macholib, capstone)
   - Optionally install Ghidra and Radare2

2. **Restart your terminal** to ensure all tools are available in your PATH.

### Using Binary Analysis

Once the tools are installed:

1. Navigate to the Binary Analysis page at http://localhost:5001/binary-analysis
2. Upload a binary file or enter a file path
3. Select an analysis tool:
   - **Basic Analysis**: Quick overview using command-line tools
   - **Capstone**: Detailed disassembly
   - **Radare2**: Comprehensive analysis including control flow
   - **Ghidra**: Decompilation and advanced analysis
   - **Angr**: Symbolic execution and program analysis

4. Review the analysis results, which may include:
   - File metadata and architecture information
   - Sections, symbols, and imports
   - Identified vulnerabilities
   - Security score
   - Disassembly (with Capstone or Radare2)
   - Decompiled code (with Ghidra)
   - Control flow graphs

5. Use the advanced Hex Viewer features:
   - View binary data in both hex and ASCII formats
   - Search for specific hex patterns or ASCII text
   - Navigate between search matches with highlighting
   - Select specific bytes for focused analysis
   - Export data in multiple formats:
     - Raw binary
     - Formatted hexdump
     - C/C++ array
     - Python bytes
     - Text format

6. Generate comprehensive reports:
   - Select which sections to include in the report
   - Choose between PDF and HTML output formats
   - Add custom notes and observations
   - Preview report contents before generation
   - Download and share reports with team members

## Docker Troubleshooting

If you encounter issues with the Docker setup:

1. **Permission Issues**: If you encounter permission issues with mounted volumes:
   ```sh
   sudo chown -R $(id -u):$(id -g) ./Untested ./saved_repositories
   ```

2. **Port Conflicts**: If port 5001 is already in use, modify the port mapping in docker-compose.yml:
   ```yaml
   ports:
     - "8080:5001"  # Change 5001 to any available port
   ```

3. **Tool Installation Failures**: If a specific tool fails to install, you can modify the Dockerfile to skip it or try an alternative version.

4. **Container Access**: To access the running container's shell:
   ```sh
   docker-compose exec bluescrub bash
   ```

## Network Configuration

CodeBlue can be configured to be accessible over your network, allowing multiple users to access it from different machines.

### Default Configuration

By default, the application is:
- Bound to all network interfaces (0.0.0.0)
- Accessible at http://localhost:5001
- Also accessible via your machine's IP address (e.g., http://192.168.1.x:5001)

### Custom Configuration

You can customize the host and port by setting environment variables in your `.env` file or modifying the config.py file:

```
# Network settings in .env file
CODEBLUE_HOST=0.0.0.0  # Use 0.0.0.0 to listen on all interfaces
CODEBLUE_PORT=5001     # Change to any available port
```

Or in config.py:

```python
# Server settings
HOST = '0.0.0.0'  # Bind to all interfaces
PORT = 5001       # Default port
```

### Multi-User Access

For multi-user environments:

1. **Ensure Firewall Access**: Make sure your firewall allows incoming connections on the configured port.

2. **Find Your IP Address**:
   - On macOS/Linux: `ifconfig` or `ip addr show`
   - On Windows: `ipconfig`

3. **Share the URL**: Users can access the application using your IP address and the configured port:
   ```
   http://YOUR_IP_ADDRESS:PORT
   ```

4. **Security Considerations**:
   - For production use, consider setting up HTTPS
   - Implement proper authentication if sensitive data is being processed
   - Consider using a reverse proxy like Nginx for additional security features