#!/usr/bin/env python3

import subprocess
import sys
import os

def check_command(command, args=None):
    """Check if a command is available and print its version."""
    if args is None:
        args = ['--version']

    try:
        output = subprocess.check_output([command] + args, stderr=subprocess.STDOUT, universal_newlines=True)
        print(f"✅ {command} is available: {output.strip()}")
        return True
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        print(f"❌ {command} is not available: {str(e)}")
        return False

def main():
    """Check if binary analysis tools are installed."""
    print("Checking binary analysis tools...")

    # List of tools to check
    tools = [
        ('file', None),
        ('strings', None),
        ('readelf', None),
        ('nm', None),
        ('objdump', None),
        ('xxd', ['-v']),
    ]

    # Check each tool
    all_available = True
    for tool, args in tools:
        if not check_command(tool, args):
            all_available = False

    # Check if Radare2 is available
    try:
        # Try with r2 command first (with full path)
        r2_output = subprocess.check_output(['/usr/local/bin/r2', '-v'], stderr=subprocess.STDOUT, universal_newlines=True)
        print(f"✅ Radare2 is available: {r2_output.strip()}")
        os.environ['RADARE2_AVAILABLE'] = 'true'
    except (subprocess.SubprocessError, FileNotFoundError):
        try:
            # Try with radare2 command
            r2_output = subprocess.check_output(['radare2', '-v'], stderr=subprocess.STDOUT, universal_newlines=True)
            print(f"✅ Radare2 is available: {r2_output.strip()}")
            os.environ['RADARE2_AVAILABLE'] = 'true'
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            print(f"❌ Radare2 is not available: {str(e)}")
            os.environ['RADARE2_AVAILABLE'] = 'false'

    # Check if Capstone is available
    try:
        import capstone
        print(f"✅ Capstone is available: {capstone.__version__}")
        os.environ['CAPSTONE_AVAILABLE'] = 'true'
    except ImportError:
        print("❌ Capstone is not available: ImportError")
        all_available = False

    # Print summary
    if all_available:
        print("\n✅ All binary analysis tools are available!")
        return 0
    else:
        print("\n❌ Some binary analysis tools are missing.")
        print("Run 'sudo ./install_binary_tools.sh' to install them.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
