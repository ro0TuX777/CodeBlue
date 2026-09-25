"""
Binary Analysis Module for CodeBlue.

This module provides functionality to analyze binary files using various tools:
- Basic Analysis: Using command-line tools like file, strings, readelf, etc.
- Ghidra: For advanced reverse engineering and decompilation
- Radare2: For disassembly and binary analysis
- Capstone: For disassembly
- LIEF: For binary format parsing
- PyElfTools: For ELF file analysis
"""

import os
import logging
import json
import tempfile
import subprocess
from datetime import datetime, timezone
from typing import Dict, List, Any
import platform
import shutil

ENABLE_BINARY_ANALYSIS = os.environ.get('ENABLE_BINARY_ANALYSIS', 'true').lower() == 'true'
RADARE2_AVAILABLE = os.environ.get('RADARE2_AVAILABLE', 'false').lower() == 'true'
CAPSTONE_AVAILABLE = os.environ.get('CAPSTONE_AVAILABLE', 'false').lower() == 'true'
ANGR_AVAILABLE = False  # Will be set to True if angr is successfully imported

# Detect the current platform
def get_platform():
    """
    Detect the current operating system platform.

    Returns:
        str: 'windows', 'macos', or 'linux'
    """
    system = platform.system().lower()
    if system == 'windows':
        return 'windows'
    elif system == 'darwin':
        return 'macos'
    else:
        return 'linux'  # Default to Linux for other Unix-like systems

# Store the current platform
CURRENT_PLATFORM = get_platform()
logging.info(f"Detected platform: {CURRENT_PLATFORM}")

# Try to import Capstone if available
try:
    import capstone
    CAPSTONE_AVAILABLE = True
    logging.info("Capstone library successfully imported")
except ImportError:
    logging.warning("Capstone library not available")
    CAPSTONE_AVAILABLE = False

# Try to import platform-specific libraries
PEFILE_AVAILABLE = False
PYELFTOOLS_AVAILABLE = False
MACHOLIB_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
    logging.info("PE file library successfully imported")
except ImportError:
    logging.warning("PE file library not found. Windows binary analysis will use command-line tools.")

try:
    import elftools
    from elftools.elf.elffile import ELFFile
    PYELFTOOLS_AVAILABLE = True
    logging.info("ELF tools library successfully imported")
except ImportError:
    logging.warning("ELF tools library not found. Linux binary analysis will use command-line tools.")

try:
    import macholib
    from macholib.MachO import MachO
    MACHOLIB_AVAILABLE = True
    logging.info("Mach-O library successfully imported")
except ImportError:
    logging.warning("Mach-O library not found. macOS binary analysis will use command-line tools.")

# Try to import Angr if available
try:
    import angr
    import claripy
    ANGR_AVAILABLE = True
    logging.info("Angr library successfully imported")
except ImportError:
    logging.warning("Angr library not available. Advanced binary analysis will be limited.")

# Platform-specific function to get binary dependencies
def get_binary_dependencies(binary_path, file_type):
    """
    Get the shared library dependencies of a binary using platform-specific methods.

    Args:
        binary_path: Path to the binary file
        file_type: Type of the binary file (from 'file' command)

    Returns:
        List of library dependencies
    """
    libraries = []

    try:
        # ELF binaries (Linux)
        if "ELF" in file_type:
            # Try using ldd command first
            try:
                ldd_output = subprocess.check_output(['ldd', binary_path], universal_newlines=True, stderr=subprocess.DEVNULL)
                for line in ldd_output.splitlines():
                    if "=>" in line:
                        lib_name = line.split("=>")[0].strip()
                        libraries.append(lib_name)
            except (subprocess.SubprocessError, FileNotFoundError):
                # Fall back to pyelftools if available
                if PYELFTOOLS_AVAILABLE:
                    try:
                        with open(binary_path, 'rb') as f:
                            elf = ELFFile(f)
                            for section in elf.iter_sections():
                                if section.name == '.dynamic':
                                    for tag in section.iter_tags():
                                        if tag.entry.d_tag == 'DT_NEEDED':
                                            libraries.append(tag.needed)
                    except Exception as e:
                        logging.error(f"Error analyzing ELF file with pyelftools: {str(e)}")
                        libraries.append(f"(Error analyzing ELF dependencies: {str(e)})")

        # Mach-O binaries (macOS)
        elif "Mach-O" in file_type:
            # Try using otool command first
            try:
                otool_output = subprocess.check_output(['otool', '-L', binary_path], universal_newlines=True, stderr=subprocess.DEVNULL)
                for line in otool_output.splitlines()[1:]:  # Skip first line
                    lib_path = line.strip().split()[0]
                    libraries.append(os.path.basename(lib_path))
            except (subprocess.SubprocessError, FileNotFoundError):
                # Fall back to macholib if available
                if MACHOLIB_AVAILABLE:
                    try:
                        macho = MachO(binary_path)
                        for header in macho.headers:
                            for cmd in header.commands:
                                if cmd[0].cmd == macholib.MachO.LC_LOAD_DYLIB:
                                    libraries.append(os.path.basename(cmd[1]))
                    except Exception as e:
                        logging.error(f"Error analyzing Mach-O file with macholib: {str(e)}")
                        libraries.append(f"(Error analyzing Mach-O dependencies: {str(e)})")
                else:
                    libraries.append("(otool not available for Mach-O analysis on this platform)")

        # PE binaries (Windows)
        elif "PE32" in file_type or "PE32+" in file_type:
            # Try using objdump command first
            try:
                objdump_output = subprocess.check_output(['objdump', '-p', binary_path], universal_newlines=True, stderr=subprocess.DEVNULL)
                for line in objdump_output.splitlines():
                    if 'DLL Name:' in line:
                        lib_name = line.split(':', 1)[1].strip()
                        libraries.append(lib_name)
            except (subprocess.SubprocessError, FileNotFoundError):
                # Fall back to pefile if available
                if PEFILE_AVAILABLE:
                    try:
                        pe = pefile.PE(binary_path)
                        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                                libraries.append(entry.dll.decode('utf-8'))
                    except Exception as e:
                        logging.error(f"Error analyzing PE file with pefile: {str(e)}")
                        libraries.append(f"(Error analyzing PE dependencies: {str(e)})")
                else:
                    libraries.append("(objdump not available for PE analysis on this platform)")

    except Exception as e:
        logging.error(f"Error getting binary dependencies: {str(e)}")
        libraries.append(f"(Error: {str(e)})")

    return libraries

# We'll use command-line tools instead of Python libraries for better compatibility
# Check if basic tools are available
try:
    # Check if file command is available
    file_output = subprocess.check_output(['file', '--version'], stderr=subprocess.STDOUT)
    logging.info(f"File command available: {file_output.decode('utf-8', errors='ignore').strip()}")

    # Check if strings command is available (part of binutils)
    strings_output = subprocess.check_output(['strings', '--version'], stderr=subprocess.STDOUT)
    logging.info(f"Strings command available: {strings_output.decode('utf-8', errors='ignore').strip()}")

    # Check if readelf command is available (part of binutils)
    readelf_output = subprocess.check_output(['readelf', '--version'], stderr=subprocess.STDOUT)
    logging.info(f"Readelf command available: {readelf_output.decode('utf-8', errors='ignore').strip()}")

    # Check if nm command is available (part of binutils)
    nm_output = subprocess.check_output(['nm', '--version'], stderr=subprocess.STDOUT)
    logging.info(f"NM command available: {nm_output.decode('utf-8', errors='ignore').strip()}")

    BINARY_ANALYSIS_AVAILABLE = True
    logging.info("All binary analysis tools successfully detected")
except (subprocess.SubprocessError, FileNotFoundError) as e:
    logging.warning(f"Binary analysis tools not fully available: {str(e)}")
    BINARY_ANALYSIS_AVAILABLE = False

if not ENABLE_BINARY_ANALYSIS:
    logging.info("Binary analysis is disabled via environment variable")
    BINARY_ANALYSIS_AVAILABLE = False

class BinaryAnalysisResult:
    """Class to store binary analysis results."""

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.file_name = os.path.basename(binary_path)
        self.analysis_date = datetime.now(timezone.utc)
        self.file_type = ""
        self.architecture = ""
        self.bit_size = 0
        self.entry_point = 0
        self.sections = []
        self.symbols = []
        self.imports = []
        self.exports = []
        self.libraries = []
        self.strings = []
        self.vulnerabilities = []
        self.security_score = 0.0
        self.warnings = []
        self.errors = []

    def to_dict(self) -> Dict[str, Any]:
        """Convert the result to a dictionary."""
        return {
            'binary_path': self.binary_path,
            'file_name': self.file_name,
            'analysis_date': self.analysis_date.isoformat(),
            'file_type': self.file_type,
            'architecture': self.architecture,
            'bit_size': self.bit_size,
            'entry_point': self.entry_point,
            'sections': self.sections,
            'symbols': self.symbols[:100],  # Limit to first 100 symbols
            'imports': self.imports[:100],  # Limit to first 100 imports
            'exports': self.exports[:100],  # Limit to first 100 exports
            'libraries': self.libraries,
            'strings': self.strings[:100],  # Limit to first 100 strings
            'vulnerabilities': self.vulnerabilities,
            'security_score': self.security_score,
            'warnings': self.warnings,
            'errors': self.errors,
            # Store the full strings and other data for potential access by other components
            'full_strings': self.strings,
            'total_symbols': len(self.symbols),
            'total_imports': len(self.imports),
            'total_exports': len(self.exports)
        }

def analyze_binary_with_basic_tools(binary_path: str) -> Dict[str, Any]:
    """
    Analyze a binary file using command-line tools.
    This is a basic analysis that doesn't use advanced tools like Angr.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dictionary containing analysis results
    """
    if not BINARY_ANALYSIS_AVAILABLE:
        return {
            'success': False,
            'error': "Binary analysis tools not available",
            'output': "Please ensure 'file' and 'strings' commands are available."
        }

    result = BinaryAnalysisResult(binary_path)

    try:
        # Basic file checks
        if not os.path.exists(binary_path):
            result.errors.append(f"File not found: {binary_path}")
            return result.to_dict()

        if not os.access(binary_path, os.R_OK):
            result.errors.append(f"File not readable: {binary_path}")
            return result.to_dict()

        # Get file type using file command
        try:
            file_output = subprocess.check_output(['file', binary_path], universal_newlines=True)
            result.file_type = file_output.split(':', 1)[1].strip()

            # Try to determine architecture from file output
            if "x86-64" in result.file_type:
                result.architecture = "x86_64"
                result.bit_size = 64
            elif "x86" in result.file_type or "Intel 80386" in result.file_type:
                result.architecture = "x86"
                result.bit_size = 32
            elif "ARM" in result.file_type:
                result.architecture = "ARM"
                result.bit_size = 32
            elif "ARM64" in result.file_type or "aarch64" in result.file_type:
                result.architecture = "ARM64"
                result.bit_size = 64
            else:
                result.architecture = "Unknown"
                result.bit_size = 0
        except Exception as e:
            logging.error(f"Error getting file type: {str(e)}")
            result.file_type = "Unknown"
            result.architecture = "Unknown"
            result.bit_size = 0

        # Try to get entry point and sections using readelf (for ELF files)
        if "ELF" in result.file_type:
            try:
                readelf_output = subprocess.check_output(['readelf', '-h', binary_path], universal_newlines=True)
                for line in readelf_output.splitlines():
                    if "Entry point address" in line:
                        entry_point_hex = line.split(':')[1].strip()
                        result.entry_point = int(entry_point_hex, 16)

                # Get sections
                readelf_sections = subprocess.check_output(['readelf', '-S', binary_path], universal_newlines=True)
                section_lines = readelf_sections.splitlines()
                for i, line in enumerate(section_lines):
                    if i > 2 and '[' in line and ']' in line:  # Skip header lines
                        parts = line.split()
                        if len(parts) >= 5:
                            name_part = parts[1]
                            if name_part.startswith('[') and name_part.endswith(']'):
                                name = name_part[1:-1]  # Remove brackets
                                # Try to find size and address in the line
                                addr_idx = -1
                                size_idx = -1
                                for j, part in enumerate(parts):
                                    if part.startswith('0x') and addr_idx == -1:
                                        addr_idx = j
                                    elif part.startswith('0x') and addr_idx != -1 and size_idx == -1:
                                        size_idx = j

                                if addr_idx != -1 and size_idx != -1:
                                    try:
                                        addr = int(parts[addr_idx], 16)
                                        size = int(parts[size_idx], 16)
                                        result.sections.append({
                                            'name': name,
                                            'size': size,
                                            'vaddr': addr
                                        })
                                    except ValueError:
                                        pass
            except (subprocess.SubprocessError, ValueError) as e:
                logging.error(f"Error using readelf: {str(e)}")

        # Extract strings
        try:
            strings_output = subprocess.check_output(['strings', binary_path], universal_newlines=True)
            result.strings = strings_output.splitlines()
        except Exception as e:
            logging.error(f"Error extracting strings: {str(e)}")

        # Try to get symbols using nm
        try:
            nm_output = subprocess.check_output(['nm', binary_path], universal_newlines=True, stderr=subprocess.DEVNULL)
            for line in nm_output.splitlines():
                parts = line.strip().split()
                if len(parts) >= 3:
                    addr_str, sym_type, name = parts
                    try:
                        addr = int(addr_str, 16)
                        result.symbols.append({
                            'name': name,
                            'address': addr
                        })
                    except ValueError:
                        pass
                elif len(parts) == 2:
                    sym_type, name = parts
                    result.symbols.append({
                        'name': name,
                        'address': 0
                    })
        except subprocess.SubprocessError:
            # nm might fail on some binaries, that's ok
            pass

        # Get shared library dependencies using platform-specific methods
        result.libraries = get_binary_dependencies(binary_path, result.file_type)

        # Perform basic security checks
        security_checks = perform_basic_security_checks(binary_path, result)
        result.vulnerabilities.extend(security_checks)

        # Calculate security score
        result.security_score = calculate_security_score(result)

    except Exception as e:
        logging.error(f"Error in binary analysis: {str(e)}")
        result.errors.append(f"Analysis error: {str(e)}")

    return result.to_dict()

def analyze_binary_with_angr(binary_path: str) -> Dict[str, Any]:
    """
    Analyze a binary file using Angr for advanced analysis.
    If Angr is not available, falls back to basic analysis.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dictionary containing analysis results
    """
    if not ANGR_AVAILABLE:
        logging.warning("Angr is not available. Falling back to basic analysis.")
        return analyze_binary_with_basic_tools(binary_path)

    if not BINARY_ANALYSIS_AVAILABLE:
        return {
            'success': False,
            'error': "Binary analysis tools not available",
            'output': "Please ensure basic analysis tools are available."
        }

    result = BinaryAnalysisResult(binary_path)

    try:
        # Basic file checks
        if not os.path.exists(binary_path):
            result.errors.append(f"File not found: {binary_path}")
            return result.to_dict()

        if not os.access(binary_path, os.R_OK):
            result.errors.append(f"File not readable: {binary_path}")
            return result.to_dict()

        # Get file type using file command
        try:
            file_output = subprocess.check_output(['file', binary_path], universal_newlines=True)
            result.file_type = file_output.split(':', 1)[1].strip()
        except Exception as e:
            logging.error(f"Error getting file type: {str(e)}")
            result.file_type = "Unknown"

        # Start with basic analysis to get strings, symbols, etc.
        basic_result = analyze_binary_with_basic_tools(binary_path)

        # Copy over basic information
        result.file_type = basic_result.get('file_type', result.file_type)
        result.architecture = basic_result.get('architecture', result.architecture)
        result.bit_size = basic_result.get('bit_size', result.bit_size)
        result.entry_point = basic_result.get('entry_point', result.entry_point)
        result.sections = basic_result.get('sections', result.sections)
        result.symbols = basic_result.get('symbols', result.symbols)
        result.strings = basic_result.get('strings', result.strings)
        result.libraries = basic_result.get('libraries', result.libraries)

        # Now perform Angr-specific analysis
        logging.info(f"Starting Angr analysis on {binary_path}")

        # Load the binary with Angr
        import angr
        import claripy

        try:
            # Create an Angr project
            project = angr.Project(binary_path, auto_load_libs=False)

            # Get basic information from Angr
            result.architecture = project.arch.name
            result.bit_size = project.arch.bits
            result.entry_point = project.entry

            # Get sections from Angr
            for section in project.loader.main_object.sections:
                if section.name and section.size > 0:
                    result.sections.append({
                        'name': section.name,
                        'size': section.memsize,
                        'vaddr': section.vaddr
                    })

            # Get symbols from Angr
            for symbol in project.loader.main_object.symbols:
                if symbol.name and symbol.rebased_addr:
                    result.symbols.append({
                        'name': symbol.name,
                        'address': symbol.rebased_addr
                    })

            # Get imports from Angr
            for imp in project.loader.main_object.imports:
                result.imports.append({
                    'name': imp.name,
                    'address': imp.rebased_addr
                })

            # Get exports from Angr
            for exp in project.loader.main_object.exports:
                result.exports.append({
                    'name': exp.name,
                    'address': exp.rebased_addr
                })

            # Perform CFG analysis
            cfg = project.analyses.CFGFast(normalize=True)

            # Add function information
            functions = []
            for addr, func in cfg.functions.items():
                function_info = {
                    'name': func.name,
                    'address': func.addr,
                    'size': func.size,
                    'num_blocks': len(func.blocks),
                    'calls': []
                }

                # Get function calls
                for block in func.blocks:
                    for succ in cfg.get_successors(block):
                        if succ.addr in cfg.functions and succ.addr != func.addr:
                            called_func = cfg.functions[succ.addr]
                            function_info['calls'].append({
                                'name': called_func.name,
                                'address': called_func.addr
                            })

                functions.append(function_info)

            # Add functions to result
            result.__dict__['functions'] = functions

            # Look for potentially dangerous functions
            dangerous_functions = [
                'system', 'exec', 'popen', 'gets', 'strcpy', 'strcat', 'sprintf',
                'scanf', 'memcpy', 'malloc', 'free', 'printf'
            ]

            for func in functions:
                for df in dangerous_functions:
                    if df in func['name']:
                        result.vulnerabilities.append({
                            'type': 'Dangerous Function',
                            'severity': 'Medium',
                            'description': f'The binary contains potentially dangerous function: {func["name"]} at address 0x{func["address"]:x}'
                        })
                        break

            # Try to identify buffer overflow vulnerabilities
            # This is a simplified approach - real analysis would be more complex
            for func in functions:
                if any(call['name'] in ['strcpy', 'strcat', 'gets', 'sprintf'] for call in func['calls']):
                    result.vulnerabilities.append({
                        'type': 'Potential Buffer Overflow',
                        'severity': 'High',
                        'description': f'Function {func["name"]} at address 0x{func["address"]:x} calls functions that may lead to buffer overflows'
                    })

            # Calculate security score
            result.security_score = calculate_security_score(result)

        except Exception as e:
            logging.error(f"Error in Angr analysis: {str(e)}")
            result.errors.append(f"Angr analysis error: {str(e)}")

            # If Angr analysis fails, we still have the basic analysis results
            logging.info("Falling back to basic analysis results")

    except Exception as e:
        logging.error(f"Error in binary analysis: {str(e)}")
        result.errors.append(f"Analysis error: {str(e)}")

    return result.to_dict()

def analyze_binary_with_radare2(binary_path: str) -> Dict[str, Any]:
    """
    Analyze a binary file using Radare2.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dictionary containing analysis results
    """
    if not BINARY_ANALYSIS_AVAILABLE:
        return {
            'success': False,
            'error': "Binary analysis tools not available",
            'output': "Please ensure basic analysis tools are available."
        }

    # Check if Radare2 is available
    radare2_available = RADARE2_AVAILABLE
    if not radare2_available:
        try:
            # Try with r2 command
            for r2_path in ['r2', 'radare2', '/usr/local/bin/r2', '/usr/bin/r2']:
                try:
                    r2_output = subprocess.check_output([r2_path, '-v'], stderr=subprocess.STDOUT, universal_newlines=True)
                    if 'radare2' in r2_output.lower():
                        radare2_available = True
                        break
                except (subprocess.SubprocessError, FileNotFoundError):
                    continue
        except Exception as e:
            logging.debug(f"Radare2 availability check failed: {e}")

    if not radare2_available:
        return {
            'success': False,
            'error': "Radare2 not found",
            'output': "Radare2 is not installed or not in the PATH. Please run the setup_radare2.sh script to install it."
        }

    result = BinaryAnalysisResult(binary_path)

    try:
        # Basic file checks
        if not os.path.exists(binary_path):
            result.errors.append(f"File not found: {binary_path}")
            return result.to_dict()

        if not os.access(binary_path, os.R_OK):
            result.errors.append(f"File not readable: {binary_path}")
            return result.to_dict()

        # Get file type using file command
        try:
            file_output = subprocess.check_output(['file', binary_path], universal_newlines=True)
            result.file_type = file_output.split(':', 1)[1].strip()
        except Exception as e:
            logging.error(f"Error getting file type: {str(e)}")
            result.file_type = "Unknown"

        # Use r2pipe to interact with Radare2
        try:
            # We'll use r2 commands directly since r2pipe might not be available
            # Get basic information
            logging.info(f"Running Radare2 analysis on {binary_path}")

            # Find the r2 command
            r2_cmd = None
            for cmd in ['r2', 'radare2', '/usr/local/bin/r2', '/usr/bin/r2']:
                try:
                    subprocess.check_output([cmd, '-v'], stderr=subprocess.STDOUT)
                    r2_cmd = cmd
                    break
                except (subprocess.SubprocessError, FileNotFoundError):
                    continue

            if not r2_cmd:
                raise FileNotFoundError("Radare2 command not found")

            # Get file information
            r2_info_cmd = [r2_cmd, '-c', 'iI', '-q', binary_path]
            r2_info = subprocess.check_output(r2_info_cmd, universal_newlines=True)

            # Parse basic information
            for line in r2_info.splitlines():
                if line.startswith('arch'):
                    result.architecture = line.split('=')[1].strip()
                elif line.startswith('bits'):
                    result.bit_size = int(line.split('=')[1].strip())
                elif line.startswith('entry0'):
                    try:
                        entry_addr = line.split('=')[1].strip()
                        if entry_addr.startswith('0x'):
                            result.entry_point = int(entry_addr, 16)
                    except (ValueError, IndexError):
                        pass

            # Get sections
            r2_sections_cmd = [r2_cmd, '-c', 'iS', '-q', binary_path]
            r2_sections = subprocess.check_output(r2_sections_cmd, universal_newlines=True)

            # Parse sections
            for line in r2_sections.splitlines():
                if line.startswith('['):
                    # Section header
                    continue

                parts = line.strip().split()
                if len(parts) >= 4 and parts[0].isdigit():
                    try:
                        # Skip the section index
                        section_name = parts[1]
                        section_size = int(parts[2], 16) if parts[2].startswith('0x') else int(parts[2])
                        section_vaddr = int(parts[3], 16) if parts[3].startswith('0x') else int(parts[3])

                        result.sections.append({
                            'name': section_name,
                            'size': section_size,
                            'vaddr': section_vaddr
                        })
                    except (ValueError, IndexError):
                        pass

            # Get symbols
            r2_symbols_cmd = [r2_cmd, '-c', 'is', '-q', binary_path]
            r2_symbols = subprocess.check_output(r2_symbols_cmd, universal_newlines=True)

            # Parse symbols
            for line in r2_symbols.splitlines():
                parts = line.strip().split()
                if len(parts) >= 3:
                    try:
                        # Format varies, but typically: address type name
                        if parts[0].startswith('0x'):
                            addr = int(parts[0], 16)
                            name = parts[-1]  # Last part is usually the name

                            result.symbols.append({
                                'name': name,
                                'address': addr
                            })
                    except (ValueError, IndexError):
                        pass

            # Get imports
            r2_imports_cmd = [r2_cmd, '-c', 'ii', '-q', binary_path]
            r2_imports = subprocess.check_output(r2_imports_cmd, universal_newlines=True)

            # Parse imports
            for line in r2_imports.splitlines():
                parts = line.strip().split()
                if len(parts) >= 3:
                    try:
                        # Format varies, but typically: ordinal address name
                        if parts[1].startswith('0x'):
                            addr = int(parts[1], 16)
                            name = parts[-1]  # Last part is usually the name

                            result.imports.append({
                                'name': name,
                                'address': addr
                            })
                    except (ValueError, IndexError):
                        pass

            # Get libraries
            r2_libs_cmd = [r2_cmd, '-c', 'il', '-q', binary_path]
            r2_libs = subprocess.check_output(r2_libs_cmd, universal_newlines=True)

            # Parse libraries
            for line in r2_libs.splitlines():
                if line.strip():
                    result.libraries.append(line.strip())

            # Get strings
            r2_strings_cmd = [r2_cmd, '-c', 'izz', '-q', binary_path]
            r2_strings = subprocess.check_output(r2_strings_cmd, universal_newlines=True)

            # Parse strings
            for line in r2_strings.splitlines():
                parts = line.strip().split(' ', 3)  # Split by first 3 spaces
                if len(parts) >= 4:
                    try:
                        string_value = parts[3].strip()
                        if string_value and len(string_value) >= 3:  # Ignore very short strings
                            result.strings.append(string_value)
                    except (IndexError, ValueError):
                        pass

            # Run additional analysis for security checks
            r2_analysis_cmd = [r2_cmd, '-c', 'aa;afl', '-q', binary_path]
            r2_analysis = subprocess.check_output(r2_analysis_cmd, universal_newlines=True)

            # Look for potentially dangerous functions
            dangerous_functions = [
                'system', 'exec', 'popen', 'gets', 'strcpy', 'strcat', 'sprintf',
                'scanf', 'memcpy', 'malloc', 'free', 'printf'
            ]

            for line in r2_analysis.splitlines():
                for df in dangerous_functions:
                    if df in line:
                        result.vulnerabilities.append({
                            'type': 'Dangerous Function',
                            'severity': 'Medium',
                            'description': f'The binary contains potentially dangerous function: {df}'
                        })
                        break

        except subprocess.SubprocessError as e:
            logging.error(f"Error running Radare2 command: {str(e)}")
            result.errors.append(f"Radare2 analysis error: {str(e)}")

        # Calculate security score
        result.security_score = calculate_security_score(result)

    except Exception as e:
        logging.error(f"Error in Radare2 analysis: {str(e)}")
        result.errors.append(f"Analysis error: {str(e)}")

    return result.to_dict()

def analyze_binary_with_ghidra(binary_path: str) -> Dict[str, Any]:
    """
    Analyze a binary file using Ghidra's headless analyzer.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dictionary containing analysis results
    """
    if not BINARY_ANALYSIS_AVAILABLE:
        return {
            'success': False,
            'error': "Binary analysis tools not available",
            'output': "Please ensure basic analysis tools are available."
        }

    # Check if Ghidra is available
    try:
        # Try to find the Ghidra installation
        ghidra_path = os.environ.get('GHIDRA_PATH', '/opt/ghidra')
        ghidra_headless = os.path.join(ghidra_path, 'support', 'analyzeHeadless')

        if not os.path.exists(ghidra_headless):
            return {
                'success': False,
                'error': "Ghidra not found",
                'output': f"Ghidra headless analyzer not found at {ghidra_headless}. Set GHIDRA_PATH environment variable to your Ghidra installation directory."
            }
    except Exception as e:
        logging.error(f"Error checking for Ghidra: {str(e)}")
        return {
            'success': False,
            'error': f"Error checking for Ghidra: {str(e)}",
            'output': "Failed to check if Ghidra is available."
        }

    result = BinaryAnalysisResult(binary_path)

    try:
        # Basic file checks
        if not os.path.exists(binary_path):
            result.errors.append(f"File not found: {binary_path}")
            return result.to_dict()

        if not os.access(binary_path, os.R_OK):
            result.errors.append(f"File not readable: {binary_path}")
            return result.to_dict()

        # Get file type using file command
        try:
            file_output = subprocess.check_output(['file', binary_path], universal_newlines=True)
            result.file_type = file_output.split(':', 1)[1].strip()
        except Exception as e:
            logging.error(f"Error getting file type: {str(e)}")
            result.file_type = "Unknown"

        # Create a temporary project directory for Ghidra
        temp_project_dir = tempfile.mkdtemp(prefix="ghidra_project_")
        project_name = "temp_analysis"

        try:
            # Run Ghidra headless analyzer
            logging.info(f"Running Ghidra headless analyzer on {binary_path}")

            # Prepare the command
            cmd = [
                ghidra_headless,
                temp_project_dir,
                project_name,
                '-import',
                binary_path,
                '-analysisTimeoutPerFile', '300',  # 5 minutes timeout
                '-scriptPath', '/tmp',  # Path for scripts
                '-postScript', 'GhidraDecompilerScript.java',  # We'll create this script
                '-noanalysis'  # Skip initial analysis
            ]

            # Create a simple script to export decompiled code
            script_content = """
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import java.io.FileWriter;
import java.io.PrintWriter;

public class GhidraDecompilerScript extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("Running Ghidra analysis script...");

        // Get program information
        String programName = currentProgram.getName();
        String programFormat = currentProgram.getExecutableFormat();
        String programArch = currentProgram.getLanguage().getProcessor().toString();

        // Output file for analysis results
        String outputPath = "/tmp/ghidra_analysis_results.json";
        PrintWriter writer = new PrintWriter(new FileWriter(outputPath));

        // Start JSON output
        writer.println("{");
        writer.println("  \\"program_name\\": \\"" + programName + "\\",");
        writer.println("  \\"format\\": \\"" + programFormat + "\\",");
        writer.println("  \\"architecture\\": \\"" + programArch + "\\",");

        // Get memory sections
        writer.println("  \\"memory_sections\\": [");
        Memory memory = currentProgram.getMemory();
        MemoryBlock[] blocks = memory.getBlocks();
        for (int i = 0; i < blocks.length; i++) {
            MemoryBlock block = blocks[i];
            writer.println("    {");
            writer.println("      \\"name\\": \\"" + block.getName() + "\\",");
            writer.println("      \\"start\\": \\"0x" + Long.toHexString(block.getStart().getOffset()) + "\\",");
            writer.println("      \\"size\\": " + block.getSize() + ",");
            writer.println("      \\"readable\\": " + block.isRead() + ",");
            writer.println("      \\"writable\\": " + block.isWrite() + ",");
            writer.println("      \\"executable\\": " + block.isExecute() + "");
            if (i < blocks.length - 1) {
                writer.println("    },");
            } else {
                writer.println("    }");
            }
        }
        writer.println("  ],");

        // Get functions
        writer.println("  \\"functions\\": [");
        Listing listing = currentProgram.getListing();
        FunctionIterator functions = listing.getFunctions(true);
        boolean firstFunction = true;
        int functionCount = 0;
        int maxFunctions = 100; // Limit to 100 functions to avoid huge output

        while (functions.hasNext() && functionCount < maxFunctions) {
            Function function = functions.next();
            if (!firstFunction) {
                writer.println("    },");
            }
            firstFunction = false;
            functionCount++;

            writer.println("    {");
            writer.println("      \\"name\\": \\"" + function.getName() + "\\",");
            writer.println("      \\"address\\": \\"0x" + Long.toHexString(function.getEntryPoint().getOffset()) + "\\",");
            writer.println("      \\"size\\": " + function.getBody().getNumAddresses() + "");
        }

        if (functionCount > 0) {
            writer.println("    }");
        }
        writer.println("  ],");

        // Get symbols
        writer.println("  \\"symbols\\": [");
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        Symbol[] symbols = symbolTable.getExternalSymbols();
        for (int i = 0; i < Math.min(symbols.length, 100); i++) { // Limit to 100 symbols
            Symbol symbol = symbols[i];
            writer.println("    {");
            writer.println("      \\"name\\": \\"" + symbol.getName() + "\\",");
            writer.println("      \\"address\\": \\"0x" + Long.toHexString(symbol.getAddress().getOffset()) + "\\"");
            if (i < Math.min(symbols.length, 100) - 1) {
                writer.println("    },");
            } else {
                writer.println("    }");
            }
        }
        writer.println("  ]");

        // End JSON output
        writer.println("}");
        writer.close();

        println("Analysis complete. Results written to " + outputPath);
    }
}
"""

            # Write the script to a temporary file
            script_path = os.path.join('/tmp', 'GhidraDecompilerScript.java')
            with open(script_path, 'w') as f:
                f.write(script_content)

            # Run Ghidra headless analyzer
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            _, stderr = process.communicate(timeout=600)  # 10 minutes timeout

            if process.returncode != 0:
                logging.error(f"Ghidra analysis failed: {stderr}")
                result.errors.append(f"Ghidra analysis failed: {stderr}")
            else:
                logging.info("Ghidra analysis completed successfully")

                # Read the analysis results
                try:
                    with open('/tmp/ghidra_analysis_results.json', 'r') as f:
                        ghidra_results = json.load(f)

                    # Update the result object with Ghidra's analysis
                    result.architecture = ghidra_results.get('architecture', 'Unknown')

                    # Extract memory sections
                    for section in ghidra_results.get('memory_sections', []):
                        result.sections.append({
                            'name': section.get('name', 'Unknown'),
                            'size': section.get('size', 0),
                            'vaddr': int(section.get('start', '0x0'), 16)
                        })

                    # Extract functions as symbols
                    for function in ghidra_results.get('functions', []):
                        result.symbols.append({
                            'name': function.get('name', 'Unknown'),
                            'address': int(function.get('address', '0x0'), 16)
                        })

                    # Extract symbols
                    for symbol in ghidra_results.get('symbols', []):
                        result.imports.append({
                            'name': symbol.get('name', 'Unknown'),
                            'address': int(symbol.get('address', '0x0'), 16)
                        })

                except Exception as e:
                    logging.error(f"Error parsing Ghidra results: {str(e)}")
                    result.errors.append(f"Error parsing Ghidra results: {str(e)}")

        except subprocess.TimeoutExpired:
            logging.error("Ghidra analysis timed out")
            result.errors.append("Ghidra analysis timed out after 10 minutes")

        except Exception as e:
            logging.error(f"Error running Ghidra: {str(e)}")
            result.errors.append(f"Error running Ghidra: {str(e)}")

        finally:
            # Clean up temporary files
            try:
                shutil.rmtree(temp_project_dir)
                if os.path.exists('/tmp/ghidra_analysis_results.json'):
                    os.remove('/tmp/ghidra_analysis_results.json')
                if os.path.exists('/tmp/GhidraDecompilerScript.java'):
                    os.remove('/tmp/GhidraDecompilerScript.java')
            except Exception as e:
                logging.error(f"Error cleaning up temporary files: {str(e)}")

        # Extract strings using the strings command
        try:
            strings_output = subprocess.check_output(['strings', binary_path], universal_newlines=True)
            result.strings = strings_output.splitlines()
        except Exception as e:
            logging.error(f"Error extracting strings: {str(e)}")

        # Perform basic security checks
        security_checks = perform_basic_security_checks(binary_path, result)
        result.vulnerabilities.extend(security_checks)

        # Calculate security score
        result.security_score = calculate_security_score(result)

    except Exception as e:
        logging.error(f"Error in Ghidra analysis: {str(e)}")
        result.errors.append(f"Analysis error: {str(e)}")

    return result.to_dict()

def perform_basic_security_checks(binary_path: str, result: BinaryAnalysisResult) -> List[Dict[str, str]]:
    """
    Perform basic security checks on the binary using command-line tools.

    Args:
        binary_path: Path to the binary file
        result: BinaryAnalysisResult object to analyze

    Returns:
        List of vulnerability dictionaries
    """
    vulnerabilities = []

    # Check for executable stack using readelf (for ELF files)
    if "ELF" in result.file_type:
        try:
            readelf_output = subprocess.check_output(['readelf', '-l', binary_path], universal_newlines=True)
            stack_executable = False
            for line in readelf_output.splitlines():
                if "GNU_STACK" in line and "RWE" in line:
                    stack_executable = True
                    break

            if stack_executable:
                vulnerabilities.append({
                    'type': 'Executable Stack',
                    'severity': 'High',
                    'description': 'The binary has an executable stack, which can be exploited for code injection attacks.'
                })
        except subprocess.SubprocessError:
            pass

    # Check for RELRO using readelf (for ELF files)
    if "ELF" in result.file_type:
        try:
            readelf_output = subprocess.check_output(['readelf', '-l', binary_path], universal_newlines=True)
            has_relro = False
            for line in readelf_output.splitlines():
                if "GNU_RELRO" in line:
                    has_relro = True
                    break

            if not has_relro:
                vulnerabilities.append({
                    'type': 'No RELRO',
                    'severity': 'Medium',
                    'description': 'The binary does not have RELRO protection, making it vulnerable to GOT overwrite attacks.'
                })
        except subprocess.SubprocessError:
            pass

    # Check for dangerous strings
    dangerous_functions = [
        'system', 'exec', 'popen', 'gets', 'strcpy', 'strcat', 'sprintf',
        'scanf', 'memcpy', 'malloc', 'free', 'printf'
    ]

    # Check in symbols and strings
    dangerous_found = set()

    # Check in symbols
    for symbol in result.symbols:
        func_name = symbol.get('name', '')
        for df in dangerous_functions:
            if df in func_name and df not in dangerous_found:
                dangerous_found.add(df)
                vulnerabilities.append({
                    'type': 'Dangerous Function',
                    'severity': 'Medium',
                    'description': f'The binary contains potentially dangerous function: {df}'
                })

    # Check in strings
    for string in result.strings:
        for df in dangerous_functions:
            if df in string and df not in dangerous_found:
                dangerous_found.add(df)
                vulnerabilities.append({
                    'type': 'Dangerous Function',
                    'severity': 'Medium',
                    'description': f'The binary contains potentially dangerous function: {df}'
                })

    # Check for hardcoded credentials
    credential_patterns = [
        'password', 'passwd', 'pwd', 'user', 'username', 'login',
        'secret', 'api_key', 'apikey', 'token', 'auth'
    ]

    for string in result.strings:
        lower_string = string.lower()
        for pattern in credential_patterns:
            if pattern in lower_string and len(string) > len(pattern) + 2:
                # Avoid false positives by checking if it looks like a credential
                if '=' in string or ':' in string or ' ' in string:
                    vulnerabilities.append({
                        'type': 'Potential Hardcoded Credential',
                        'severity': 'High',
                        'description': f'The binary may contain a hardcoded credential: "{string[:20]}..."'
                    })
                    break

    return vulnerabilities

def calculate_security_score(result):
    """Calculate a security score based on vulnerabilities."""
    base_score = 100.0

    # Deduct points for vulnerabilities
    severity_weights = {
        'High': 20.0,
        'Medium': 10.0,
        'Low': 5.0
    }

    for vuln in result.vulnerabilities:
        severity = vuln.get('severity', 'Low')
        base_score -= severity_weights.get(severity, 5.0)

    # Deduct points for dangerous imports
    dangerous_imports_count = sum(1 for imp in result.imports if 'system' in imp.get('name', '') or 'exec' in imp.get('name', ''))
    base_score -= dangerous_imports_count * 5.0

    # Ensure score is between 0 and 100
    return max(0.0, min(100.0, base_score))

def get_binary_analysis_tools():
    """
    Get a list of available binary analysis tools.

    Returns:
        List of dictionaries containing tool information
    """
    # Check if command-line tools are available
    file_available = False
    strings_available = False
    ghidra_available = False
    radare2_available = False

    try:
        subprocess.check_output(['file', '--version'], stderr=subprocess.STDOUT)
        file_available = True
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    try:
        subprocess.check_output(['strings', '--version'], stderr=subprocess.STDOUT)
        strings_available = True
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    # Check if Ghidra is available
    try:
        ghidra_path = os.environ.get('GHIDRA_PATH', '/opt/ghidra')
        ghidra_headless = os.path.join(ghidra_path, 'support', 'analyzeHeadless')
        if os.path.exists(ghidra_headless):
            ghidra_available = True
    except Exception as e:
        logging.debug(f"Ghidra availability check failed: {e}")

    # Check if Radare2 is available
    radare2_available = RADARE2_AVAILABLE
    if not radare2_available:
        try:
            r2_output = subprocess.check_output(['r2', '-v'], stderr=subprocess.STDOUT, universal_newlines=True)
            if 'radare2' in r2_output.lower():
                radare2_available = True
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

    # Basic tools availability
    basic_tools_available = file_available and strings_available

    tools = [
        {
            'id': 'basic',
            'name': 'Basic Analysis',
            'description': 'Basic binary analysis using file, strings, and other command-line tools.',
            'available': basic_tools_available
        },
        {
            'id': 'angr',
            'name': 'Angr Analysis',
            'description': 'Advanced binary analysis using the Angr framework for symbolic execution and program analysis.',
            'available': ANGR_AVAILABLE
        },
        {
            'id': 'ghidra',
            'name': 'Ghidra',
            'description': 'NSA-developed software reverse engineering framework with advanced analysis capabilities.',
            'available': ghidra_available
        },
        {
            'id': 'radare2',
            'name': 'Radare2',
            'description': 'Advanced command-line disassembler and binary analysis tool.',
            'available': radare2_available
        },

    ]

    # Check if Capstone is available
    capstone_available = CAPSTONE_AVAILABLE
    if not capstone_available:
        try:
            import capstone
            capstone_available = True
        except ImportError:
            pass

    # Add Capstone to the tools list
    try:
        import capstone
        capstone_available = True
    except ImportError:
        capstone_available = False

    tools.append({
        'id': 'capstone',
        'name': 'Capstone',
        'description': 'Advanced multi-architecture disassembly framework.',
        'available': capstone_available
    })

    return tools

def analyze_binary_with_capstone(binary_path: str) -> Dict[str, Any]:
    """
    Analyze a binary file using Capstone disassembler.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dictionary containing analysis results
    """
    if not BINARY_ANALYSIS_AVAILABLE:
        return {
            'success': False,
            'error': "Binary analysis tools not available",
            'output': "Please ensure basic analysis tools are available."
        }

    # Check if Capstone is available
    try:
        import capstone
    except ImportError:
        return {
            'success': False,
            'error': "Capstone not found",
            'output': "Capstone is not installed. Please run the install_capstone.sh script to install it."
        }

    result = BinaryAnalysisResult(binary_path)

    try:
        # Basic file checks
        if not os.path.exists(binary_path):
            result.errors.append(f"File not found: {binary_path}")
            return result.to_dict()

        if not os.access(binary_path, os.R_OK):
            result.errors.append(f"File not readable: {binary_path}")
            return result.to_dict()

        # Get file type using file command
        try:
            file_output = subprocess.check_output(['file', binary_path], universal_newlines=True)
            result.file_type = file_output.split(':', 1)[1].strip()
        except Exception as e:
            logging.error(f"Error getting file type: {str(e)}")
            result.file_type = "Unknown"

        # Determine architecture and mode
        arch = None
        mode = None

        if 'x86-64' in result.file_type or 'x86_64' in result.file_type or 'amd64' in result.file_type:
            arch = capstone.CS_ARCH_X86
            mode = capstone.CS_MODE_64
            result.architecture = "x86-64"
            result.bit_size = 64
        elif 'x86' in result.file_type or 'Intel 80386' in result.file_type or 'i386' in result.file_type:
            arch = capstone.CS_ARCH_X86
            mode = capstone.CS_MODE_32
            result.architecture = "x86"
            result.bit_size = 32
        elif 'ARM' in result.file_type or 'arm' in result.file_type.lower():
            # Check for ARM64/AArch64
            if '64-bit' in result.file_type or 'arm64' in result.file_type.lower() or 'aarch64' in result.file_type.lower():
                arch = capstone.CS_ARCH_ARM64
                mode = capstone.CS_MODE_ARM
                result.architecture = "ARM64"
                result.bit_size = 64
            else:
                arch = capstone.CS_ARCH_ARM
                mode = capstone.CS_MODE_ARM
                result.architecture = "ARM"
                result.bit_size = 32
        elif 'MIPS' in result.file_type:
            arch = capstone.CS_ARCH_MIPS
            if '64-bit' in result.file_type:
                mode = capstone.CS_MODE_MIPS64
                result.architecture = "MIPS64"
                result.bit_size = 64
            else:
                mode = capstone.CS_MODE_MIPS32
                result.architecture = "MIPS"
                result.bit_size = 32
        elif 'PowerPC' in result.file_type:
            arch = capstone.CS_ARCH_PPC
            if '64-bit' in result.file_type:
                mode = capstone.CS_MODE_64
                result.architecture = "PowerPC64"
                result.bit_size = 64
            else:
                mode = capstone.CS_MODE_32
                result.architecture = "PowerPC"
                result.bit_size = 32
        # Special case for Mach-O arm64
        elif 'Mach-O' in result.file_type and ('arm64' in result.file_type.lower() or 'aarch64' in result.file_type.lower()):
            arch = capstone.CS_ARCH_ARM64
            mode = capstone.CS_MODE_ARM
            result.architecture = "ARM64"
            result.bit_size = 64
        else:
            result.errors.append(f"Unsupported architecture: {result.file_type}")
            return result.to_dict()

        # Read the binary file
        with open(binary_path, 'rb') as f:
            binary_data = f.read()

        # Get entry point and sections using readelf
        try:
            readelf_output = subprocess.check_output(['readelf', '-h', binary_path], universal_newlines=True)
            for line in readelf_output.splitlines():
                if 'Entry point address:' in line:
                    entry_point_str = line.split(':', 1)[1].strip()
                    try:
                        result.entry_point = int(entry_point_str, 16)
                    except ValueError:
                        result.entry_point = 0
        except Exception as e:
            logging.error(f"Error getting entry point: {str(e)}")
            result.entry_point = 0

        # Get sections
        try:
            if 'ELF' in result.file_type:
                # For ELF files, use readelf
                readelf_sections = subprocess.check_output(['readelf', '-S', binary_path], universal_newlines=True)
                section_lines = readelf_sections.splitlines()

                # Skip header lines
                section_start = 0
                for i, line in enumerate(section_lines):
                    if 'Section Headers:' in line or '[Nr]' in line:
                        section_start = i + 2
                        break

                # Parse sections
                for i in range(section_start, len(section_lines)):
                    line = section_lines[i].strip()
                    if not line:
                        continue

                    parts = line.split()
                    if len(parts) >= 7:
                        try:
                            section_name = parts[1]
                            section_type = parts[2]
                            section_addr = int(parts[3], 16) if '0x' in parts[3] else int(parts[3])
                            section_offset = int(parts[4], 16) if '0x' in parts[4] else int(parts[4])
                            section_size = int(parts[5], 16) if '0x' in parts[5] else int(parts[5])

                            result.sections.append({
                                'name': section_name,
                                'type': section_type,
                                'address': section_addr,
                                'offset': section_offset,
                                'size': section_size
                            })

                            # If this is a code section, disassemble it
                            if section_type == 'PROGBITS' and (section_name == '.text' or 'CODE' in section_name):
                                # Create Capstone instance
                                md = capstone.Cs(arch, mode)
                                md.detail = True

                                # Extract section data
                                section_data = binary_data[section_offset:section_offset + section_size]

                                # Disassemble
                                instructions = []
                                for i, (address, size, mnemonic, op_str) in enumerate(md.disasm_lite(section_data, section_addr)):
                                    instructions.append({
                                        'address': address,
                                        'size': size,
                                        'mnemonic': mnemonic,
                                        'operands': op_str
                                    })

                                    # Limit to 1000 instructions to avoid overwhelming the UI
                                    if i >= 1000:
                                        break

                                # Add disassembly to result
                                if 'disassembly' not in result.__dict__:
                                    result.__dict__['disassembly'] = {}

                                result.__dict__['disassembly'][section_name] = instructions
                        except Exception as e:
                            logging.error(f"Error parsing section: {str(e)}")

            elif 'Mach-O' in result.file_type:
                # For Mach-O files, try to use otool
                try:
                    # Get sections with otool
                    otool_output = subprocess.check_output(['otool', '-l', binary_path], universal_newlines=True)

                    # Parse sections
                    section_name = None
                    section_addr = 0
                    section_offset = 0
                    section_size = 0
                    in_section = False

                    for line in otool_output.splitlines():
                        line = line.strip()
                        if 'Section' in line and '(' in line and ')' in line:
                            # New section
                            if section_name:
                                # Add previous section
                                result.sections.append({
                                    'name': section_name,
                                    'type': 'CODE' if 'text' in section_name else 'DATA',
                                    'address': section_addr,
                                    'offset': section_offset,
                                    'size': section_size
                                })

                            # Reset section info
                            section_name = None
                            section_addr = 0
                            section_offset = 0
                            section_size = 0
                            in_section = True

                        if in_section:
                            if 'sectname' in line and '=' in line:
                                section_name = line.split('=')[1].strip()
                            elif 'addr' in line and '=' in line:
                                try:
                                    section_addr = int(line.split('=')[1].strip(), 16)
                                except ValueError:
                                    pass
                            elif 'offset' in line and '=' in line:
                                try:
                                    section_offset = int(line.split('=')[1].strip())
                                except ValueError:
                                    pass
                            elif 'size' in line and '=' in line:
                                try:
                                    section_size = int(line.split('=')[1].strip())
                                except ValueError:
                                    pass

                    # Add the last section
                    if section_name:
                        result.sections.append({
                            'name': section_name,
                            'type': 'CODE' if 'text' in section_name else 'DATA',
                            'address': section_addr,
                            'offset': section_offset,
                            'size': section_size
                        })

                    # Disassemble text sections
                    for section in result.sections:
                        if section['name'] == '__text' or 'text' in section['name'].lower():
                            # Create Capstone instance
                            md = capstone.Cs(arch, mode)
                            md.detail = True

                            # Extract section data
                            section_offset = section['offset']
                            section_size = section['size']
                            section_addr = section['address']

                            if section_offset + section_size <= len(binary_data):
                                section_data = binary_data[section_offset:section_offset + section_size]

                                # Disassemble
                                instructions = []
                                for i, (address, size, mnemonic, op_str) in enumerate(md.disasm_lite(section_data, section_addr)):
                                    instructions.append({
                                        'address': address,
                                        'size': size,
                                        'mnemonic': mnemonic,
                                        'operands': op_str
                                    })

                                    # Limit to 1000 instructions to avoid overwhelming the UI
                                    if i >= 1000:
                                        break

                                # Add disassembly to result
                                if 'disassembly' not in result.__dict__:
                                    result.__dict__['disassembly'] = {}

                                result.__dict__['disassembly'][section['name']] = instructions

                except (subprocess.SubprocessError, FileNotFoundError) as e:
                    logging.error(f"Error using otool: {str(e)}")

                    # If otool fails, try a simple approach - just disassemble from the beginning
                    # This is not ideal but better than nothing
                    if arch and mode:
                        md = capstone.Cs(arch, mode)
                        md.detail = True

                        # Disassemble first 4KB as a sample
                        sample_size = min(4096, len(binary_data))
                        instructions = []

                        for i, (address, size, mnemonic, op_str) in enumerate(md.disasm_lite(binary_data[:sample_size], 0)):
                            instructions.append({
                                'address': address,
                                'size': size,
                                'mnemonic': mnemonic,
                                'operands': op_str
                            })

                            # Limit to 1000 instructions
                            if i >= 1000:
                                break

                        # Add disassembly to result
                        if 'disassembly' not in result.__dict__:
                            result.__dict__['disassembly'] = {}

                        result.__dict__['disassembly']['sample'] = instructions

            # For PE files or other formats, we'll add specific handling later

        except Exception as e:
            logging.error(f"Error getting sections: {str(e)}")

        # Get symbols
        try:
            nm_output = subprocess.check_output(['nm', '-n', binary_path], universal_newlines=True)
            for line in nm_output.splitlines():
                parts = line.strip().split()
                if len(parts) >= 3:
                    addr_str, sym_type, name = parts
                    try:
                        addr = int(addr_str, 16)
                        result.symbols.append({
                            'name': name,
                            'address': addr,
                            'type': sym_type
                        })
                    except ValueError:
                        pass
                elif len(parts) == 2:
                    sym_type, name = parts
                    result.symbols.append({
                        'name': name,
                        'address': 0,
                        'type': sym_type
                    })
        except Exception as e:
            logging.error(f"Error getting symbols: {str(e)}")

        # Get imports
        try:
            if 'ELF' in result.file_type:
                readelf_imports = subprocess.check_output(['readelf', '-s', binary_path], universal_newlines=True)
                for line in readelf_imports.splitlines():
                    if 'GLOBAL' in line and 'UND' in line:
                        parts = line.strip().split()
                        if len(parts) >= 8:
                            name = parts[7]
                            result.imports.append({
                                'name': name,
                                'address': 0
                            })
            elif 'PE32' in result.file_type:
                # For PE files, use objdump
                objdump_imports = subprocess.check_output(['objdump', '-p', binary_path], universal_newlines=True)
                import_section = False
                dll_name = ""
                for line in objdump_imports.splitlines():
                    if 'Import Address Table' in line:
                        import_section = True
                    elif import_section and line.strip():
                        if 'DLL Name:' in line:
                            dll_name = line.split(':', 1)[1].strip()
                        elif dll_name and line.strip():
                            parts = line.strip().split()
                            if len(parts) >= 2:
                                name = parts[1]
                                result.imports.append({
                                    'name': f"{dll_name}:{name}",
                                    'address': 0
                                })
        except Exception as e:
            logging.error(f"Error getting imports: {str(e)}")

        # Get libraries
        try:
            if 'ELF' in result.file_type:
                ldd_output = subprocess.check_output(['ldd', binary_path], universal_newlines=True, stderr=subprocess.DEVNULL)
                for line in ldd_output.splitlines():
                    if '=>' in line:
                        lib_name = line.split('=>')[0].strip()
                        lib_path = line.split('=>')[1].split('(')[0].strip()
                        result.libraries.append({
                            'name': lib_name,
                            'path': lib_path
                        })
        except Exception as e:
            logging.error(f"Error getting libraries: {str(e)}")

        # Extract strings
        try:
            strings_output = subprocess.check_output(['strings', binary_path], universal_newlines=True)
            result.strings = strings_output.splitlines()
        except Exception as e:
            logging.error(f"Error extracting strings: {str(e)}")

        # Perform basic security checks
        security_checks = perform_basic_security_checks(binary_path, result)
        result.vulnerabilities.extend(security_checks)

        # Calculate security score
        result.security_score = calculate_security_score(result)

    except Exception as e:
        logging.error(f"Error in Capstone analysis: {str(e)}")
        result.errors.append(f"Analysis error: {str(e)}")

    return result.to_dict()
