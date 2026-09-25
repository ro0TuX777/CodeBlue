import os
import logging
from typing import Dict, List, Any, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_repo_structure(repo_path: str) -> Dict[str, Any]:
    """
    Extract the repository structure for visualization.

    Args:
        repo_path: Path to the local repository or directory

    Returns:
        Dictionary containing repository structure information
    """
    if not os.path.isdir(repo_path):
        logger.error(f"Path does not exist or is not a directory: {repo_path}")
        return {"error": "Path does not exist or is not a directory"}

    try:
        # Get directory name
        repo_name = os.path.basename(repo_path)

        # Get file tree
        file_tree = get_file_tree(repo_path)

        if not file_tree:
            logger.warning(f"No files found in directory: {repo_path}")
            return {"error": "No files found in directory"}

        # Get README content if available
        readme_content = get_readme_content(repo_path)

        return {
            "name": repo_name,
            "path": repo_path,
            "file_tree": file_tree,
            "readme": readme_content
        }
    except Exception as e:
        logger.error(f"Error extracting directory structure: {str(e)}")
        return {"error": str(e)}

def get_file_tree(repo_path: str) -> List[str]:
    """
    Get a list of files in the repository or directory, excluding certain patterns.

    Args:
        repo_path: Path to the local repository or directory

    Returns:
        List of file paths relative to the repository root
    """
    excluded_patterns = [
        # Dependencies
        "node_modules/",
        "vendor/",
        "venv/",
        "__pycache__/",
        # Compiled files
        ".min.",
        ".pyc",
        ".pyo",
        ".pyd",
        ".so",
        ".dll",
        ".class",
        # Asset files
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".ico",
        ".svg",
        ".ttf",
        ".woff",
        ".webp",
        # Cache and temporary files
        ".cache/",
        ".tmp/",
        # Lock files and logs
        "yarn.lock",
        "poetry.lock",
        "*.log",
        # Configuration files
        ".vscode/",
        ".idea/",
        ".git/"
    ]

    file_list = []

    try:
        for root, dirs, files in os.walk(repo_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if not any(pattern in f"{d}/" for pattern in excluded_patterns if pattern.endswith('/'))]

            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, repo_path)

                # Skip excluded files
                if any(pattern in rel_path for pattern in excluded_patterns if not pattern.endswith('/')):
                    continue

                file_list.append(rel_path)
    except Exception as e:
        logger.error(f"Error walking directory {repo_path}: {str(e)}")

    # Limit the number of files to prevent overwhelming the visualization
    max_files = 500
    if len(file_list) > max_files:
        logger.warning(f"Too many files in {repo_path}, limiting to {max_files} files")
        file_list = file_list[:max_files]

    return file_list

def get_readme_content(repo_path: str) -> Optional[str]:
    """
    Get the content of the README file if it exists.

    Args:
        repo_path: Path to the local repository

    Returns:
        Content of the README file or None if not found
    """
    readme_patterns = ["README.md", "README.txt", "README", "readme.md"]

    for pattern in readme_patterns:
        readme_path = os.path.join(repo_path, pattern)
        if os.path.isfile(readme_path):
            try:
                with open(readme_path, 'r', encoding='utf-8') as f:
                    return f.read()
            except Exception as e:
                logger.warning(f"Error reading README file: {str(e)}")
                return None

    return None

def generate_mermaid_diagram(repo_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a Mermaid.js diagram for the repository structure.
    This is a simplified version that creates a basic structure diagram.

    Args:
        repo_data: Repository structure data

    Returns:
        Dictionary containing the generated diagram and metadata
    """
    if "error" in repo_data:
        return {"error": repo_data["error"]}

    try:
        # Create a simplified directory structure
        directories = set()
        for file_path in repo_data["file_tree"]:
            parts = file_path.split(os.sep)
            for i in range(len(parts)):
                if i > 0:  # Skip the file itself
                    dir_path = os.sep.join(parts[:i])
                    directories.add(dir_path)

        # Sort directories by depth (number of separators) and then alphabetically
        sorted_dirs = sorted(list(directories), key=lambda x: (x.count(os.sep), x))

        # Create a mapping of directories to their files
        dir_files = {}
        for dir_path in sorted_dirs:
            dir_files[dir_path] = []

        # Add root directory if not present
        if '' not in dir_files:
            dir_files[''] = []

        # Assign files to their directories
        for file_path in repo_data["file_tree"]:
            dir_path = os.path.dirname(file_path)
            if dir_path in dir_files:
                dir_files[dir_path].append(os.path.basename(file_path))
            elif dir_path == '':  # Root files
                dir_files[''].append(file_path)

        # Generate Mermaid diagram code
        diagram_code = "graph TD\n"

        # Add root node
        diagram_code += f"    Root[\"{repo_data['name']}\"]:::root\n"

        # Add directory nodes
        for dir_path in sorted_dirs:
            # Create a safe ID for the directory
            safe_id = "dir_" + dir_path.replace(os.sep, "_").replace(".", "_").replace("-", "_").replace(" ", "_")
            if safe_id == "dir_":  # Handle empty string
                continue

            parent_dir = os.path.dirname(dir_path)
            parent_id = "dir_" + parent_dir.replace(os.sep, "_").replace(".", "_").replace("-", "_").replace(" ", "_") if parent_dir else "Root"
            if parent_id == "dir_":  # Handle empty parent
                parent_id = "Root"

            dir_name = os.path.basename(dir_path)
            diagram_code += f"    {safe_id}[\"{dir_name}/\"]:::directory\n"
            diagram_code += f"    {parent_id} --> {safe_id}\n"

        # Add file nodes (limit to 5 files per directory to avoid clutter)
        max_files_per_dir = 5
        for dir_path, files in dir_files.items():
            if not files:
                continue

            # Sort files alphabetically
            files.sort()

            # Create a safe ID for the directory
            dir_id = "dir_" + dir_path.replace(os.sep, "_").replace(".", "_").replace("-", "_").replace(" ", "_") if dir_path else "Root"
            if dir_id == "dir_":  # Handle empty directory
                dir_id = "Root"

            # Limit to max_files_per_dir files per directory
            shown_files = files[:max_files_per_dir]

            for i, file in enumerate(shown_files):
                # Create a unique ID for each file to avoid collisions
                file_id = f"file_{dir_id}_{i}"
                # Escape special characters in file names
                safe_file_name = file.replace("\"", "'").replace("<", "&lt;").replace(">", "&gt;")
                diagram_code += f"    {file_id}(\"{safe_file_name}\"):::file\n"
                diagram_code += f"    {dir_id} --> {file_id}\n"

            # Add indicator for more files
            if len(files) > max_files_per_dir:
                more_id = f"more_{dir_id}"
                diagram_code += f"    {more_id}(\"... {len(files) - max_files_per_dir} more files\"):::more\n"
                diagram_code += f"    {dir_id} --> {more_id}\n"

        # Add styling
        diagram_code += "    classDef root fill:#f96,stroke:#333,stroke-width:2px;\n"
        diagram_code += "    classDef directory fill:#9cf,stroke:#333,stroke-width:1px;\n"
        diagram_code += "    classDef file fill:#cfc,stroke:#333,stroke-width:1px;\n"
        diagram_code += "    classDef more fill:#fcf,stroke:#333,stroke-width:1px;\n"

        # Add click events for navigation
        diagram_code += f"    click Root \"#\" \"View repository: {repo_data['name']}\"\n"

        return {
            "diagram": diagram_code,
            "repo_name": repo_data["name"],
            "repo_path": repo_data["path"]
        }
    except Exception as e:
        logger.error(f"Error generating Mermaid diagram: {str(e)}")
        return {"error": str(e)}
