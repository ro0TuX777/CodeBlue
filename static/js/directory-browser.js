/**
 * Directory Browser for Visualization Page
 * 
 * This script provides a more advanced directory browsing experience
 * by showing a modal with a file system tree.
 */

// Initialize the directory browser when the page loads
document.addEventListener('DOMContentLoaded', function() {
    initDirectoryBrowser();
});

// Initialize the directory browser
function initDirectoryBrowser() {
    // Add event listener to the browse button
    const browseButton = document.getElementById('browse-button');
    if (browseButton) {
        browseButton.addEventListener('click', showDirectoryBrowser);
    }
    
    // Add event listener to the file input (fallback for browsers that don't support the directory browser)
    const directoryInput = document.getElementById('directory-input');
    if (directoryInput) {
        directoryInput.addEventListener('change', handleDirectorySelection);
    }
    
    // Create the directory browser modal if it doesn't exist
    if (!document.getElementById('directory-browser-modal')) {
        createDirectoryBrowserModal();
    }
}

// Create the directory browser modal
function createDirectoryBrowserModal() {
    const modal = document.createElement('div');
    modal.id = 'directory-browser-modal';
    modal.className = 'modal fade';
    modal.tabIndex = '-1';
    modal.role = 'dialog';
    modal.setAttribute('aria-labelledby', 'directoryBrowserLabel');
    modal.setAttribute('aria-hidden', 'true');
    
    modal.innerHTML = `
        <div class="modal-dialog modal-lg" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="directoryBrowserLabel">Select a Directory</h5>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label for="current-path">Current Path:</label>
                        <div class="input-group">
                            <input type="text" class="form-control" id="current-path" readonly>
                            <div class="input-group-append">
                                <button class="btn btn-outline-secondary" type="button" id="parent-dir-button">
                                    <i class="fa fa-level-up" aria-hidden="true"></i> Up
                                </button>
                            </div>
                        </div>
                    </div>
                    <div id="directory-tree" class="border p-2" style="height: 300px; overflow-y: auto;">
                        <div class="spinner-border text-primary" role="status">
                            <span class="sr-only">Loading...</span>
                        </div>
                        <p>Loading directory structure...</p>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" id="select-directory-button">Select Directory</button>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    // Add event listeners for the modal
    document.getElementById('parent-dir-button').addEventListener('click', navigateToParentDirectory);
    document.getElementById('select-directory-button').addEventListener('click', selectCurrentDirectory);
    
    // Initialize the modal with jQuery
    $(modal).on('shown.bs.modal', function() {
        loadDirectoryContents();
    });
}

// Show the directory browser modal
function showDirectoryBrowser() {
    // Check if the browser supports the directory browser
    const directoryInput = document.getElementById('directory-input');
    
    // If the browser supports the webkitdirectory attribute, use the native file picker
    if ('webkitdirectory' in directoryInput) {
        directoryInput.click();
    } else {
        // Otherwise, show our custom modal
        $('#directory-browser-modal').modal('show');
    }
}

// Handle directory selection from the file input
function handleDirectorySelection(event) {
    const files = event.target.files;
    if (files.length > 0) {
        // Get the directory path from the first file
        const filePath = files[0].webkitRelativePath;
        const dirPath = filePath.split('/')[0];
        
        // Get the full path using AJAX
        fetch('/get_full_path?dir_name=' + encodeURIComponent(dirPath))
            .then(response => response.json())
            .then(data => {
                if (data.full_path) {
                    document.getElementById('path').value = data.full_path;
                } else {
                    alert('Could not determine the full path. Please enter it manually.');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('An error occurred while getting the full path. Please enter it manually.');
            });
    }
}

// Load directory contents for the browser modal
function loadDirectoryContents(path = '') {
    const directoryTree = document.getElementById('directory-tree');
    directoryTree.innerHTML = `
        <div class="spinner-border text-primary" role="status">
            <span class="sr-only">Loading...</span>
        </div>
        <p>Loading directory structure...</p>
    `;
    
    // Get the directory contents using AJAX
    fetch('/get_directory_contents?path=' + encodeURIComponent(path))
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                directoryTree.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
                return;
            }
            
            // Update the current path
            document.getElementById('current-path').value = data.current_path;
            
            // Display the directory contents
            directoryTree.innerHTML = '';
            
            if (data.directories.length === 0 && data.files.length === 0) {
                directoryTree.innerHTML = '<div class="alert alert-info">This directory is empty.</div>';
                return;
            }
            
            // Add directories
            data.directories.forEach(dir => {
                const dirElement = document.createElement('div');
                dirElement.className = 'directory-item p-2 border-bottom';
                dirElement.innerHTML = `
                    <i class="fa fa-folder text-warning" aria-hidden="true"></i>
                    <span class="ml-2">${dir}</span>
                `;
                dirElement.addEventListener('click', () => {
                    const newPath = data.current_path ? `${data.current_path}/${dir}` : dir;
                    loadDirectoryContents(newPath);
                });
                directoryTree.appendChild(dirElement);
            });
            
            // Add files (just for display, not selectable)
            data.files.forEach(file => {
                const fileElement = document.createElement('div');
                fileElement.className = 'file-item p-2 border-bottom text-muted';
                fileElement.innerHTML = `
                    <i class="fa fa-file-o" aria-hidden="true"></i>
                    <span class="ml-2">${file}</span>
                `;
                directoryTree.appendChild(fileElement);
            });
        })
        .catch(error => {
            console.error('Error:', error);
            directoryTree.innerHTML = `<div class="alert alert-danger">An error occurred while loading the directory contents.</div>`;
        });
}

// Navigate to the parent directory
function navigateToParentDirectory() {
    const currentPath = document.getElementById('current-path').value;
    const parentPath = currentPath.substring(0, currentPath.lastIndexOf('/'));
    loadDirectoryContents(parentPath);
}

// Select the current directory
function selectCurrentDirectory() {
    const currentPath = document.getElementById('current-path').value;
    document.getElementById('path').value = currentPath;
    $('#directory-browser-modal').modal('hide');
}
