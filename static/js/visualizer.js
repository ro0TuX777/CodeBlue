// Initialize Mermaid when the page loads
document.addEventListener('DOMContentLoaded', function() {
    initializeMermaid();
    setupEventListeners();
});

// Initialize Mermaid with custom configuration
function initializeMermaid() {
    mermaid.initialize({
        startOnLoad: true,
        theme: 'neutral',
        flowchart: {
            htmlLabels: true,
            curve: 'basis',
            nodeSpacing: 50,
            rankSpacing: 50,
            padding: 15
        },
        themeCSS: `
            .clickable {
                transition: transform 0.2s ease;
            }
            .clickable:hover {
                transform: scale(1.05);
                cursor: pointer;
            }
            .clickable:hover > * {
                filter: brightness(0.85);
            }
        `
    });
}

// Set up event listeners for interactive elements
function setupEventListeners() {
    // Export diagram as PNG
    const exportButton = document.getElementById('export-diagram');
    if (exportButton) {
        exportButton.addEventListener('click', exportDiagramAsPNG);
    }

    // Toggle zoom functionality
    const zoomToggle = document.getElementById('toggle-zoom');
    if (zoomToggle) {
        zoomToggle.addEventListener('change', toggleZoom);
    }

    // Customize diagram
    const customizeForm = document.getElementById('customize-form');
    if (customizeForm) {
        customizeForm.addEventListener('submit', customizeDiagram);
    }
}

// Export the diagram as a PNG image
function exportDiagramAsPNG() {
    const svgElement = document.querySelector('.mermaid svg');
    if (!svgElement) {
        alert('No diagram found to export');
        return;
    }

    try {
        const canvas = document.createElement('canvas');
        const scale = 2; // Higher scale for better quality

        // Get SVG dimensions
        const bbox = svgElement.getBBox();
        const width = Math.ceil(bbox.width);
        const height = Math.ceil(bbox.height);

        // Set canvas dimensions
        canvas.width = width * scale;
        canvas.height = height * scale;

        // Get canvas context and set background
        const ctx = canvas.getContext('2d');
        ctx.fillStyle = 'white';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        // Convert SVG to data URL
        const svgData = new XMLSerializer().serializeToString(svgElement);
        const img = new Image();

        img.onload = function() {
            ctx.scale(scale, scale);
            ctx.drawImage(img, 0, 0, width, height);

            // Create download link
            const a = document.createElement('a');
            a.download = 'repository-diagram.png';
            a.href = canvas.toDataURL('image/png', 1.0);
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        };

        img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgData)));
    } catch (error) {
        console.error('Error exporting diagram:', error);
        alert('Failed to export diagram: ' + error.message);
    }
}

// Variables to track zoom state
let currentZoom = 1;
const zoomStep = 0.1;
const minZoom = 0.5;
const maxZoom = 3;
let isPanning = false;
let startX, startY, translateX = 0, translateY = 0;

// Toggle zoom functionality
function toggleZoom(event) {
    const diagramContainer = document.getElementById('diagram-container');
    if (!diagramContainer) return;

    if (event.target.checked) {
        diagramContainer.classList.add('zoomable');
        enablePanZoom();

        // Add zoom controls if they don't exist
        if (!document.getElementById('zoom-controls')) {
            addZoomControls();
        }
    } else {
        diagramContainer.classList.remove('zoomable');
        disablePanZoom();

        // Remove zoom controls
        const zoomControls = document.getElementById('zoom-controls');
        if (zoomControls) {
            zoomControls.remove();
        }

        // Reset zoom
        resetZoom();
    }
}

// Add zoom control buttons
function addZoomControls() {
    const controlsDiv = document.createElement('div');
    controlsDiv.id = 'zoom-controls';
    controlsDiv.className = 'zoom-controls';

    // Zoom in button
    const zoomInBtn = document.createElement('button');
    zoomInBtn.innerHTML = '+';
    zoomInBtn.title = 'Zoom In';
    zoomInBtn.onclick = zoomIn;

    // Zoom out button
    const zoomOutBtn = document.createElement('button');
    zoomOutBtn.innerHTML = '-';
    zoomOutBtn.title = 'Zoom Out';
    zoomOutBtn.onclick = zoomOut;

    // Reset zoom button
    const resetBtn = document.createElement('button');
    resetBtn.innerHTML = '↺';
    resetBtn.title = 'Reset Zoom';
    resetBtn.onclick = resetZoom;

    // Add buttons to controls div
    controlsDiv.appendChild(zoomInBtn);
    controlsDiv.appendChild(zoomOutBtn);
    controlsDiv.appendChild(resetBtn);

    // Add controls to the page
    const diagramContainer = document.getElementById('diagram-container');
    diagramContainer.appendChild(controlsDiv);
}

// Zoom in function
function zoomIn() {
    if (currentZoom < maxZoom) {
        currentZoom += zoomStep;
        applyZoom();
    }
}

// Zoom out function
function zoomOut() {
    if (currentZoom > minZoom) {
        currentZoom -= zoomStep;
        applyZoom();
    }
}

// Reset zoom function
function resetZoom() {
    currentZoom = 1;
    translateX = 0;
    translateY = 0;
    applyZoom();
}

// Apply zoom and translation to the SVG
function applyZoom() {
    const svgElement = document.querySelector('.mermaid svg');
    if (!svgElement) return;

    svgElement.style.transform = `translate(${translateX}px, ${translateY}px) scale(${currentZoom})`;
    svgElement.style.transformOrigin = 'center';
}

// Enable pan and zoom functionality
function enablePanZoom() {
    const svgElement = document.querySelector('.mermaid svg');
    if (!svgElement) return;

    // Set cursor style
    svgElement.style.cursor = 'move';

    // Add event listeners for panning
    svgElement.addEventListener('mousedown', startPan);
    document.addEventListener('mousemove', pan);
    document.addEventListener('mouseup', endPan);

    // Add event listener for mouse wheel zoom
    svgElement.addEventListener('wheel', handleWheel);

    console.log('Pan and zoom enabled');
}

// Start panning
function startPan(e) {
    isPanning = true;
    startX = e.clientX - translateX;
    startY = e.clientY - translateY;
}

// Pan the diagram
function pan(e) {
    if (!isPanning) return;

    translateX = e.clientX - startX;
    translateY = e.clientY - startY;
    applyZoom();
}

// End panning
function endPan() {
    isPanning = false;
}

// Handle mouse wheel for zooming
function handleWheel(e) {
    e.preventDefault();

    if (e.deltaY < 0) {
        // Zoom in
        zoomIn();
    } else {
        // Zoom out
        zoomOut();
    }
}

// Disable pan and zoom functionality
function disablePanZoom() {
    const svgElement = document.querySelector('.mermaid svg');
    if (!svgElement) return;

    // Reset cursor style
    svgElement.style.cursor = 'default';

    // Remove transform
    svgElement.style.transform = '';

    // Remove event listeners for panning
    svgElement.removeEventListener('mousedown', startPan);
    document.removeEventListener('mousemove', pan);
    document.removeEventListener('mouseup', endPan);

    // Remove event listener for mouse wheel zoom
    svgElement.removeEventListener('wheel', handleWheel);

    console.log('Pan and zoom disabled');
}

// Customize the diagram based on form input
function customizeDiagram(event) {
    event.preventDefault();

    const formData = new FormData(event.target);
    const customizations = {
        theme: formData.get('theme'),
        direction: formData.get('direction')
    };

    // Apply customizations
    mermaid.initialize({
        theme: customizations.theme
    });

    // Update diagram direction
    const diagramCode = document.getElementById('mermaid-code').textContent;
    const updatedCode = diagramCode.replace(
        /graph (TD|LR|RL|BT)/,
        `graph ${customizations.direction}`
    );

    // Re-render the diagram
    const diagramContainer = document.getElementById('diagram-container');
    diagramContainer.innerHTML = `<div class="mermaid">${updatedCode}</div>`;

    // Re-initialize Mermaid
    mermaid.init(undefined, '.mermaid');
}
