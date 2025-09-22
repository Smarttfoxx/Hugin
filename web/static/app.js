document.addEventListener('DOMContentLoaded', function() {
    const scanForm = document.getElementById('scanForm');
    const resultsSection = document.getElementById('results');
    const scanOutput = document.getElementById('scanOutput');
    
    scanForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const target = document.getElementById('target').value;
        const ports = document.getElementById('ports').value;
        const serviceDetection = document.getElementById('serviceDetection').checked;
        
        if (!target) {
            alert('Please enter a target IP or range');
            return;
        }
        
        // Show results section
        resultsSection.style.display = 'block';
        scanOutput.textContent = 'Starting scan...\n';
        
        // Build scan parameters
        const scanParams = {
            target: target,
            ports: ports || '1-1000',
            serviceDetection: serviceDetection
        };
        
        // Start scan via API
        startScan(scanParams);
    });
    
    function startScan(params) {
        scanOutput.textContent = 'Initializing Hugin scanner...\n';
        scanOutput.textContent += `Target: ${params.target}\n`;
        scanOutput.textContent += `Ports: ${params.ports}\n`;
        scanOutput.textContent += `Service Detection: ${params.serviceDetection ? 'Enabled' : 'Disabled'}\n`;
        scanOutput.textContent += '\n--- Scan Results ---\n';
        
        // Simulate scan progress (in real implementation, this would connect to the backend)
        setTimeout(() => {
            scanOutput.textContent += 'Scan completed. Connect to backend API for real results.\n';
        }, 2000);
    }
});
