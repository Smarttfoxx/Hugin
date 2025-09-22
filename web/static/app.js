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
        scanOutput.textContent += '\n--- Starting scan ---\n';
        
        // Make API call to start scan
        fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(params)
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                scanOutput.textContent += 'Scan started successfully!\n';
                scanOutput.textContent += 'Monitoring progress...\n\n';
                
                // Start polling for results
                pollScanStatus();
            } else {
                scanOutput.textContent += `Error: ${data.message}\n`;
            }
        })
        .catch(error => {
            console.error('Error starting scan:', error);
            scanOutput.textContent += `Error: Failed to start scan - ${error.message}\n`;
        });
    }
    
    function pollScanStatus() {
        const pollInterval = setInterval(() => {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    if (!data.scanning) {
                        clearInterval(pollInterval);
                        scanOutput.textContent += 'Scan completed!\n';
                        scanOutput.textContent += 'Loading results...\n\n';
                        loadResults();
                    } else {
                        scanOutput.textContent += '.';
                    }
                })
                .catch(error => {
                    console.error('Error polling status:', error);
                    clearInterval(pollInterval);
                    scanOutput.textContent += `\nError polling status: ${error.message}\n`;
                });
        }, 1000);
    }
    
    function loadResults() {
        fetch('/api/results')
            .then(response => response.json())
            .then(data => {
                scanOutput.textContent += '=== SCAN RESULTS ===\n\n';
                
                if (data.results && data.results.length > 0) {
                    data.results.forEach(result => {
                        scanOutput.textContent += `Target: ${result.target}\n`;
                        scanOutput.textContent += `Status: ${result.status}\n`;
                        scanOutput.textContent += `Timestamp: ${result.timestamp}\n`;
                        
                        if (result.openPorts && result.openPorts.length > 0) {
                            scanOutput.textContent += `Open Ports:\n`;
                            result.openPorts.forEach(port => {
                                scanOutput.textContent += `  - ${port}\n`;
                            });
                        } else {
                            scanOutput.textContent += 'No open ports found.\n';
                        }
                        scanOutput.textContent += '\n';
                    });
                } else {
                    scanOutput.textContent += 'No results available.\n';
                }
            })
            .catch(error => {
                console.error('Error loading results:', error);
                scanOutput.textContent += `Error loading results: ${error.message}\n`;
            });
    }
});
