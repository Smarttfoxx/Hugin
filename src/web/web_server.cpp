/*
* GNU GENERAL PUBLIC LICENSE
* Version 3, 29 June 2007
* Copyright (C) 2025 Smarttfoxx
*/

#include "web_server.h"
#include "../utilities/log_system.h"
#include <iostream>
#include <chrono>
#include <iomanip>

// Static members
std::vector<WebServer::ScanResult> WebServer::scanResults;
std::atomic<bool> WebServer::scanInProgress{false};
std::string WebServer::currentScanTarget;

WebServer::WebServer(int port, bool enableSSL) : port(port), enableSSL(enableSSL) {
    // Setup routes
    routes["/"] = [this](const HttpRequest& req) { return handleIndex(req); };
    routes["/index.html"] = [this](const HttpRequest& req) { return handleIndex(req); };
    routes["/api/scan"] = [this](const HttpRequest& req) { return handleScan(req); };
    routes["/api/results"] = [this](const HttpRequest& req) { return handleResults(req); };
    routes["/api/status"] = [this](const HttpRequest& req) { return handleStatus(req); };
    
    // Static file handler (catch-all)
    routes["*"] = [this](const HttpRequest& req) { return handleStatic(req); };
}

WebServer::~WebServer() {
    stop();
}

bool WebServer::start() {
    // Create socket
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        logsys.Error("Failed to create socket");
        return false;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        logsys.Warning("Failed to set socket options");
    }
    
    // Bind socket
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    if (bind(serverSocket, (struct sockaddr*)&address, sizeof(address)) < 0) {
        logsys.Error("Failed to bind socket to port", port);
        close(serverSocket);
        return false;
    }
    
    // Listen for connections
    if (listen(serverSocket, 10) < 0) {
        logsys.Error("Failed to listen on socket");
        close(serverSocket);
        return false;
    }
    
    running = true;
    serverThread = std::thread(&WebServer::serverLoop, this);
    
    logsys.Info("Web server started successfully");
    logsys.Info("Listening on", enableSSL ? "https" : "http", "://localhost:" + std::to_string(port));
    
    return true;
}

void WebServer::stop() {
    if (running) {
        running = false;
        close(serverSocket);
        if (serverThread.joinable()) {
            serverThread.join();
        }
        logsys.Info("Web server stopped");
    }
}

void WebServer::serverLoop() {
    while (running) {
        struct sockaddr_in clientAddress;
        socklen_t clientLen = sizeof(clientAddress);
        
        int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddress, &clientLen);
        if (clientSocket < 0) {
            if (running) {
                logsys.Warning("Failed to accept client connection");
            }
            continue;
        }
        
        // Handle client in separate thread for better performance
        std::thread clientThread(&WebServer::handleClient, this, clientSocket);
        clientThread.detach();
    }
}

void WebServer::handleClient(int clientSocket) {
    char buffer[4096];
    ssize_t bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    
    if (bytesRead <= 0) {
        close(clientSocket);
        return;
    }
    
    buffer[bytesRead] = '\0';
    std::string rawRequest(buffer);
    
    // Parse request
    HttpRequest request = parseRequest(rawRequest);
    
    // Find matching route
    HttpResponse response;
    auto routeIt = routes.find(request.path);
    if (routeIt != routes.end()) {
        response = routeIt->second(request);
    } else {
        // Try static file handler
        response = handleStatic(request);
    }
    
    // Send response
    std::string responseStr = buildResponse(response);
    send(clientSocket, responseStr.c_str(), responseStr.length(), 0);
    
    close(clientSocket);
}

WebServer::HttpRequest WebServer::parseRequest(const std::string& rawRequest) {
    HttpRequest request;
    std::istringstream stream(rawRequest);
    std::string line;
    
    // Parse request line
    if (std::getline(stream, line)) {
        std::istringstream requestLine(line);
        requestLine >> request.method >> request.path;
        
        // Extract query parameters
        size_t queryPos = request.path.find('?');
        if (queryPos != std::string::npos) {
            request.query = request.path.substr(queryPos + 1);
            request.path = request.path.substr(0, queryPos);
        }
    }
    
    // Parse headers
    while (std::getline(stream, line) && line != "\r") {
        size_t colonPos = line.find(':');
        if (colonPos != std::string::npos) {
            std::string key = line.substr(0, colonPos);
            std::string value = line.substr(colonPos + 2);
            if (!value.empty() && value.back() == '\r') {
                value.pop_back();
            }
            request.headers[key] = value;
        }
    }
    
    // Parse body (for POST requests)
    std::string body;
    while (std::getline(stream, line)) {
        body += line + "\n";
    }
    request.body = body;
    
    return request;
}

std::string WebServer::buildResponse(const HttpResponse& response) {
    std::ostringstream responseStream;
    
    // Status line
    responseStream << "HTTP/1.1 " << response.statusCode << " " << response.statusText << "\r\n";
    
    // Headers
    for (const auto& header : response.headers) {
        responseStream << header.first << ": " << header.second << "\r\n";
    }
    
    // Content-Length
    responseStream << "Content-Length: " << response.body.length() << "\r\n";
    responseStream << "Connection: close\r\n";
    responseStream << "\r\n";
    
    // Body
    responseStream << response.body;
    
    return responseStream.str();
}

std::string WebServer::getContentType(const std::string& path) {
    auto endsWith = [](const std::string& str, const std::string& suffix) {
        return str.size() >= suffix.size() && 
               str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
    };
    
    if (endsWith(path, ".html")) return "text/html";
    if (endsWith(path, ".css")) return "text/css";
    if (endsWith(path, ".js")) return "application/javascript";
    if (endsWith(path, ".json")) return "application/json";
    if (endsWith(path, ".png")) return "image/png";
    if (endsWith(path, ".jpg") || endsWith(path, ".jpeg")) return "image/jpeg";
    if (endsWith(path, ".ico")) return "image/x-icon";
    return "text/plain";
}

std::string WebServer::readFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return "";
    }
    
    std::ostringstream content;
    content << file.rdbuf();
    return content.str();
}

WebServer::HttpResponse WebServer::handleIndex(const HttpRequest& request) {
    (void)request; // Suppress unused parameter warning
    
    HttpResponse response;
    response.headers["Content-Type"] = "text/html";
    
    std::string indexPath = "/usr/share/hugin/web/templates/index.html";
    std::string content = readFile(indexPath);
    
    if (content.empty()) {
        // Fallback to embedded HTML
        content = R"(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hugin Network Scanner</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .scan-form { background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input, select { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .results { margin-top: 20px; }
        .result-item { background: #e9ecef; padding: 15px; margin-bottom: 10px; border-radius: 5px; }
        .status { padding: 5px 10px; border-radius: 3px; color: white; }
        .status.running { background: #ffc107; color: black; }
        .status.completed { background: #28a745; }
        .status.error { background: #dc3545; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Hugin Network Scanner</h1>
            <p>Enterprise-Grade Network Security Scanner</p>
        </div>
        
        <div class="scan-form">
            <h3>Start New Scan</h3>
            <form id="scanForm">
                <div class="form-group">
                    <label for="target">Target IP/Host:</label>
                    <input type="text" id="target" name="target" placeholder="192.168.1.1 or example.com" required>
                </div>
                <div class="form-group">
                    <label for="ports">Ports:</label>
                    <select id="ports" name="ports">
                        <option value="top100">Top 100 Ports</option>
                        <option value="top1000">Top 1000 Ports</option>
                        <option value="all">All Ports (1-65535)</option>
                        <option value="custom">Custom Range</option>
                    </select>
                </div>
                <div class="form-group" id="customPorts" style="display:none;">
                    <label for="customRange">Custom Port Range:</label>
                    <input type="text" id="customRange" name="customRange" placeholder="22,80,443 or 1-1000">
                </div>
                <div class="form-group">
                    <label>
                        <input type="checkbox" id="serviceDetection" name="serviceDetection" checked>
                        Enable Service Detection
                    </label>
                </div>
                <button type="submit">Start Scan</button>
            </form>
        </div>
        
        <div class="results">
            <h3>Scan Results</h3>
            <div id="scanStatus"></div>
            <div id="resultsList"></div>
        </div>
    </div>
    
    <script>
        document.getElementById('ports').addEventListener('change', function() {
            const customPorts = document.getElementById('customPorts');
            customPorts.style.display = this.value === 'custom' ? 'block' : 'none';
        });
        
        document.getElementById('scanForm').addEventListener('submit', function(e) {
            e.preventDefault();
            startScan();
        });
        
        function startScan() {
            const formData = new FormData(document.getElementById('scanForm'));
            const data = Object.fromEntries(formData);
            
            fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .then(data => {
                updateStatus(data);
                if (data.success) {
                    pollResults();
                }
            })
            .catch(error => {
                console.error('Error:', error);
                updateStatus({success: false, message: 'Failed to start scan'});
            });
        }
        
        function updateStatus(data) {
            const statusDiv = document.getElementById('scanStatus');
            if (data.success) {
                statusDiv.innerHTML = '<div class="status running">Scan in progress...</div>';
            } else {
                statusDiv.innerHTML = '<div class="status error">Error: ' + data.message + '</div>';
            }
        }
        
        function pollResults() {
            const interval = setInterval(() => {
                fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    if (!data.scanning) {
                        clearInterval(interval);
                        loadResults();
                        document.getElementById('scanStatus').innerHTML = '<div class="status completed">Scan completed</div>';
                    }
                });
            }, 2000);
        }
        
        function loadResults() {
            fetch('/api/results')
            .then(response => response.json())
            .then(data => {
                const resultsList = document.getElementById('resultsList');
                resultsList.innerHTML = '';
                
                data.results.forEach(result => {
                    const resultDiv = document.createElement('div');
                    resultDiv.className = 'result-item';
                    resultDiv.innerHTML = `
                        <h4>${result.target}</h4>
                        <p><strong>Status:</strong> ${result.status}</p>
                        <p><strong>Time:</strong> ${result.timestamp}</p>
                        <p><strong>Open Ports:</strong> ${result.openPorts.join(', ') || 'None'}</p>
                    `;
                    resultsList.appendChild(resultDiv);
                });
            });
        }
        
        // Load initial results
        loadResults();
        
        // Auto-refresh every 30 seconds
        setInterval(loadResults, 30000);
    </script>
</body>
</html>)";
    }
    
    response.body = content;
    return response;
}

WebServer::HttpResponse WebServer::handleScan(const HttpRequest& request) {
    HttpResponse response;
    response.headers["Content-Type"] = "application/json";
    
    if (request.method != "POST") {
        response.statusCode = 405;
        response.statusText = "Method Not Allowed";
        response.body = R"({"success": false, "message": "Method not allowed"})";
        return response;
    }
    
    if (scanInProgress) {
        response.body = R"({"success": false, "message": "Scan already in progress"})";
        return response;
    }
    
    // Parse JSON body (simplified)
    std::string target = "127.0.0.1"; // Default target
    
    // Extract target from JSON body (basic parsing)
    size_t targetPos = request.body.find("\"target\":");
    if (targetPos != std::string::npos) {
        size_t startQuote = request.body.find("\"", targetPos + 9);
        size_t endQuote = request.body.find("\"", startQuote + 1);
        if (startQuote != std::string::npos && endQuote != std::string::npos) {
            target = request.body.substr(startQuote + 1, endQuote - startQuote - 1);
        }
    }
    
    currentScanTarget = target;
    scanInProgress = true;
    
    // Start scan in background thread
    std::thread scanThread([target]() {
        // Simulate scan (in real implementation, call actual scan functions)
        std::this_thread::sleep_for(std::chrono::seconds(3));
        
        ScanResult result;
        result.target = target;
        result.status = "Completed";
        result.openPorts = {"22/tcp (ssh)", "80/tcp (http)", "443/tcp (https)"};
        
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::ostringstream timeStream;
        timeStream << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        result.timestamp = timeStream.str();
        
        scanResults.push_back(result);
        scanInProgress = false;
    });
    scanThread.detach();
    
    response.body = R"({"success": true, "message": "Scan started successfully"})";
    return response;
}

WebServer::HttpResponse WebServer::handleResults(const HttpRequest& request) {
    (void)request; // Suppress unused parameter warning
    
    HttpResponse response;
    response.headers["Content-Type"] = "application/json";
    
    std::ostringstream json;
    json << R"({"results": [)";
    
    for (size_t i = 0; i < scanResults.size(); ++i) {
        if (i > 0) json << ",";
        const auto& result = scanResults[i];
        json << R"({"target": ")" << result.target << R"(",)";
        json << R"("status": ")" << result.status << R"(",)";
        json << R"("timestamp": ")" << result.timestamp << R"(",)";
        json << R"("openPorts": [)";
        for (size_t j = 0; j < result.openPorts.size(); ++j) {
            if (j > 0) json << ",";
            json << "\"" << result.openPorts[j] << "\"";
        }
        json << "]}";
    }
    
    json << "]}";
    response.body = json.str();
    return response;
}

WebServer::HttpResponse WebServer::handleStatus(const HttpRequest& request) {
    (void)request; // Suppress unused parameter warning
    
    HttpResponse response;
    response.headers["Content-Type"] = "application/json";
    
    std::ostringstream json;
    json << R"({"scanning": )" << (scanInProgress ? "true" : "false");
    if (scanInProgress) {
        json << R"(, "target": ")" << currentScanTarget << "\"";
    }
    json << "}";
    
    response.body = json.str();
    return response;
}

WebServer::HttpResponse WebServer::handleStatic(const HttpRequest& request) {
    HttpResponse response;
    
    std::string filePath = "/usr/share/hugin/web/static" + request.path;
    std::string content = readFile(filePath);
    
    if (content.empty()) {
        response.statusCode = 404;
        response.statusText = "Not Found";
        response.headers["Content-Type"] = "text/html";
        response.body = "<html><body><h1>404 Not Found</h1></body></html>";
    } else {
        response.headers["Content-Type"] = getContentType(request.path);
        response.body = content;
    }
    
    return response;
}
