/*
* GNU GENERAL PUBLIC LICENSE
* Version 3, 29 June 2007
* Copyright (C) 2025 Smarttfoxx
*/

#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <map>
#include <vector>
#include <functional>
#include <sstream>
#include <fstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <signal.h>

class WebServer {
private:
    int port;
    bool enableSSL;
    std::atomic<bool> running{false};
    int serverSocket;
    std::thread serverThread;
    
    // HTTP request/response handling
    struct HttpRequest {
        std::string method;
        std::string path;
        std::string query;
        std::map<std::string, std::string> headers;
        std::string body;
    };
    
    struct HttpResponse {
        int statusCode = 200;
        std::string statusText = "OK";
        std::map<std::string, std::string> headers;
        std::string body;
    };
    
    // Route handlers
    std::map<std::string, std::function<HttpResponse(const HttpRequest&)>> routes;
    
    // Helper methods
    HttpRequest parseRequest(const std::string& rawRequest);
    std::string buildResponse(const HttpResponse& response);
    std::string getContentType(const std::string& path);
    std::string readFile(const std::string& path);
    void handleClient(int clientSocket);
    void serverLoop();
    
    // Route handlers
    HttpResponse handleIndex(const HttpRequest& request);
    HttpResponse handleScan(const HttpRequest& request);
    HttpResponse handleResults(const HttpRequest& request);
    HttpResponse handleStatus(const HttpRequest& request);
    HttpResponse handleStatic(const HttpRequest& request);
    
public:
    WebServer(int port, bool enableSSL = false);
    ~WebServer();
    
    bool start();
    void stop();
    bool isRunning() const { return running; }
    
    // Scan management
    struct ScanResult {
        std::string target;
        std::vector<std::string> openPorts;
        std::string status;
        std::string timestamp;
    };
    
    static std::vector<ScanResult> scanResults;
    static std::atomic<bool> scanInProgress;
    static std::string currentScanTarget;
};
