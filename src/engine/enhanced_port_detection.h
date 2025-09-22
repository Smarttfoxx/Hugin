/*
* Enhanced Port Detection for Hugin
* Improved connectivity and timeout handling
*/

#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

class EnhancedPortDetector {
private:
    std::string target_ip_;
    int connect_timeout_;
    int read_timeout_;
    
public:
    EnhancedPortDetector(const std::string& target_ip, int connect_timeout = 3, int read_timeout = 2);
    
    // Enhanced port detection methods
    bool IsPortOpen(int port);
    bool IsPortOpenTCP(int port);
    bool IsPortOpenConnect(int port);  // TCP connect scan as fallback
    
    // Batch port detection
    std::vector<int> GetOpenPorts(const std::vector<int>& ports);
    std::vector<int> GetOpenPortsParallel(const std::vector<int>& ports, int max_threads = 50);
    
    // Configuration
    void SetConnectTimeout(int timeout_seconds);
    void SetReadTimeout(int timeout_seconds);
    
private:
    bool ConnectWithTimeout(int sockfd, const struct sockaddr* addr, socklen_t addrlen, int timeout);
    void SetSocketNonBlocking(int sockfd);
    void SetSocketBlocking(int sockfd);
};

// Enhanced SYN scan implementation
class EnhancedSYNScanner {
private:
    std::string target_ip_;
    int timeout_;
    
public:
    EnhancedSYNScanner(const std::string& target_ip, int timeout = 3);
    
    bool ScanPort(int port);
    std::vector<int> ScanPorts(const std::vector<int>& ports);
    
private:
    bool SendSYNPacket(int port);
    bool ReceiveSYNACK(int port, int timeout);
};
