/*
* Enhanced Port Detection for Hugin
* Improved connectivity and timeout handling
*/

#include "enhanced_port_detection.h"
#include <sys/select.h>
#include <thread>
#include <future>
#include <algorithm>

EnhancedPortDetector::EnhancedPortDetector(const std::string& target_ip, int connect_timeout, int read_timeout)
    : target_ip_(target_ip), connect_timeout_(connect_timeout), read_timeout_(read_timeout) {}

bool EnhancedPortDetector::IsPortOpen(int port) {
    // Try TCP connect first (more reliable)
    if (IsPortOpenConnect(port)) {
        return true;
    }
    
    // Fallback to regular TCP check
    return IsPortOpenTCP(port);
}

bool EnhancedPortDetector::IsPortOpenTCP(int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return false;
    }
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, target_ip_.c_str(), &server_addr.sin_addr) <= 0) {
        close(sockfd);
        return false;
    }
    
    // Set socket to non-blocking
    SetSocketNonBlocking(sockfd);
    
    // Attempt connection
    bool is_open = ConnectWithTimeout(sockfd, (struct sockaddr*)&server_addr, 
                                     sizeof(server_addr), connect_timeout_);
    
    close(sockfd);
    return is_open;
}

bool EnhancedPortDetector::IsPortOpenConnect(int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return false;
    }
    
    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = connect_timeout_;
    timeout.tv_usec = 0;
    
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, target_ip_.c_str(), &server_addr.sin_addr) <= 0) {
        close(sockfd);
        return false;
    }
    
    bool is_open = (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0);
    close(sockfd);
    
    return is_open;
}

std::vector<int> EnhancedPortDetector::GetOpenPorts(const std::vector<int>& ports) {
    std::vector<int> open_ports;
    
    for (int port : ports) {
        if (IsPortOpen(port)) {
            open_ports.push_back(port);
        }
    }
    
    return open_ports;
}

std::vector<int> EnhancedPortDetector::GetOpenPortsParallel(const std::vector<int>& ports, int max_threads) {
    std::vector<int> open_ports;
    std::vector<std::future<std::pair<int, bool>>> futures;
    
    // Launch async tasks
    for (int port : ports) {
        futures.push_back(std::async(std::launch::async, [this, port]() {
            return std::make_pair(port, IsPortOpen(port));
        }));
        
        // Limit concurrent threads
        if (futures.size() >= static_cast<size_t>(max_threads)) {
            // Wait for some to complete
            for (auto& future : futures) {
                auto result = future.get();
                if (result.second) {
                    open_ports.push_back(result.first);
                }
            }
            futures.clear();
        }
    }
    
    // Wait for remaining tasks
    for (auto& future : futures) {
        auto result = future.get();
        if (result.second) {
            open_ports.push_back(result.first);
        }
    }
    
    // Sort the results
    std::sort(open_ports.begin(), open_ports.end());
    
    return open_ports;
}

bool EnhancedPortDetector::ConnectWithTimeout(int sockfd, const struct sockaddr* addr, 
                                             socklen_t addrlen, int timeout) {
    int result = connect(sockfd, addr, addrlen);
    
    if (result == 0) {
        return true;  // Connected immediately
    }
    
    if (errno != EINPROGRESS) {
        return false;  // Connection failed
    }
    
    // Use select to wait for connection with timeout
    fd_set write_fds;
    FD_ZERO(&write_fds);
    FD_SET(sockfd, &write_fds);
    
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    
    result = select(sockfd + 1, nullptr, &write_fds, nullptr, &tv);
    
    if (result <= 0) {
        return false;  // Timeout or error
    }
    
    // Check if connection was successful
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        return false;
    }
    
    return (error == 0);
}

void EnhancedPortDetector::SetSocketNonBlocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
}

void EnhancedPortDetector::SetSocketBlocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags & ~O_NONBLOCK);
}

void EnhancedPortDetector::SetConnectTimeout(int timeout_seconds) {
    connect_timeout_ = timeout_seconds;
}

void EnhancedPortDetector::SetReadTimeout(int timeout_seconds) {
    read_timeout_ = timeout_seconds;
}
