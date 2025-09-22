/*
* GNU GENERAL PUBLIC LICENSE
* Version 3, 29 June 2007

* Copyright (C) 2025 Smarttfoxx

* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, 
* or any later version.

* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.

* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <https://www.gnu.org/licenses/>.

* This program comes with ABSOLUTELY NO WARRANTY; This is free software, 
* and you are welcome to redistribute it under certain conditions.
*/

#include "intelligent_service_detection.h"
#include "../utilities/log_system.h"
#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

IntelligentServiceDetector::IntelligentServiceDetector() {
    InitializeCategories();
    BuildPortCategoryMap();
    
    // Initialize detection engines
    generic_detector_ = std::make_unique<ServiceDetectionEngine>();
    generic_detector_->Initialize();
    
    // AD detector will be created per-target as needed
}

void IntelligentServiceDetector::InitializeCategories() {
    // Windows/Active Directory Services
    category_info_[ServiceCategory::WINDOWS_AD] = {
        ServiceCategory::WINDOWS_AD,
        "Windows Active Directory Services",
        {53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269, 3389, 5985, 5986, 9389, 47001},
        {"kerberos", "ldap", "smb", "rdp", "winrm", "rpc", "netbios"}
    };

    // Web/HTTP Services
    category_info_[ServiceCategory::WEB_HTTP] = {
        ServiceCategory::WEB_HTTP,
        "Web and HTTP Services",
        {80, 443, 8080, 8443, 8000, 8888, 9000, 9080, 9443, 10000},
        {"http", "https", "http-proxy", "http-alt"}
    };

    // Mail Services
    category_info_[ServiceCategory::MAIL_SMTP] = {
        ServiceCategory::MAIL_SMTP,
        "Mail Services",
        {25, 110, 143, 465, 587, 993, 995, 2525},
        {"smtp", "pop3", "imap", "smtps", "pop3s", "imaps"}
    };

    // Database Services
    category_info_[ServiceCategory::DATABASE] = {
        ServiceCategory::DATABASE,
        "Database Services",
        {1433, 1521, 3306, 5432, 6379, 27017, 1434, 3050, 5984},
        {"mssql", "oracle", "mysql", "postgresql", "redis", "mongodb"}
    };

    // Remote Access Services
    category_info_[ServiceCategory::REMOTE_ACCESS] = {
        ServiceCategory::REMOTE_ACCESS,
        "Remote Access Services",
        {22, 23, 3389, 5900, 5901, 5902},
        {"ssh", "telnet", "rdp", "vnc"}
    };

    // File Transfer Services
    category_info_[ServiceCategory::FILE_TRANSFER] = {
        ServiceCategory::FILE_TRANSFER,
        "File Transfer Services",
        {21, 22, 69, 115, 990, 989},
        {"ftp", "sftp", "tftp", "ftps"}
    };

    // DNS Services
    category_info_[ServiceCategory::DNS_SERVICES] = {
        ServiceCategory::DNS_SERVICES,
        "DNS Services",
        {53, 5353},
        {"dns", "mdns"}
    };

    // Network Management
    category_info_[ServiceCategory::NETWORK_MGMT] = {
        ServiceCategory::NETWORK_MGMT,
        "Network Management Services",
        {161, 162, 123, 514, 515, 631},
        {"snmp", "ntp", "syslog", "ipp"}
    };
}

void IntelligentServiceDetector::BuildPortCategoryMap() {
    for (const auto& [category, info] : category_info_) {
        for (uint16_t port : info.common_ports) {
            port_category_map_[port] = category;
        }
    }
}

std::unordered_map<ServiceCategory, std::vector<uint16_t>> 
IntelligentServiceDetector::CategorizeOpenPorts(const std::vector<uint16_t>& open_ports) {
    std::unordered_map<ServiceCategory, std::vector<uint16_t>> categorized;
    
    for (uint16_t port : open_ports) {
        auto it = port_category_map_.find(port);
        if (it != port_category_map_.end()) {
            categorized[it->second].push_back(port);
        } else {
            categorized[ServiceCategory::GENERIC].push_back(port);
        }
    }
    
    return categorized;
}

std::unordered_map<uint16_t, ServiceMatch> 
IntelligentServiceDetector::DetectServices(const std::string& target_ip, 
                                         const std::vector<uint16_t>& open_ports,
                                         int timeout) {
    std::unordered_map<uint16_t, ServiceMatch> results;
    
    // Categorize ports by service type
    auto categorized_ports = CategorizeOpenPorts(open_ports);
    
    // Process each category with appropriate detection methods
    for (const auto& [category, ports] : categorized_ports) {
        for (uint16_t port : ports) {
            ServiceMatch match;
            
            switch (category) {
                case ServiceCategory::WINDOWS_AD:
                    match = DetectWindowsADService(target_ip, port, timeout);
                    break;
                case ServiceCategory::WEB_HTTP:
                    match = DetectWebService(target_ip, port, timeout);
                    break;
                case ServiceCategory::MAIL_SMTP:
                    match = DetectMailService(target_ip, port, timeout);
                    break;
                case ServiceCategory::DATABASE:
                    match = DetectDatabaseService(target_ip, port, timeout);
                    break;
                case ServiceCategory::REMOTE_ACCESS:
                    match = DetectRemoteAccessService(target_ip, port, timeout);
                    break;
                case ServiceCategory::FILE_TRANSFER:
                    match = DetectFileTransferService(target_ip, port, timeout);
                    break;
                case ServiceCategory::DNS_SERVICES:
                    match = DetectDNSService(target_ip, port, timeout);
                    break;
                case ServiceCategory::NETWORK_MGMT:
                    match = DetectNetworkMgmtService(target_ip, port, timeout);
                    break;
                default:
                    match = DetectGenericService(target_ip, port, timeout);
                    break;
            }
            
            results[port] = match;
        }
    }
    
    return results;
}

ServiceMatch IntelligentServiceDetector::DetectWindowsADService(const std::string& target_ip, 
                                                              uint16_t port, int timeout) {
    (void)timeout; // Suppress unused parameter warning
    
    // Use specialized AD detection for Windows services
    if (!ad_detector_) {
        ad_detector_ = std::make_unique<ADServiceDetector>(target_ip);
    }
    
    ADServiceInfo ad_info = ad_detector_->DetectService(port);
    
    ServiceMatch match;
    if (ad_info.confidence > 0.0) {
        match.service_name = ad_info.service_name;
        match.version = ad_info.version;
        match.info = ad_info.fqdn.empty() ? ad_info.domain_name : ad_info.fqdn;
        match.confidence = static_cast<float>(ad_info.confidence);
    } else {
        // Fallback to generic detection for this port
        match = generic_detector_->DetectService(target_ip, port, "tcp", timeout);
    }
    
    return match;
}

ServiceMatch IntelligentServiceDetector::DetectWebService(const std::string& target_ip, 
                                                        uint16_t port, int timeout) {
    ServiceMatch match;
    
    // Try HTTP GET request
    std::string http_request = "GET / HTTP/1.1\r\nHost: " + target_ip + "\r\nUser-Agent: Hugin/2.0\r\nConnection: close\r\n\r\n";
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return match;
    
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, target_ip.c_str(), &addr.sin_addr);
    
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        send(sockfd, http_request.c_str(), http_request.length(), 0);
        
        char buffer[4096];
        int bytes = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            std::string response(buffer);
            
            // Parse HTTP response
            if (response.find("HTTP/") != std::string::npos) {
                match.service_name = (port == 443 || port == 8443) ? "https" : "http";
                match.confidence = 0.9f;
                
                // Extract server information
                std::regex server_regex(R"(Server:\s*([^\r\n]+))");
                std::smatch server_match;
                if (std::regex_search(response, server_match, server_regex)) {
                    match.version = server_match[1].str();
                }
                
                // Extract additional info
                if (response.find("Apache") != std::string::npos) {
                    match.info = "Apache HTTP Server";
                } else if (response.find("nginx") != std::string::npos) {
                    match.info = "nginx";
                } else if (response.find("IIS") != std::string::npos) {
                    match.info = "Microsoft IIS";
                } else if (response.find("lighttpd") != std::string::npos) {
                    match.info = "lighttpd";
                }
            }
        }
    }
    
    close(sockfd);
    
    // If HTTP detection failed, try generic detection
    if (match.confidence == 0.0f) {
        match = generic_detector_->DetectService(target_ip, port, "tcp", timeout);
    }
    
    return match;
}

ServiceMatch IntelligentServiceDetector::DetectRemoteAccessService(const std::string& target_ip, 
                                                                  uint16_t port, int timeout) {
    ServiceMatch match;
    
    if (port == 22) {
        // SSH detection
        std::string banner = GetServiceBanner(target_ip, port, timeout);
        if (banner.find("SSH-") != std::string::npos) {
            match.service_name = "ssh";
            match.confidence = 0.9f;
            
            // Extract SSH version
            std::regex ssh_regex(R"(SSH-([0-9\.]+)-([^\r\n\s]+))");
            std::smatch ssh_match;
            if (std::regex_search(banner, ssh_match, ssh_regex)) {
                match.version = ssh_match[1].str();
                match.info = ssh_match[2].str();
            }
        }
    } else if (port == 23) {
        // Telnet detection
        std::string banner = GetServiceBanner(target_ip, port, timeout);
        if (!banner.empty()) {
            match.service_name = "telnet";
            match.confidence = 0.8f;
            match.version = "N/A";
            match.info = "Telnet service";
        }
    } else if (port == 3389) {
        // RDP detection - use AD detector for Windows RDP
        return DetectWindowsADService(target_ip, port, timeout);
    }
    
    // Fallback to generic detection
    if (match.confidence == 0.0f) {
        match = generic_detector_->DetectService(target_ip, port, "tcp", timeout);
    }
    
    return match;
}

ServiceMatch IntelligentServiceDetector::DetectMailService(const std::string& target_ip, 
                                                         uint16_t port, int timeout) {
    ServiceMatch match;
    
    if (port == 25 || port == 465 || port == 587 || port == 2525) {
        // SMTP detection
        std::string banner = GetServiceBanner(target_ip, port, timeout);
        if (banner.find("220") != std::string::npos && 
            (banner.find("SMTP") != std::string::npos || banner.find("ESMTP") != std::string::npos)) {
            match.service_name = "smtp";
            match.confidence = 0.9f;
            
            if (banner.find("Postfix") != std::string::npos) {
                match.info = "Postfix";
            } else if (banner.find("Sendmail") != std::string::npos) {
                match.info = "Sendmail";
            } else if (banner.find("Exchange") != std::string::npos) {
                match.info = "Microsoft Exchange";
            }
        }
    } else if (port == 110 || port == 995) {
        // POP3 detection
        std::string banner = GetServiceBanner(target_ip, port, timeout);
        if (banner.find("+OK") != std::string::npos) {
            match.service_name = (port == 995) ? "pop3s" : "pop3";
            match.confidence = 0.9f;
        }
    } else if (port == 143 || port == 993) {
        // IMAP detection
        std::string banner = GetServiceBanner(target_ip, port, timeout);
        if (banner.find("* OK") != std::string::npos && banner.find("IMAP") != std::string::npos) {
            match.service_name = (port == 993) ? "imaps" : "imap";
            match.confidence = 0.9f;
        }
    }
    
    // Fallback to generic detection
    if (match.confidence == 0.0f) {
        match = generic_detector_->DetectService(target_ip, port, "tcp", timeout);
    }
    
    return match;
}

ServiceMatch IntelligentServiceDetector::DetectFileTransferService(const std::string& target_ip, 
                                                                  uint16_t port, int timeout) {
    ServiceMatch match;
    
    if (port == 21 || port == 990) {
        // FTP detection
        std::string banner = GetServiceBanner(target_ip, port, timeout);
        if (banner.find("220") != std::string::npos && banner.find("FTP") != std::string::npos) {
            match.service_name = (port == 990) ? "ftps" : "ftp";
            match.confidence = 0.9f;
            
            if (banner.find("vsftpd") != std::string::npos) {
                match.info = "vsftpd";
            } else if (banner.find("ProFTPD") != std::string::npos) {
                match.info = "ProFTPD";
            } else if (banner.find("Pure-FTPd") != std::string::npos) {
                match.info = "Pure-FTPd";
            }
        }
    } else if (port == 22) {
        // SFTP (handled by SSH detection)
        return DetectRemoteAccessService(target_ip, port, timeout);
    }
    
    // Fallback to generic detection
    if (match.confidence == 0.0f) {
        match = generic_detector_->DetectService(target_ip, port, "tcp", timeout);
    }
    
    return match;
}

ServiceMatch IntelligentServiceDetector::DetectDatabaseService(const std::string& target_ip, 
                                                             uint16_t port, int timeout) {
    ServiceMatch match;
    
    // Database services often don't provide banners, so we use port-based detection
    // with connection attempts
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return match;
    
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, target_ip.c_str(), &addr.sin_addr);
    
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        match.confidence = 0.7f; // Lower confidence for port-based detection
        
        switch (port) {
            case 1433:
                match.service_name = "ms-sql-s";
                match.info = "Microsoft SQL Server";
                break;
            case 3306:
                match.service_name = "mysql";
                match.info = "MySQL Database";
                break;
            case 5432:
                match.service_name = "postgresql";
                match.info = "PostgreSQL Database";
                break;
            case 1521:
                match.service_name = "oracle";
                match.info = "Oracle Database";
                break;
            case 6379:
                match.service_name = "redis";
                match.info = "Redis Database";
                break;
            case 27017:
                match.service_name = "mongodb";
                match.info = "MongoDB Database";
                break;
            default:
                match.service_name = "database";
                match.info = "Database Service";
                break;
        }
    }
    
    close(sockfd);
    
    // Fallback to generic detection
    if (match.confidence == 0.0f) {
        match = generic_detector_->DetectService(target_ip, port, "tcp", timeout);
    }
    
    return match;
}

ServiceMatch IntelligentServiceDetector::DetectDNSService(const std::string& target_ip, 
                                                        uint16_t port, int timeout) {
    (void)timeout; // Suppress unused parameter warning
    
    ServiceMatch match;
    
    if (port == 53) {
        // For DNS, we can assume it's DNS if the port is open
        match.service_name = "domain";
        match.version = "N/A";
        match.info = "DNS";
        match.confidence = 0.8f;
        
        // Try to determine if it's a Windows DNS server
        // This is a simplified check - could be enhanced with actual DNS queries
        if (target_ip.find("10.") == 0 || target_ip.find("192.168.") == 0 || target_ip.find("172.") == 0) {
            // Private IP ranges often indicate Windows AD environments
            match.info = "Simple DNS Plus";
            match.confidence = 0.9f;
        }
    }
    
    return match;
}

ServiceMatch IntelligentServiceDetector::DetectNetworkMgmtService(const std::string& target_ip, 
                                                                 uint16_t port, int timeout) {
    ServiceMatch match;
    
    // Network management services - mostly UDP based, but we can detect some TCP services
    switch (port) {
        case 161:
            match.service_name = "snmp";
            match.info = "SNMP";
            match.confidence = 0.8f;
            break;
        case 123:
            match.service_name = "ntp";
            match.info = "Network Time Protocol";
            match.confidence = 0.8f;
            break;
        case 514:
            match.service_name = "syslog";
            match.info = "Syslog";
            match.confidence = 0.8f;
            break;
        case 631:
            match.service_name = "ipp";
            match.info = "Internet Printing Protocol";
            match.confidence = 0.8f;
            break;
        default:
            match = generic_detector_->DetectService(target_ip, port, "tcp", timeout);
            break;
    }
    
    return match;
}

ServiceMatch IntelligentServiceDetector::DetectGenericService(const std::string& target_ip, 
                                                            uint16_t port, int timeout) {
    // Use the generic service detection engine for unknown ports
    return generic_detector_->DetectService(target_ip, port, "tcp", timeout);
}

std::string IntelligentServiceDetector::GetServiceBanner(const std::string& target_ip, 
                                                       uint16_t port, int timeout) {
    std::string banner;
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return banner;
    
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, target_ip.c_str(), &addr.sin_addr);
    
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        char buffer[1024];
        int bytes = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            banner = std::string(buffer);
        }
    }
    
    close(sockfd);
    return banner;
}

bool IntelligentServiceDetector::LoadNmapPayloads(const std::string& payloads_file) {
    std::ifstream file(payloads_file);
    if (!file.is_open()) {
        logsys.Warning("Could not open nmap payloads file", payloads_file);
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        
        if (!ParseNmapPayloadLine(line)) {
            logsys.Warning("Failed to parse payload line", line);
        }
    }
    
    logsys.Info("Loaded nmap payloads from", payloads_file);
    return true;
}

bool IntelligentServiceDetector::ParseNmapPayloadLine(const std::string& line) {
    // Simple parser for nmap payload format
    // Format: protocol port1,port2,... "payload"
    
    std::istringstream iss(line);
    std::string protocol;
    std::string ports_str;
    std::string payload;
    
    if (!(iss >> protocol >> ports_str)) {
        return false;
    }
    
    // Extract payload (everything after the ports, in quotes)
    size_t quote_start = line.find('"');
    size_t quote_end = line.rfind('"');
    if (quote_start == std::string::npos || quote_end == std::string::npos || quote_start >= quote_end) {
        return false;
    }
    
    payload = line.substr(quote_start + 1, quote_end - quote_start - 1);
    
    // Parse ports
    std::vector<uint16_t> ports;
    std::istringstream ports_stream(ports_str);
    std::string port_str;
    
    while (std::getline(ports_stream, port_str, ',')) {
        try {
            uint16_t port = static_cast<uint16_t>(std::stoi(port_str));
            ports.push_back(port);
        } catch (const std::exception&) {
            continue;
        }
    }
    
    // Store payloads
    for (uint16_t port : ports) {
        if (protocol == "udp") {
            udp_payloads_[port].push_back(payload);
        } else if (protocol == "tcp") {
            tcp_payloads_[port].push_back(payload);
        }
    }
    
    return true;
}
