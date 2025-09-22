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

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include "service_detection.h"
#include "ad_detection.h"

enum class ServiceCategory {
    WINDOWS_AD,      // Active Directory services (88, 389, 445, etc.)
    WEB_HTTP,        // Web services (80, 443, 8080, etc.)
    MAIL_SMTP,       // Mail services (25, 465, 587, 110, 143, 993, 995)
    DATABASE,        // Database services (1433, 3306, 5432, 1521, etc.)
    REMOTE_ACCESS,   // SSH, Telnet, RDP (22, 23, 3389)
    FILE_TRANSFER,   // FTP, SFTP, TFTP (21, 22, 69, 115)
    DNS_SERVICES,    // DNS services (53)
    NETWORK_MGMT,    // SNMP, NTP, etc. (161, 123)
    GENERIC          // Unknown or mixed services
};

struct ServiceCategoryInfo {
    ServiceCategory category;
    std::string description;
    std::vector<uint16_t> common_ports;
    std::vector<std::string> probe_types;
};

class IntelligentServiceDetector {
public:
    IntelligentServiceDetector();
    ~IntelligentServiceDetector() = default;

    // Main detection method - analyzes all ports and applies appropriate detection
    std::unordered_map<uint16_t, ServiceMatch> DetectServices(
        const std::string& target_ip, 
        const std::vector<uint16_t>& open_ports,
        int timeout = 5
    );

    // Categorize ports by service type
    std::unordered_map<ServiceCategory, std::vector<uint16_t>> CategorizeOpenPorts(
        const std::vector<uint16_t>& open_ports
    );

    // Load nmap payloads for enhanced detection
    bool LoadNmapPayloads(const std::string& payloads_file);

private:
    // Service category definitions
    std::unordered_map<ServiceCategory, ServiceCategoryInfo> category_info_;
    
    // Port to category mapping for quick lookup
    std::unordered_map<uint16_t, ServiceCategory> port_category_map_;
    
    // Detection engines for different categories
    std::unique_ptr<ServiceDetectionEngine> generic_detector_;
    std::unique_ptr<ADServiceDetector> ad_detector_;
    
    // Nmap payloads database
    std::unordered_map<uint16_t, std::vector<std::string>> udp_payloads_;
    std::unordered_map<uint16_t, std::vector<std::string>> tcp_payloads_;

    // Category-specific detection methods
    ServiceMatch DetectWindowsADService(const std::string& target_ip, uint16_t port, int timeout);
    ServiceMatch DetectWebService(const std::string& target_ip, uint16_t port, int timeout);
    ServiceMatch DetectMailService(const std::string& target_ip, uint16_t port, int timeout);
    ServiceMatch DetectDatabaseService(const std::string& target_ip, uint16_t port, int timeout);
    ServiceMatch DetectRemoteAccessService(const std::string& target_ip, uint16_t port, int timeout);
    ServiceMatch DetectFileTransferService(const std::string& target_ip, uint16_t port, int timeout);
    ServiceMatch DetectDNSService(const std::string& target_ip, uint16_t port, int timeout);
    ServiceMatch DetectNetworkMgmtService(const std::string& target_ip, uint16_t port, int timeout);
    ServiceMatch DetectGenericService(const std::string& target_ip, uint16_t port, int timeout);

    // Helper methods
    void InitializeCategories();
    void BuildPortCategoryMap();
    ServiceMatch SendCategorySpecificProbes(const std::string& target_ip, uint16_t port, 
                                           ServiceCategory category, int timeout);
    std::string GetServiceBanner(const std::string& target_ip, uint16_t port, int timeout);
    bool ParseNmapPayloadLine(const std::string& line);
};
