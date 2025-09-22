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
#include <chrono>
#include <memory>
#include <functional>

/**
 * Enhanced Active Directory and Windows service detection
 * Designed to match nmap's depth while maintaining Hugin's speed
 */

struct ADServiceInfo {
    std::string service_name;
    std::string version;
    std::string domain_name;
    std::string site_name;
    std::string fqdn;
    std::string netbios_name;
    std::string computer_name;
    std::string os_version;
    std::string server_time;
    std::string product_version;
    std::unordered_map<std::string, std::string> additional_info;
    double confidence;
};

struct KerberosInfo {
    std::string realm;
    std::string server_time;
    std::string version;
    bool time_sync_enabled;
    int time_offset_seconds;
};

struct LDAPInfo {
    std::string domain_name;
    std::string site_name;
    std::string server_name;
    std::string forest_name;
    std::string schema_version;
    std::vector<std::string> naming_contexts;
    std::string supported_sasl_mechanisms;
    std::string supported_ldap_version;
};

struct RDPInfo {
    std::string target_name;
    std::string netbios_domain;
    std::string netbios_computer;
    std::string dns_domain;
    std::string dns_computer;
    std::string dns_tree;
    std::string product_version;
    std::string system_time;
    std::string ssl_cert_subject;
    std::string ssl_cert_issuer;
    std::string ssl_cert_valid_from;
    std::string ssl_cert_valid_to;
};

struct SMBInfo {
    std::string smb_version;
    std::string dialect;
    std::string server_guid;
    std::string domain_name;
    std::string computer_name;
    std::string forest_name;
    bool message_signing_enabled;
    bool message_signing_required;
    std::string start_time;
    std::string system_time;
};

/**
 * High-performance Active Directory service detector
 */
class ADServiceDetector {
private:
    std::string target_ip_;
    std::unordered_map<int, ADServiceInfo> detected_services_;
    
public:
    ADServiceDetector(const std::string& target_ip);
    
    // Main detection methods
    ADServiceInfo DetectService(int port, const std::string& banner = "");
    std::vector<ADServiceInfo> DetectAllServices(const std::vector<int>& ports);
    
    // Specific service detectors
    ADServiceInfo DetectDNS(int port);
    ADServiceInfo DetectKerberos(int port);
    ADServiceInfo DetectLDAP(int port);
    ADServiceInfo DetectSMB(int port);
    ADServiceInfo DetectRDP(int port);
    ADServiceInfo DetectWinRM(int port);
    ADServiceInfo DetectRPC(int port);
    ADServiceInfo DetectNetBIOS(int port);
    
    // Advanced detection methods
    KerberosInfo GetKerberosDetails(int port);
    LDAPInfo GetLDAPDetails(int port);
    RDPInfo GetRDPDetails(int port);
    SMBInfo GetSMBDetails(int port);
    
    // Utility methods
    std::string ExtractDomainFromLDAP(const std::string& ldap_response);
    std::string ExtractSiteFromLDAP(const std::string& ldap_response);
    std::string FormatWindowsTime(const std::string& filetime);
    bool IsActiveDirectoryPort(int port);
    
private:
    // Low-level protocol handlers
    std::string SendLDAPQuery(int port, const std::string& query);
    std::string SendKerberosProbe(int port);
    std::string SendSMBNegotiate(int port);
    std::string SendRDPProbe(int port);
    std::string SendDNSQuery(int port, const std::string& query_type = "A");
    
    // Response parsers
    KerberosInfo ParseKerberosResponse(const std::string& response);
    LDAPInfo ParseLDAPResponse(const std::string& response);
    RDPInfo ParseRDPResponse(const std::string& response);
    SMBInfo ParseSMBResponse(const std::string& response);
    
    // SSL/TLS helpers
    std::string ExtractSSLCertificate(int port);
    std::unordered_map<std::string, std::string> ParseSSLCertificate(const std::string& cert_data);
    
    // Network utilities
    std::string ConnectAndSend(int port, const std::string& data, int timeout = 5);
    std::string ConnectSSLAndSend(int port, const std::string& data, int timeout = 5);
    bool IsPortOpen(int port);
    
    // Data formatting
    std::string FormatServiceOutput(const ADServiceInfo& info);
    double CalculateConfidence(const ADServiceInfo& info);
};

/**
 * Windows-specific service signature database
 */
class WindowsServiceSignatures {
private:
    struct ServiceSignature {
        std::string service_name;
        std::vector<std::string> patterns;
        std::vector<int> common_ports;
        std::string version_regex;
        std::function<ADServiceInfo(const std::string&, int)> custom_detector;
    };
    
    std::vector<ServiceSignature> signatures_;
    
public:
    WindowsServiceSignatures();
    
    void LoadSignatures();
    ADServiceInfo MatchSignature(const std::string& banner, int port);
    bool IsKnownWindowsService(int port);
    
private:
    void LoadDNSSignatures();
    void LoadKerberosSignatures();
    void LoadLDAPSignatures();
    void LoadSMBSignatures();
    void LoadRDPSignatures();
    void LoadWinRMSignatures();
    void LoadRPCSignatures();
    void LoadHTTPAPISignatures();
};

/**
 * Fast Active Directory environment profiler
 */
class ADEnvironmentProfiler {
private:
    std::string target_ip_;
    std::unordered_map<std::string, std::string> environment_info_;
    
public:
    ADEnvironmentProfiler(const std::string& target_ip);
    
    // High-level profiling
    std::unordered_map<std::string, std::string> ProfileEnvironment();
    std::string GetDomainController();
    std::string GetDomainName();
    std::string GetForestName();
    std::string GetSiteName();
    std::vector<std::string> GetDomainControllers();
    
    // OS and version detection
    std::string DetectWindowsVersion();
    std::string DetectADFunctionalLevel();
    std::string DetectExchangeVersion();
    
    // Time synchronization
    std::chrono::system_clock::time_point GetDomainTime();
    int GetTimeOffset();
    
private:
    void ProfileFromLDAP();
    void ProfileFromKerberos();
    void ProfileFromSMB();
    void ProfileFromRDP();
    void ProfileFromDNS();
    
    std::string QueryDNSForDomainControllers();
    std::string QueryLDAPForSchema();
    std::string QuerySMBForInfo();
};

/**
 * Performance-optimized multi-threaded AD scanner
 */
class FastADScanner {
private:
    std::string target_ip_;
    std::vector<int> ad_ports_;
    int max_threads_;
    int timeout_;
    
public:
    FastADScanner(const std::string& target_ip, int max_threads = 50);
    
    // Fast scanning methods
    std::vector<ADServiceInfo> FastScan();
    std::vector<ADServiceInfo> DeepScan();
    std::vector<ADServiceInfo> CustomScan(const std::vector<int>& ports);
    
    // Configuration
    void SetTimeout(int timeout_seconds);
    void SetMaxThreads(int threads);
    void AddCustomPort(int port);
    
    // Results formatting
    std::string FormatResults(const std::vector<ADServiceInfo>& results, const std::string& format = "human");
    std::string GenerateNmapCompatibleOutput(const std::vector<ADServiceInfo>& results);
    
private:
    void InitializeADPorts();
    std::vector<int> GetOpenPorts(const std::vector<int>& ports);
    ADServiceInfo ScanPort(int port);
    
    // Threading utilities
    void ScanPortsThreaded(const std::vector<int>& ports, std::vector<ADServiceInfo>& results);
    static void ScanPortWorker(FastADScanner* scanner, int port, ADServiceInfo* result);
};

// Global AD scanner instance
extern std::unique_ptr<FastADScanner> ad_scanner;
