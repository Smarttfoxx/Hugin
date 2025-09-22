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
#include <regex>
#include <memory>
#include <chrono>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

/**
 * Represents a service probe definition
 */
struct ServiceProbe {
    std::string name;
    std::string protocol;  // "tcp" or "udp"
    std::string data;      // Probe data to send
    int rarity;           // Probe rarity (1-9, lower = more common)
    bool ssl_capable;     // Whether this probe works over SSL
    std::vector<uint16_t> default_ports;
    
    ServiceProbe(const std::string& n, const std::string& proto, 
                const std::string& d, int r = 5, bool ssl = false)
        : name(n), protocol(proto), data(d), rarity(r), ssl_capable(ssl) {}
};

/**
 * Represents a service match pattern
 */
struct ServiceMatch {
    std::string service_name;
    std::string version;
    std::string info;
    std::string hostname;
    std::string os_type;
    std::string device_type;
    std::string cpe;
    float confidence;
    
    ServiceMatch() : confidence(0.0f) {}
};

/**
 * Represents a compiled match pattern
 */
struct MatchPattern {
    std::regex pattern;
    std::string service_name;
    std::string version_template;
    std::string info_template;
    std::string hostname_template;
    std::string os_template;
    std::string device_template;
    std::string cpe_template;
    float base_confidence;
    
    MatchPattern(const std::string& regex_str, const std::string& service,
                float confidence = 0.8f)
        : pattern(regex_str), service_name(service), base_confidence(confidence) {}
};

/**
 * SSL/TLS service detection and certificate analysis
 */
class SSLServiceDetector {
private:
    SSL_CTX* ssl_ctx_;
    
public:
    SSLServiceDetector();
    ~SSLServiceDetector();
    
    bool InitializeSSL();
    void CleanupSSL();
    bool IsSSLService(const std::string& response);
    ServiceMatch ProbeSSLService(const std::string& ip, uint16_t port, int timeout);
    std::vector<std::string> ExtractCertificateInfo(X509* cert);
    std::string GetSSLVersion(SSL* ssl);
    std::string GetCipherSuite(SSL* ssl);
};

/**
 * Operating System fingerprinting engine
 */
class OSFingerprintEngine {
private:
    struct TCPFingerprint {
        std::string window_size;
        std::string options;
        std::string mss;
        std::string window_scale;
        std::string timestamp;
        std::string sack_permitted;
    };
    
    std::unordered_map<std::string, std::string> os_signatures_;
    std::unordered_map<std::string, std::string> app_exclusivity_;
    
public:
    OSFingerprintEngine();
    void LoadOSSignatures();
    std::string AnalyzeTCPBehavior(const std::string& ip, uint16_t port);
    std::string DeduceFromServices(const std::vector<ServiceMatch>& services);
    float CalculateOSConfidence(const std::vector<std::string>& indicators);
    std::string GenerateOSFingerprint(const std::string& ip);
};

/**
 * Main service detection database and engine
 */
class ServiceDetectionEngine {
private:
    std::vector<ServiceProbe> probes_;
    std::unordered_map<std::string, std::vector<MatchPattern>> service_patterns_;
    std::unique_ptr<SSLServiceDetector> ssl_detector_;
    std::unique_ptr<OSFingerprintEngine> os_engine_;
    
    // Performance optimization
    std::unordered_map<uint16_t, std::vector<size_t>> port_probe_index_;
    std::unordered_map<std::string, std::regex> compiled_patterns_;
    
public:
    ServiceDetectionEngine();
    ~ServiceDetectionEngine();
    
    bool Initialize();
    void LoadServiceDatabase();
    void LoadCustomSignatures(const std::string& file_path);
    
    std::vector<ServiceProbe> GetProbesForPort(uint16_t port, const std::string& protocol);
    ServiceMatch MatchResponse(const std::string& response, const ServiceProbe& probe);
    ServiceMatch DetectService(const std::string& ip, uint16_t port, 
                              const std::string& protocol, int timeout = 5);
    
    // Enhanced service detection with multiple probes
    ServiceMatch ComprehensiveServiceDetection(const std::string& ip, uint16_t port,
                                              const std::string& protocol, int timeout = 10);
    
    // SSL-aware service detection
    ServiceMatch DetectSSLService(const std::string& ip, uint16_t port, int timeout = 10);
    
    // OS detection integration
    std::string DetectOperatingSystem(const std::string& ip, 
                                     const std::vector<ServiceMatch>& services);
    
private:
    void BuildPortIndex();
    std::string ProcessTemplate(const std::string& template_str, 
                               const std::smatch& matches);
    bool SendProbe(const std::string& ip, uint16_t port, const ServiceProbe& probe,
                   std::string& response, int timeout);
    bool SendSSLProbe(const std::string& ip, uint16_t port, const ServiceProbe& probe,
                      std::string& response, int timeout);
};

/**
 * Service signature database loader and manager
 */
class ServiceSignatureManager {
private:
    std::string database_path_;
    std::chrono::system_clock::time_point last_update_;
    
public:
    ServiceSignatureManager(const std::string& db_path = "/usr/share/hugin/service-probes");
    
    bool LoadSignatures(ServiceDetectionEngine& engine);
    bool UpdateSignatures();
    void AddCustomSignature(const ServiceProbe& probe, 
                           const std::vector<MatchPattern>& patterns);
    std::string GetDatabaseVersion();
    bool ValidateSignature(const ServiceProbe& probe);
};

// Utility functions for service detection
namespace ServiceUtils {
    std::string EscapeProbeString(const std::string& input);
    std::string UnescapeProbeString(const std::string& input);
    bool IsPortLikelyService(uint16_t port, const std::string& service);
    std::vector<std::string> ExtractVersionInfo(const std::string& banner);
    std::string NormalizeServiceName(const std::string& service);
    float CalculateConfidence(const std::string& response, const MatchPattern& pattern);
}
