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

#include "service_detection.h"
#include "../utilities/log_system.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iomanip>

// SSL Service Detector Implementation
SSLServiceDetector::SSLServiceDetector() : ssl_ctx_(nullptr) {
    InitializeSSL();
}

SSLServiceDetector::~SSLServiceDetector() {
    CleanupSSL();
}

bool SSLServiceDetector::InitializeSSL() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    ssl_ctx_ = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx_) {
        logsys.Error("Failed to create SSL context");
        return false;
    }
    
    // Set options for compatibility
    SSL_CTX_set_options(ssl_ctx_, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_NONE, nullptr);
    
    return true;
}

void SSLServiceDetector::CleanupSSL() {
    if (ssl_ctx_) {
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
    }
    EVP_cleanup();
    ERR_free_strings();
}

bool SSLServiceDetector::IsSSLService(const std::string& response) {
    if (response.length() < 3) return false;
    
    // Check for SSL/TLS handshake patterns
    unsigned char first_byte = static_cast<unsigned char>(response[0]);
    unsigned char second_byte = static_cast<unsigned char>(response[1]);
    unsigned char third_byte = static_cast<unsigned char>(response[2]);
    
    // SSL/TLS handshake record type (0x16) and version checks
    if (first_byte == 0x16) {
        // Check for SSL 3.0, TLS 1.0, 1.1, 1.2, 1.3
        if ((second_byte == 0x03 && (third_byte >= 0x00 && third_byte <= 0x04)) ||
            (second_byte == 0x02 && third_byte == 0x00)) {
            return true;
        }
    }
    
    // Check for common SSL error responses
    if (response.find("SSL") != std::string::npos ||
        response.find("TLS") != std::string::npos ||
        response.find("certificate") != std::string::npos) {
        return true;
    }
    
    return false;
}

ServiceMatch SSLServiceDetector::ProbeSSLService(const std::string& ip, uint16_t port, int timeout) {
    ServiceMatch match;
    
    if (!ssl_ctx_) {
        logsys.Error("SSL context not initialized");
        return match;
    }
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        logsys.Error("Failed to create socket for SSL probe");
        return match;
    }
    
    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
    
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sockfd);
        return match;
    }
    
    SSL* ssl = SSL_new(ssl_ctx_);
    if (!ssl) {
        close(sockfd);
        return match;
    }
    
    SSL_set_fd(ssl, sockfd);
    
    int ssl_result = SSL_connect(ssl);
    if (ssl_result <= 0) {
        int error = SSL_get_error(ssl, ssl_result);
        logsys.Warning("SSL connection failed:", error);
        SSL_free(ssl);
        close(sockfd);
        return match;
    }
    
    // Successfully established SSL connection
    match.service_name = "ssl";
    match.confidence = 0.9f;
    
    // Get SSL version
    std::string ssl_version = GetSSLVersion(ssl);
    if (!ssl_version.empty()) {
        match.version = ssl_version;
    }
    
    // Get cipher suite
    std::string cipher = GetCipherSuite(ssl);
    if (!cipher.empty()) {
        match.info = "cipher: " + cipher;
    }
    
    // Get certificate information
    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        std::vector<std::string> cert_info = ExtractCertificateInfo(cert);
        if (!cert_info.empty()) {
            match.hostname = cert_info[0]; // Common name
            if (cert_info.size() > 1) {
                match.info += " org: " + cert_info[1];
            }
        }
        X509_free(cert);
    }
    
    // Try to detect the underlying service
    const char* http_request = "GET / HTTP/1.0\r\n\r\n";
    SSL_write(ssl, http_request, strlen(http_request));
    
    char buffer[4096];
    int bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        std::string response(buffer);
        
        if (response.find("HTTP/") != std::string::npos) {
            match.service_name = "ssl/http";
            if (response.find("Server:") != std::string::npos) {
                size_t server_pos = response.find("Server:");
                size_t end_pos = response.find("\r\n", server_pos);
                if (end_pos != std::string::npos) {
                    std::string server_info = response.substr(server_pos + 7, end_pos - server_pos - 7);
                    // Trim whitespace
                    server_info.erase(0, server_info.find_first_not_of(" \t"));
                    server_info.erase(server_info.find_last_not_of(" \t") + 1);
                    match.info += " server: " + server_info;
                }
            }
        }
    }
    
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    
    return match;
}

std::vector<std::string> SSLServiceDetector::ExtractCertificateInfo(X509* cert) {
    std::vector<std::string> info;
    
    if (!cert) return info;
    
    // Get subject name
    X509_NAME* subject = X509_get_subject_name(cert);
    if (subject) {
        char* subject_str = X509_NAME_oneline(subject, nullptr, 0);
        if (subject_str) {
            std::string subject_line(subject_str);
            
            // Extract CN (Common Name)
            size_t cn_pos = subject_line.find("CN=");
            if (cn_pos != std::string::npos) {
                size_t start = cn_pos + 3;
                size_t end = subject_line.find("/", start);
                if (end == std::string::npos) end = subject_line.length();
                info.push_back(subject_line.substr(start, end - start));
            }
            
            // Extract O (Organization)
            size_t o_pos = subject_line.find("O=");
            if (o_pos != std::string::npos) {
                size_t start = o_pos + 2;
                size_t end = subject_line.find("/", start);
                if (end == std::string::npos) end = subject_line.length();
                info.push_back(subject_line.substr(start, end - start));
            }
            
            OPENSSL_free(subject_str);
        }
    }
    
    return info;
}

std::string SSLServiceDetector::GetSSLVersion(SSL* ssl) {
    if (!ssl) return "";
    
    const char* version = SSL_get_version(ssl);
    return version ? std::string(version) : "";
}

std::string SSLServiceDetector::GetCipherSuite(SSL* ssl) {
    if (!ssl) return "";
    
    const char* cipher = SSL_get_cipher(ssl);
    return cipher ? std::string(cipher) : "";
}

// OS Fingerprint Engine Implementation
OSFingerprintEngine::OSFingerprintEngine() {
    LoadOSSignatures();
}

void OSFingerprintEngine::LoadOSSignatures() {
    // Load basic OS signatures based on application exclusivity
    app_exclusivity_["Microsoft Exchange"] = "Windows";
    app_exclusivity_["IIS"] = "Windows";
    app_exclusivity_["Apache/2"] = "Linux/Unix";
    app_exclusivity_["nginx"] = "Linux/Unix";
    app_exclusivity_["OpenSSH"] = "Linux/Unix";
    app_exclusivity_["Samba"] = "Linux/Unix";
    app_exclusivity_["vsftpd"] = "Linux";
    app_exclusivity_["ProFTPD"] = "Linux/Unix";
    app_exclusivity_["Pure-FTPd"] = "Linux/Unix";
    app_exclusivity_["Microsoft-IIS"] = "Windows";
    app_exclusivity_["Microsoft-HTTPAPI"] = "Windows";
}

std::string OSFingerprintEngine::DeduceFromServices(const std::vector<ServiceMatch>& services) {
    std::unordered_map<std::string, int> os_votes;
    
    for (const auto& service : services) {
        std::string service_key = service.service_name;
        if (!service.version.empty()) {
            service_key += "/" + service.version;
        }
        
        // Check application exclusivity
        for (const auto& [app, os] : app_exclusivity_) {
            if (service.service_name.find(app) != std::string::npos ||
                service.info.find(app) != std::string::npos) {
                os_votes[os] += 3; // High confidence vote
            }
        }
        
        // Analyze service banners for OS hints
        std::string combined_info = service.service_name + " " + service.version + " " + service.info;
        std::transform(combined_info.begin(), combined_info.end(), combined_info.begin(), ::tolower);
        
        if (combined_info.find("windows") != std::string::npos ||
            combined_info.find("win32") != std::string::npos ||
            combined_info.find("microsoft") != std::string::npos) {
            os_votes["Windows"] += 2;
        }
        
        if (combined_info.find("linux") != std::string::npos ||
            combined_info.find("ubuntu") != std::string::npos ||
            combined_info.find("debian") != std::string::npos ||
            combined_info.find("centos") != std::string::npos ||
            combined_info.find("redhat") != std::string::npos) {
            os_votes["Linux"] += 2;
        }
        
        if (combined_info.find("unix") != std::string::npos ||
            combined_info.find("freebsd") != std::string::npos ||
            combined_info.find("openbsd") != std::string::npos ||
            combined_info.find("netbsd") != std::string::npos) {
            os_votes["Unix"] += 2;
        }
        
        if (combined_info.find("darwin") != std::string::npos ||
            combined_info.find("macos") != std::string::npos ||
            combined_info.find("mac os") != std::string::npos) {
            os_votes["macOS"] += 2;
        }
    }
    
    // Find the OS with the most votes
    std::string best_os = "Unknown";
    int max_votes = 0;
    
    for (const auto& [os, votes] : os_votes) {
        if (votes > max_votes) {
            max_votes = votes;
            best_os = os;
        }
    }
    
    return best_os;
}

float OSFingerprintEngine::CalculateOSConfidence(const std::vector<std::string>& indicators) {
    if (indicators.empty()) return 0.0f;
    
    // Simple confidence calculation based on number of indicators
    float base_confidence = 0.3f;
    float per_indicator = 0.2f;
    
    return std::min(1.0f, base_confidence + (indicators.size() * per_indicator));
}

// Service Detection Engine Implementation
ServiceDetectionEngine::ServiceDetectionEngine() {
    ssl_detector_ = std::make_unique<SSLServiceDetector>();
    os_engine_ = std::make_unique<OSFingerprintEngine>();
}

ServiceDetectionEngine::~ServiceDetectionEngine() = default;

bool ServiceDetectionEngine::Initialize() {
    LoadServiceDatabase();
    BuildPortIndex();
    return true;
}

void ServiceDetectionEngine::LoadServiceDatabase() {
    // Load common service probes
    
    // HTTP probes
    probes_.emplace_back("GetRequest", "tcp", "GET / HTTP/1.0\\r\\n\\r\\n", 1, true);
    probes_.back().default_ports = {80, 443, 8080, 8443, 8000, 8888};
    
    probes_.emplace_back("HTTPOptions", "tcp", "OPTIONS / HTTP/1.0\\r\\n\\r\\n", 3, true);
    probes_.back().default_ports = {80, 443, 8080, 8443};
    
    // SSH probe
    probes_.emplace_back("SSHVersionExchange", "tcp", "SSH-2.0-Hugin_Scanner\\r\\n", 1, false);
    probes_.back().default_ports = {22, 2222};
    
    // FTP probe
    probes_.emplace_back("FTPBanner", "tcp", "", 1, false); // NULL probe for banner
    probes_.back().default_ports = {21, 2121};
    
    // SMTP probe
    probes_.emplace_back("SMTPBanner", "tcp", "", 1, true);
    probes_.back().default_ports = {25, 465, 587};
    
    probes_.emplace_back("SMTPHelo", "tcp", "HELO hugin.scanner\\r\\n", 2, true);
    probes_.back().default_ports = {25, 465, 587};
    
    // DNS probe
    probes_.emplace_back("DNSVersionBindReq", "tcp", "\\x00\\x1e\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07version\\x04bind\\x00\\x00\\x10\\x00\\x03", 3, false);
    probes_.back().default_ports = {53};
    
    // Load match patterns
    service_patterns_["http"].emplace_back("HTTP/1\\.[01] \\d+ .*Server: ([^\\r\\n]+)", "http");
    service_patterns_["http"].emplace_back("HTTP/1\\.[01] \\d+ .*", "http");
    
    service_patterns_["ssh"].emplace_back("SSH-([\\d\\.]+)-OpenSSH[_-]([\\w\\.]+)", "ssh");
    service_patterns_["ssh"].emplace_back("SSH-([\\d\\.]+)-([^\\r\\n]+)", "ssh");
    
    service_patterns_["ftp"].emplace_back("220.*Welcome to.*Pure-?FTPd ([\\d\\S]+)", "ftp");
    service_patterns_["ftp"].emplace_back("220.*vsftpd ([\\d\\.]+)", "ftp");
    service_patterns_["ftp"].emplace_back("220.*ProFTPD ([\\d\\.]+)", "ftp");
    service_patterns_["ftp"].emplace_back("220[- ].*", "ftp");
    
    service_patterns_["smtp"].emplace_back("220.*ESMTP ([^\\r\\n]+)", "smtp");
    service_patterns_["smtp"].emplace_back("220.*Postfix", "smtp");
    service_patterns_["smtp"].emplace_back("220.*Sendmail ([\\d\\.]+)", "smtp");
    service_patterns_["smtp"].emplace_back("220[- ].*", "smtp");
    
    service_patterns_["dns"].emplace_back("\\x00.*\\x81\\x80", "dns");
}

std::vector<ServiceProbe> ServiceDetectionEngine::GetProbesForPort(uint16_t port, const std::string& protocol) {
    std::vector<ServiceProbe> relevant_probes;
    
    // Get probes specifically for this port
    auto it = port_probe_index_.find(port);
    if (it != port_probe_index_.end()) {
        for (size_t probe_idx : it->second) {
            if (probes_[probe_idx].protocol == protocol) {
                relevant_probes.push_back(probes_[probe_idx]);
            }
        }
    }
    
    // Add generic probes for the protocol
    for (const auto& probe : probes_) {
        if (probe.protocol == protocol && probe.default_ports.empty()) {
            relevant_probes.push_back(probe);
        }
    }
    
    // Sort by rarity (lower rarity = higher priority)
    std::sort(relevant_probes.begin(), relevant_probes.end(),
              [](const ServiceProbe& a, const ServiceProbe& b) {
                  return a.rarity < b.rarity;
              });
    
    return relevant_probes;
}

ServiceMatch ServiceDetectionEngine::MatchResponse(const std::string& response, const ServiceProbe& probe) {
    ServiceMatch match;
    
    if (response.empty()) return match;
    
    // Try to match against known patterns
    for (const auto& [service_name, patterns] : service_patterns_) {
        for (const auto& pattern : patterns) {
            std::smatch matches;
            if (std::regex_search(response, matches, pattern.pattern)) {
                match.service_name = pattern.service_name;
                match.confidence = pattern.base_confidence;
                
                // Extract version information if available
                if (matches.size() > 1) {
                    match.version = matches[1].str();
                }
                if (matches.size() > 2) {
                    match.info = matches[2].str();
                }
                
                return match;
            }
        }
    }
    
    // If no specific pattern matched, try generic detection
    if (probe.name == "GetRequest" && response.find("HTTP/") != std::string::npos) {
        match.service_name = "http";
        match.confidence = 0.7f;
        
        // Extract server information
        size_t server_pos = response.find("Server:");
        if (server_pos != std::string::npos) {
            size_t end_pos = response.find("\r\n", server_pos);
            if (end_pos != std::string::npos) {
                match.info = response.substr(server_pos + 7, end_pos - server_pos - 7);
                // Trim whitespace
                match.info.erase(0, match.info.find_first_not_of(" \t"));
                match.info.erase(match.info.find_last_not_of(" \t") + 1);
            }
        }
    }
    
    return match;
}

ServiceMatch ServiceDetectionEngine::DetectService(const std::string& ip, uint16_t port, 
                                                   const std::string& protocol, int timeout) {
    ServiceMatch best_match;
    
    // First check if it might be an SSL service
    if (protocol == "tcp") {
        // Try a quick SSL detection
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd >= 0) {
            struct timeval tv;
            tv.tv_sec = 2; // Quick timeout for SSL check
            tv.tv_usec = 0;
            setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
            
            if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                char buffer[1024];
                int bytes = recv(sockfd, buffer, sizeof(buffer) - 1, MSG_DONTWAIT);
                if (bytes > 0) {
                    buffer[bytes] = '\0';
                    if (ssl_detector_->IsSSLService(std::string(buffer))) {
                        close(sockfd);
                        return ssl_detector_->ProbeSSLService(ip, port, timeout);
                    }
                }
            }
            close(sockfd);
        }
    }
    
    // Get relevant probes for this port and protocol
    std::vector<ServiceProbe> probes = GetProbesForPort(port, protocol);
    
    for (const auto& probe : probes) {
        std::string response;
        if (SendProbe(ip, port, probe, response, timeout)) {
            ServiceMatch match = MatchResponse(response, probe);
            if (match.confidence > best_match.confidence) {
                best_match = match;
                // If we have high confidence, we can stop here
                if (match.confidence > 0.8f) {
                    break;
                }
            }
        }
    }
    
    return best_match;
}

bool ServiceDetectionEngine::SendProbe(const std::string& ip, uint16_t port, const ServiceProbe& probe,
                                      std::string& response, int timeout) {
    if (probe.protocol != "tcp" && probe.protocol != "udp") {
        return false;
    }
    
    int sockfd = socket(AF_INET, (probe.protocol == "tcp") ? SOCK_STREAM : SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return false;
    }
    
    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
    
    bool success = false;
    
    if (probe.protocol == "tcp") {
        if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            // Send probe data if any
            if (!probe.data.empty()) {
                std::string unescaped_data = ServiceUtils::UnescapeProbeString(probe.data);
                send(sockfd, unescaped_data.c_str(), unescaped_data.length(), 0);
            }
            
            // Receive response
            char buffer[4096];
            int bytes = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
            if (bytes > 0) {
                buffer[bytes] = '\0';
                response = std::string(buffer);
                success = true;
            }
        }
    } else { // UDP
        // For UDP, we send the probe and wait for a response
        if (!probe.data.empty()) {
            std::string unescaped_data = ServiceUtils::UnescapeProbeString(probe.data);
            sendto(sockfd, unescaped_data.c_str(), unescaped_data.length(), 0,
                   (struct sockaddr*)&addr, sizeof(addr));
        }
        
        char buffer[4096];
        int bytes = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0, nullptr, nullptr);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            response = std::string(buffer);
            success = true;
        }
    }
    
    close(sockfd);
    return success;
}

std::string ServiceDetectionEngine::DetectOperatingSystem(const std::string& ip, 
                                                        const std::vector<ServiceMatch>& services) {
    if (!os_engine_) {
        return "Unknown";
    }
    
    return os_engine_->DeduceFromServices(services);
}

void ServiceDetectionEngine::BuildPortIndex() {
    for (size_t i = 0; i < probes_.size(); ++i) {
        for (uint16_t port : probes_[i].default_ports) {
            port_probe_index_[port].push_back(i);
        }
    }
}

// Service Utils Implementation
namespace ServiceUtils {
    std::string UnescapeProbeString(const std::string& input) {
        std::string result;
        result.reserve(input.length());
        
        for (size_t i = 0; i < input.length(); ++i) {
            if (input[i] == '\\' && i + 1 < input.length()) {
                char next = input[i + 1];
                switch (next) {
                    case 'r': result += '\r'; i++; break;
                    case 'n': result += '\n'; i++; break;
                    case 't': result += '\t'; i++; break;
                    case '\\': result += '\\'; i++; break;
                    case '0': result += '\0'; i++; break;
                    case 'x':
                        if (i + 3 < input.length()) {
                            std::string hex = input.substr(i + 2, 2);
                            try {
                                unsigned char byte = static_cast<unsigned char>(std::stoi(hex, nullptr, 16));
                                result += byte;
                                i += 3;
                            } catch (...) {
                                result += input[i];
                            }
                        } else {
                            result += input[i];
                        }
                        break;
                    default:
                        result += input[i];
                        break;
                }
            } else {
                result += input[i];
            }
        }
        
        return result;
    }
    
    std::string EscapeProbeString(const std::string& input) {
        std::string result;
        result.reserve(input.length() * 2);
        
        for (char c : input) {
            switch (c) {
                case '\r': result += "\\r"; break;
                case '\n': result += "\\n"; break;
                case '\t': result += "\\t"; break;
                case '\\': result += "\\\\"; break;
                case '\0': result += "\\0"; break;
                default:
                    if (std::isprint(c)) {
                        result += c;
                    } else {
                        std::ostringstream oss;
                        oss << "\\x" << std::hex << std::setw(2) << std::setfill('0') 
                            << static_cast<unsigned char>(c);
                        result += oss.str();
                    }
                    break;
            }
        }
        
        return result;
    }
    
    bool IsPortLikelyService(uint16_t port, const std::string& service) {
        static std::unordered_map<uint16_t, std::string> common_ports = {
            {21, "ftp"}, {22, "ssh"}, {23, "telnet"}, {25, "smtp"},
            {53, "dns"}, {80, "http"}, {110, "pop3"}, {143, "imap"},
            {443, "https"}, {993, "imaps"}, {995, "pop3s"}
        };
        
        auto it = common_ports.find(port);
        return it != common_ports.end() && it->second == service;
    }
    
    std::string NormalizeServiceName(const std::string& service) {
        std::string normalized = service;
        std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::tolower);
        
        // Remove common prefixes/suffixes
        if (normalized.find("ssl/") == 0) {
            normalized = normalized.substr(4);
        }
        
        return normalized;
    }
    
    float CalculateConfidence(const std::string& response, const MatchPattern& pattern) {
        if (response.empty()) return 0.0f;
        
        float base_confidence = pattern.base_confidence;
        
        // Increase confidence based on response length and content
        if (response.length() > 100) base_confidence += 0.1f;
        if (response.find("version") != std::string::npos ||
            response.find("Version") != std::string::npos) {
            base_confidence += 0.1f;
        }
        
        return std::min(1.0f, base_confidence);
    }
}
