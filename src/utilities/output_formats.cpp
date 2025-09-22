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

#include "output_formats.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <filesystem>

// Global instances
std::unique_ptr<OutputManager> output_manager = nullptr;
std::unique_ptr<ComplianceReporter> compliance_reporter = nullptr;
std::unique_ptr<VulnerabilityCorrelator> vulnerability_correlator = nullptr;

// Human Readable Formatter Implementation
std::string HumanReadableFormatter::Format(const ScanResult& result) {
    std::ostringstream oss;
    
    // Header
    oss << "Hugin Network Scan Report\n";
    oss << std::string(50, '=') << "\n\n";
    
    // Target information
    oss << "Target: " << result.target_ip;
    if (!result.hostname.empty()) {
        oss << " (" << result.hostname << ")";
    }
    oss << "\n";
    
    oss << "Status: " << (result.host_up ? "Up" : "Down") << "\n";
    
    if (!result.os_detection.empty()) {
        oss << "OS: " << result.os_detection;
        if (result.os_confidence > 0.0f) {
            oss << " (confidence: " << std::fixed << std::setprecision(2) << result.os_confidence << ")";
        }
        oss << "\n";
    }
    
    oss << "\n";
    
    // Port table
    if (!result.ports.empty()) {
        oss << FormatPortTable(result.ports);
    } else {
        oss << "No open ports found.\n";
    }
    
    oss << "\n";
    
    // Scan summary
    oss << FormatScanSummary(result);
    
    return oss.str();
}

std::string HumanReadableFormatter::FormatPortTable(const std::vector<ScanResult::PortResult>& ports) {
    std::ostringstream oss;
    
    oss << std::left;
    oss << std::setw(12) << "PORT" 
        << std::setw(8) << "STATE" 
        << std::setw(20) << "SERVICE" 
        << std::setw(15) << "VERSION" 
        << std::setw(30) << "INFO" 
        << std::setw(10) << "CONF\n";
    
    oss << std::string(95, '-') << "\n";
    
    for (const auto& port : ports) {
        oss << std::setw(12) << (std::to_string(port.port) + "/" + port.protocol)
            << std::setw(8) << port.state
            << std::setw(20) << (port.ssl_enabled ? "ssl/" + port.service : port.service)
            << std::setw(15) << (port.version.empty() ? "N/A" : port.version)
            << std::setw(30) << (port.info.empty() ? "N/A" : port.info)
            << std::setw(10) << std::fixed << std::setprecision(2) << port.confidence
            << "\n";
    }
    
    return oss.str();
}

std::string HumanReadableFormatter::FormatScanSummary(const ScanResult& result) {
    std::ostringstream oss;
    
    oss << "Scan Summary:\n";
    oss << "  Total ports scanned: " << result.total_ports_scanned << "\n";
    oss << "  Open ports: " << result.stats.open_ports << "\n";
    oss << "  Services detected: " << result.stats.services_detected << "\n";
    oss << "  SSL services: " << result.stats.ssl_services << "\n";
    oss << "  Scan duration: " << std::fixed << std::setprecision(1) << result.stats.scan_duration_seconds << " seconds\n";
    oss << "  Average port time: " << std::fixed << std::setprecision(2) << result.stats.average_port_time_ms << " ms\n";
    
    return oss.str();
}

// JSON Formatter Implementation
std::string JSONFormatter::Format(const ScanResult& result) {
    std::ostringstream oss;
    
    oss << "{\n";
    oss << "  \"scan_info\": {\n";
    oss << "    \"target\": \"" << EscapeJSON(result.target_ip) << "\",\n";
    if (!result.hostname.empty()) {
        oss << "    \"hostname\": \"" << EscapeJSON(result.hostname) << "\",\n";
    }
    oss << "    \"start_time\": \"" << FormatTimestamp(result.scan_start) << "\",\n";
    oss << "    \"end_time\": \"" << FormatTimestamp(result.scan_end) << "\",\n";
    oss << "    \"duration\": " << result.stats.scan_duration_seconds << ",\n";
    oss << "    \"ports_scanned\": " << result.total_ports_scanned << "\n";
    oss << "  },\n";
    
    oss << "  \"host\": {\n";
    oss << "    \"ip\": \"" << EscapeJSON(result.target_ip) << "\",\n";
    oss << "    \"status\": \"" << (result.host_up ? "up" : "down") << "\"";
    
    if (!result.os_detection.empty()) {
        oss << ",\n    \"os\": {\n";
        oss << "      \"name\": \"" << EscapeJSON(result.os_detection) << "\",\n";
        oss << "      \"confidence\": " << result.os_confidence << "\n";
        oss << "    }";
    }
    oss << "\n  },\n";
    
    oss << "  \"ports\": [\n";
    for (size_t i = 0; i < result.ports.size(); ++i) {
        const auto& port = result.ports[i];
        oss << "    {\n";
        oss << "      \"port\": " << port.port << ",\n";
        oss << "      \"protocol\": \"" << port.protocol << "\",\n";
        oss << "      \"state\": \"" << port.state << "\",\n";
        oss << "      \"service\": \"" << EscapeJSON(port.service) << "\",\n";
        oss << "      \"version\": \"" << EscapeJSON(port.version) << "\",\n";
        oss << "      \"info\": \"" << EscapeJSON(port.info) << "\",\n";
        oss << "      \"confidence\": " << port.confidence << ",\n";
        oss << "      \"ssl_enabled\": " << (port.ssl_enabled ? "true" : "false");
        
        if (port.ssl_enabled) {
            oss << ",\n      \"ssl_info\": {\n";
            oss << "        \"version\": \"" << EscapeJSON(port.ssl_version) << "\",\n";
            oss << "        \"cipher\": \"" << EscapeJSON(port.ssl_cipher) << "\"";
            if (!port.ssl_cert_info.empty()) {
                oss << ",\n        \"certificate\": [\n";
                for (size_t j = 0; j < port.ssl_cert_info.size(); ++j) {
                    oss << "          \"" << EscapeJSON(port.ssl_cert_info[j]) << "\"";
                    if (j < port.ssl_cert_info.size() - 1) oss << ",";
                    oss << "\n";
                }
                oss << "        ]";
            }
            oss << "\n      }";
        }
        
        if (!port.cpe.empty()) {
            oss << ",\n      \"cpe\": \"" << EscapeJSON(port.cpe) << "\"";
        }
        
        oss << "\n    }";
        if (i < result.ports.size() - 1) oss << ",";
        oss << "\n";
    }
    oss << "  ],\n";
    
    oss << "  \"statistics\": {\n";
    oss << "    \"open_ports\": " << result.stats.open_ports << ",\n";
    oss << "    \"closed_ports\": " << result.stats.closed_ports << ",\n";
    oss << "    \"filtered_ports\": " << result.stats.filtered_ports << ",\n";
    oss << "    \"services_detected\": " << result.stats.services_detected << ",\n";
    oss << "    \"ssl_services\": " << result.stats.ssl_services << ",\n";
    oss << "    \"scan_duration_seconds\": " << result.stats.scan_duration_seconds << ",\n";
    oss << "    \"average_port_time_ms\": " << result.stats.average_port_time_ms << "\n";
    oss << "  }\n";
    oss << "}\n";
    
    return oss.str();
}

std::string JSONFormatter::EscapeJSON(const std::string& input) {
    std::string result;
    result.reserve(input.length() * 2);
    
    for (char c : input) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (c < 0x20) {
                    result += "\\u";
                    result += "0000";
                    std::ostringstream oss;
                    oss << std::hex << static_cast<int>(c);
                    std::string hex = oss.str();
                    result.replace(result.length() - hex.length(), hex.length(), hex);
                } else {
                    result += c;
                }
                break;
        }
    }
    
    return result;
}

std::string JSONFormatter::FormatTimestamp(const std::chrono::system_clock::time_point& time) {
    auto time_t = std::chrono::system_clock::to_time_t(time);
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

// XML Formatter Implementation
std::string XMLFormatter::Format(const ScanResult& result) {
    std::ostringstream oss;
    
    oss << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    oss << "<nmaprun scanner=\"hugin\" version=\"2.0\" start=\"" 
        << std::chrono::duration_cast<std::chrono::seconds>(result.scan_start.time_since_epoch()).count() 
        << "\">\n";
    
    oss << "  <scaninfo type=\"syn\" protocol=\"tcp\" numservices=\"" << result.total_ports_scanned << "\"/>\n";
    
    oss << "  <host>\n";
    oss << "    <status state=\"" << (result.host_up ? "up" : "down") << "\"/>\n";
    oss << "    <address addr=\"" << EscapeXML(result.target_ip) << "\" addrtype=\"ipv4\"/>\n";
    
    if (!result.hostname.empty()) {
        oss << "    <hostnames>\n";
        oss << "      <hostname name=\"" << EscapeXML(result.hostname) << "\" type=\"PTR\"/>\n";
        oss << "    </hostnames>\n";
    }
    
    if (!result.ports.empty()) {
        oss << "    <ports>\n";
        for (const auto& port : result.ports) {
            oss << "      <port protocol=\"" << port.protocol << "\" portid=\"" << port.port << "\">\n";
            oss << "        <state state=\"" << port.state << "\"/>\n";
            oss << "        <service name=\"" << EscapeXML(port.service) << "\"";
            if (!port.version.empty()) {
                oss << " version=\"" << EscapeXML(port.version) << "\"";
            }
            if (!port.info.empty()) {
                oss << " extrainfo=\"" << EscapeXML(port.info) << "\"";
            }
            oss << " conf=\"" << static_cast<int>(port.confidence * 10) << "\"";
            if (port.ssl_enabled) {
                oss << " tunnel=\"ssl\"";
            }
            oss << "/>\n";
            oss << "      </port>\n";
        }
        oss << "    </ports>\n";
    }
    
    if (!result.os_detection.empty()) {
        oss << "    <os>\n";
        oss << "      <osmatch name=\"" << EscapeXML(result.os_detection) << "\" accuracy=\"" 
            << static_cast<int>(result.os_confidence * 100) << "\"/>\n";
        oss << "    </os>\n";
    }
    
    oss << "  </host>\n";
    
    oss << "  <runstats>\n";
    oss << "    <finished time=\"" 
        << std::chrono::duration_cast<std::chrono::seconds>(result.scan_end.time_since_epoch()).count() 
        << "\" timestr=\"" << FormatTimestamp(result.scan_end) << "\"/>\n";
    oss << "    <hosts up=\"" << (result.host_up ? 1 : 0) << "\" down=\"" << (result.host_up ? 0 : 1) << "\" total=\"1\"/>\n";
    oss << "  </runstats>\n";
    
    oss << "</nmaprun>\n";
    
    return oss.str();
}

std::string XMLFormatter::EscapeXML(const std::string& input) {
    std::string result;
    result.reserve(input.length() * 2);
    
    for (char c : input) {
        switch (c) {
            case '<': result += "&lt;"; break;
            case '>': result += "&gt;"; break;
            case '&': result += "&amp;"; break;
            case '"': result += "&quot;"; break;
            case '\'': result += "&apos;"; break;
            default: result += c; break;
        }
    }
    
    return result;
}

std::string XMLFormatter::FormatTimestamp(const std::chrono::system_clock::time_point& time) {
    auto time_t = std::chrono::system_clock::to_time_t(time);
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&time_t), "%a %b %d %H:%M:%S %Y");
    return oss.str();
}

// CSV Formatter Implementation
std::string CSVFormatter::Format(const ScanResult& result) {
    std::ostringstream oss;
    
    // Header
    oss << "Target,Port,Protocol,State,Service,Version,Info,Confidence,SSL,SSL_Version,SSL_Cipher\n";
    
    // Data rows
    for (const auto& port : result.ports) {
        oss << EscapeCSV(result.target_ip) << ",";
        oss << port.port << ",";
        oss << EscapeCSV(port.protocol) << ",";
        oss << EscapeCSV(port.state) << ",";
        oss << EscapeCSV(port.service) << ",";
        oss << EscapeCSV(port.version) << ",";
        oss << EscapeCSV(port.info) << ",";
        oss << port.confidence << ",";
        oss << (port.ssl_enabled ? "Yes" : "No") << ",";
        oss << EscapeCSV(port.ssl_version) << ",";
        oss << EscapeCSV(port.ssl_cipher) << "\n";
    }
    
    return oss.str();
}

std::string CSVFormatter::EscapeCSV(const std::string& input) {
    if (input.find(',') != std::string::npos || 
        input.find('"') != std::string::npos || 
        input.find('\n') != std::string::npos) {
        
        std::string result = "\"";
        for (char c : input) {
            if (c == '"') {
                result += "\"\"";
            } else {
                result += c;
            }
        }
        result += "\"";
        return result;
    }
    return input;
}

// Greppable Formatter Implementation
std::string GreppableFormatter::Format(const ScanResult& result) {
    std::ostringstream oss;
    
    oss << "Host: " << result.target_ip;
    if (!result.hostname.empty()) {
        oss << " (" << result.hostname << ")";
    }
    oss << "\tStatus: " << (result.host_up ? "Up" : "Down") << "\n";
    
    if (!result.ports.empty()) {
        oss << "Host: " << result.target_ip << "\tPorts: ";
        for (size_t i = 0; i < result.ports.size(); ++i) {
            const auto& port = result.ports[i];
            oss << port.port << "/" << port.state << "/" << port.protocol << "//" 
                << port.service << "/" << port.version << "/";
            if (i < result.ports.size() - 1) {
                oss << ", ";
            }
        }
        oss << "\n";
    }
    
    if (!result.os_detection.empty()) {
        oss << "Host: " << result.target_ip << "\tOS: " << result.os_detection << "\n";
    }
    
    return oss.str();
}

// Output Manager Implementation
OutputManager::OutputManager(const std::string& output_dir, bool console) 
    : output_directory_(output_dir), console_output_(console) {
    
    // Register default formatters
    RegisterFormatter("human", std::make_unique<HumanReadableFormatter>());
    RegisterFormatter("json", std::make_unique<JSONFormatter>());
    RegisterFormatter("xml", std::make_unique<XMLFormatter>());
    RegisterFormatter("csv", std::make_unique<CSVFormatter>());
    RegisterFormatter("gnmap", std::make_unique<GreppableFormatter>());
}

void OutputManager::RegisterFormatter(const std::string& name, std::unique_ptr<OutputFormatter> formatter) {
    formatters_[name] = std::move(formatter);
}

void OutputManager::SetOutputDirectory(const std::string& directory) {
    output_directory_ = directory;
    if (!output_directory_.empty() && !std::filesystem::exists(output_directory_)) {
        std::filesystem::create_directories(output_directory_);
    }
}

void OutputManager::EnableConsoleOutput(bool enable) {
    console_output_ = enable;
}

bool OutputManager::OutputResults(const ScanResult& result, const std::string& format_name, const std::string& filename) {
    auto it = formatters_.find(format_name);
    if (it == formatters_.end()) {
        std::cerr << "Unknown output format: " << format_name << std::endl;
        return false;
    }
    
    std::string content = it->second->Format(result);
    
    if (console_output_ && filename.empty()) {
        OutputToConsole(content, format_name);
    }
    
    if (!filename.empty()) {
        std::string filepath = filename;
        if (!output_directory_.empty()) {
            filepath = output_directory_ + "/" + filename;
        }
        return WriteToFile(content, filepath);
    }
    
    return true;
}

bool OutputManager::OutputResults(const ScanResult& result, const std::vector<std::string>& formats, const std::string& base_filename) {
    bool success = true;
    
    for (const auto& format : formats) {
        auto it = formatters_.find(format);
        if (it == formatters_.end()) {
            std::cerr << "Unknown output format: " << format << std::endl;
            success = false;
            continue;
        }
        
        std::string filename = base_filename.empty() ? 
            GenerateFilename(result, it->second->GetFileExtension()) :
            base_filename + "." + it->second->GetFileExtension();
        
        if (!OutputResults(result, format, filename)) {
            success = false;
        }
    }
    
    return success;
}

std::vector<std::string> OutputManager::GetAvailableFormats() const {
    std::vector<std::string> formats;
    for (const auto& [name, formatter] : formatters_) {
        formats.push_back(name);
    }
    return formats;
}

std::string OutputManager::GenerateFilename(const ScanResult& result, const std::string& extension) {
    auto time_t = std::chrono::system_clock::to_time_t(result.scan_start);
    std::ostringstream oss;
    oss << "hugin_" << result.target_ip << "_" 
        << std::put_time(std::localtime(&time_t), "%Y%m%d_%H%M%S") 
        << "." << extension;
    return oss.str();
}

bool OutputManager::WriteToFile(const std::string& content, const std::string& filepath) {
    std::ofstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Failed to open file for writing: " << filepath << std::endl;
        return false;
    }
    
    file << content;
    file.close();
    
    if (console_output_) {
        std::cout << "Output written to: " << filepath << std::endl;
    }
    
    return true;
}

void OutputManager::OutputToConsole(const std::string& content, const std::string& format_name) {
    if (format_name == "human") {
        std::cout << content;
    } else {
        std::cout << "=== " << format_name << " Output ===" << std::endl;
        std::cout << content << std::endl;
    }
}

// Compliance Reporter Implementation
ComplianceReporter::ComplianceReporter() {
    InitializePCIDSSRules();
    InitializeHIPAARules();
    InitializeSOXRules();
    InitializeNISTRules();
    InitializeISO27001Rules();
}

void ComplianceReporter::LoadComplianceRules(Standard standard) {
    (void)standard; // Suppress unused parameter warning
    // Rules are loaded in constructor
}

std::string ComplianceReporter::GenerateComplianceReport(const ScanResult& result, Standard standard) {
    std::ostringstream oss;
    
    oss << StandardToString(standard) << " Compliance Report\n";
    oss << std::string(50, '=') << "\n\n";
    
    oss << "Target: " << result.target_ip << "\n";
    auto time_t = std::chrono::system_clock::to_time_t(result.scan_start);
    oss << "Scan Date: " << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << "\n\n";
    
    std::vector<std::string> violations = CheckCompliance(result, standard);
    
    oss << "FINDINGS:\n";
    if (violations.empty()) {
        oss << "[PASS] No compliance violations detected\n";
    } else {
        for (const auto& violation : violations) {
            oss << "[FAIL] " << violation << "\n";
        }
    }
    
    oss << "\nRECOMMENDATIONS:\n";
    if (!violations.empty()) {
        oss << "- Review and remediate identified violations\n";
        oss << "- Implement proper firewall rules\n";
        oss << "- Ensure all services use encryption where required\n";
        oss << "- Regular compliance scanning recommended\n";
    } else {
        oss << "- Continue regular compliance monitoring\n";
        oss << "- Document current configuration for audit purposes\n";
    }
    
    return oss.str();
}

std::vector<std::string> ComplianceReporter::CheckCompliance(const ScanResult& result, Standard standard) {
    std::vector<std::string> violations;
    
    auto it = compliance_rules_.find(standard);
    if (it == compliance_rules_.end()) {
        return violations;
    }
    
    const auto& rules = it->second;
    
    for (const auto& port : result.ports) {
        if (port.state != "open") continue;
        
        // Check prohibited ports
        if (IsPortProhibited(port.port, rules)) {
            violations.push_back("Port " + std::to_string(port.port) + " (" + port.service + ") - Prohibited port is open");
        }
        
        // Check prohibited services
        if (IsServiceProhibited(port.service, rules)) {
            violations.push_back("Service " + port.service + " on port " + std::to_string(port.port) + " - Prohibited service detected");
        }
        
        // Check encryption requirements
        if (RequiresEncryption(port.port, rules) && !port.ssl_enabled) {
            violations.push_back("Port " + std::to_string(port.port) + " (" + port.service + ") - Encryption required but not detected");
        }
    }
    
    return violations;
}

void ComplianceReporter::InitializePCIDSSRules() {
    std::vector<ComplianceRule> pci_rules;
    
    ComplianceRule telnet_rule;
    telnet_rule.rule_id = "PCI-DSS-2.3";
    telnet_rule.description = "Encrypt all non-console administrative access";
    telnet_rule.prohibited_ports = {23}; // Telnet
    telnet_rule.require_encryption = true;
    pci_rules.push_back(telnet_rule);
    
    ComplianceRule web_encryption;
    web_encryption.rule_id = "PCI-DSS-4.1";
    web_encryption.description = "Use strong cryptography for transmission of cardholder data";
    web_encryption.prohibited_ports = {80}; // HTTP should redirect to HTTPS
    web_encryption.require_encryption = true;
    pci_rules.push_back(web_encryption);
    
    compliance_rules_[Standard::PCI_DSS] = pci_rules;
}

void ComplianceReporter::InitializeHIPAARules() {
    std::vector<ComplianceRule> hipaa_rules;
    
    ComplianceRule encryption_rule;
    encryption_rule.rule_id = "HIPAA-164.312";
    encryption_rule.description = "Encryption and decryption of PHI";
    encryption_rule.prohibited_ports = {21, 23, 80}; // FTP, Telnet, HTTP
    encryption_rule.require_encryption = true;
    hipaa_rules.push_back(encryption_rule);
    
    compliance_rules_[Standard::HIPAA] = hipaa_rules;
}

void ComplianceReporter::InitializeSOXRules() {
    std::vector<ComplianceRule> sox_rules;
    
    ComplianceRule access_control;
    access_control.rule_id = "SOX-404";
    access_control.description = "Internal control over financial reporting";
    access_control.prohibited_ports = {23, 135, 139, 445}; // Telnet, RPC, NetBIOS
    sox_rules.push_back(access_control);
    
    compliance_rules_[Standard::SOX] = sox_rules;
}

void ComplianceReporter::InitializeNISTRules() {
    std::vector<ComplianceRule> nist_rules;
    
    ComplianceRule crypto_rule;
    crypto_rule.rule_id = "NIST-800-53-SC-8";
    crypto_rule.description = "Transmission confidentiality and integrity";
    crypto_rule.prohibited_ports = {21, 23, 80, 110, 143}; // Unencrypted protocols
    crypto_rule.require_encryption = true;
    nist_rules.push_back(crypto_rule);
    
    compliance_rules_[Standard::NIST] = nist_rules;
}

void ComplianceReporter::InitializeISO27001Rules() {
    std::vector<ComplianceRule> iso_rules;
    
    ComplianceRule network_security;
    network_security.rule_id = "ISO-27001-A.13.1.1";
    network_security.description = "Network controls";
    network_security.prohibited_ports = {23, 69, 161}; // Telnet, TFTP, SNMP
    iso_rules.push_back(network_security);
    
    compliance_rules_[Standard::ISO27001] = iso_rules;
}

std::string ComplianceReporter::StandardToString(Standard standard) {
    switch (standard) {
        case Standard::PCI_DSS: return "PCI DSS";
        case Standard::HIPAA: return "HIPAA";
        case Standard::SOX: return "SOX";
        case Standard::NIST: return "NIST";
        case Standard::ISO27001: return "ISO 27001";
        default: return "Unknown";
    }
}

bool ComplianceReporter::IsPortProhibited(int port, const std::vector<ComplianceRule>& rules) {
    for (const auto& rule : rules) {
        if (std::find(rule.prohibited_ports.begin(), rule.prohibited_ports.end(), port) != rule.prohibited_ports.end()) {
            return true;
        }
    }
    return false;
}

bool ComplianceReporter::IsServiceProhibited(const std::string& service, const std::vector<ComplianceRule>& rules) {
    for (const auto& rule : rules) {
        if (std::find(rule.prohibited_services.begin(), rule.prohibited_services.end(), service) != rule.prohibited_services.end()) {
            return true;
        }
    }
    return false;
}

bool ComplianceReporter::RequiresEncryption(int port, const std::vector<ComplianceRule>& rules) {
    for (const auto& rule : rules) {
        if (rule.require_encryption && 
            std::find(rule.prohibited_ports.begin(), rule.prohibited_ports.end(), port) != rule.prohibited_ports.end()) {
            return true;
        }
    }
    return false;
}

// Vulnerability Correlator Implementation
VulnerabilityCorrelator::VulnerabilityCorrelator() {
    // Initialize with some sample vulnerability data
    VulnerabilityInfo ssh_vuln;
    ssh_vuln.cve_id = "CVE-2021-41617";
    ssh_vuln.description = "OpenSSH privilege escalation vulnerability";
    ssh_vuln.cvss_score = 7.0f;
    ssh_vuln.severity = "High";
    ssh_vuln.affected_services = {"ssh", "openssh"};
    ssh_vuln.affected_versions = {"8.0", "8.1", "8.2", "8.3", "8.4", "8.5", "8.6", "8.7"};
    vulnerability_db_.push_back(ssh_vuln);
}

bool VulnerabilityCorrelator::LoadVulnerabilityDatabase(const std::string& db_path) {
    (void)db_path; // Suppress unused parameter warning
    // In a real implementation, this would load from a CVE database file
    return true;
}

std::vector<VulnerabilityCorrelator::VulnerabilityInfo> VulnerabilityCorrelator::FindVulnerabilities(const ScanResult::PortResult& port) {
    std::vector<VulnerabilityInfo> matches;
    
    for (const auto& vuln : vulnerability_db_) {
        if (ServiceMatches(port.service, port.version, vuln)) {
            matches.push_back(vuln);
        }
    }
    
    return matches;
}

std::string VulnerabilityCorrelator::GenerateVulnerabilityReport(const ScanResult& result) {
    std::ostringstream oss;
    
    oss << "Vulnerability Assessment Report\n";
    oss << std::string(50, '=') << "\n\n";
    
    oss << "Target: " << result.target_ip << "\n";
    auto time_t = std::chrono::system_clock::to_time_t(result.scan_start);
    oss << "Scan Date: " << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << "\n\n";
    
    bool vulnerabilities_found = false;
    
    for (const auto& port : result.ports) {
        if (port.state != "open") continue;
        
        auto vulns = FindVulnerabilities(port);
        if (!vulns.empty()) {
            vulnerabilities_found = true;
            oss << "Port " << port.port << "/" << port.protocol << " (" << port.service << "):\n";
            
            for (const auto& vuln : vulns) {
                oss << "  [" << vuln.severity << "] " << vuln.cve_id << "\n";
                oss << "    Description: " << vuln.description << "\n";
                oss << "    CVSS Score: " << vuln.cvss_score << "\n\n";
            }
        }
    }
    
    if (!vulnerabilities_found) {
        oss << "No known vulnerabilities detected for the identified services.\n";
    }
    
    float risk_score = CalculateRiskScore(result);
    oss << "\nOverall Risk Score: " << std::fixed << std::setprecision(1) << risk_score << "/10.0\n";
    
    return oss.str();
}

float VulnerabilityCorrelator::CalculateRiskScore(const ScanResult& result) {
    float total_score = 0.0f;
    int vuln_count = 0;
    
    for (const auto& port : result.ports) {
        if (port.state != "open") continue;
        
        auto vulns = FindVulnerabilities(port);
        for (const auto& vuln : vulns) {
            total_score += vuln.cvss_score;
            vuln_count++;
        }
    }
    
    if (vuln_count == 0) return 0.0f;
    
    return std::min(10.0f, total_score / vuln_count);
}

bool VulnerabilityCorrelator::ServiceMatches(const std::string& service, const std::string& version, const VulnerabilityInfo& vuln) {
    // Check if service matches
    bool service_match = false;
    for (const auto& affected_service : vuln.affected_services) {
        if (service.find(affected_service) != std::string::npos) {
            service_match = true;
            break;
        }
    }
    
    if (!service_match) return false;
    
    // If no version info, assume vulnerable
    if (version.empty()) return true;
    
    // Check if version matches
    for (const auto& affected_version : vuln.affected_versions) {
        if (version.find(affected_version) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

std::string VulnerabilityCorrelator::SeverityFromCVSS(float cvss_score) {
    if (cvss_score >= 9.0f) return "Critical";
    if (cvss_score >= 7.0f) return "High";
    if (cvss_score >= 4.0f) return "Medium";
    if (cvss_score > 0.0f) return "Low";
    return "None";
}
