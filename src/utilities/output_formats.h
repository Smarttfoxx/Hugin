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
#include <fstream>
#include "../engine/service_detection.h"

/**
 * Structured data representation for scan results
 */
struct ScanResult {
    std::string target_ip;
    std::string hostname;
    bool host_up;
    std::string os_detection;
    float os_confidence;
    std::chrono::system_clock::time_point scan_start;
    std::chrono::system_clock::time_point scan_end;
    int total_ports_scanned;
    
    struct PortResult {
        int port;
        std::string protocol;
        std::string state;
        std::string service;
        std::string version;
        std::string info;
        std::string cpe;
        float confidence;
        bool ssl_enabled;
        std::string ssl_version;
        std::string ssl_cipher;
        std::vector<std::string> ssl_cert_info;
    };
    
    std::vector<PortResult> ports;
    
    // Scan statistics
    struct Statistics {
        int open_ports = 0;
        int closed_ports = 0;
        int filtered_ports = 0;
        int services_detected = 0;
        int ssl_services = 0;
        double scan_duration_seconds = 0.0;
        double average_port_time_ms = 0.0;
    } stats;
};

/**
 * Output format generators
 */
class OutputFormatter {
public:
    virtual ~OutputFormatter() = default;
    virtual std::string Format(const ScanResult& result) = 0;
    virtual std::string GetFileExtension() const = 0;
    virtual std::string GetMimeType() const = 0;
};

/**
 * Human-readable console output (default Hugin format)
 */
class HumanReadableFormatter : public OutputFormatter {
public:
    std::string Format(const ScanResult& result) override;
    std::string GetFileExtension() const override { return "txt"; }
    std::string GetMimeType() const override { return "text/plain"; }
    
private:
    std::string FormatPortTable(const std::vector<ScanResult::PortResult>& ports);
    std::string FormatScanSummary(const ScanResult& result);
};

/**
 * JSON output format for API integration
 */
class JSONFormatter : public OutputFormatter {
public:
    std::string Format(const ScanResult& result) override;
    std::string GetFileExtension() const override { return "json"; }
    std::string GetMimeType() const override { return "application/json"; }
    
private:
    std::string EscapeJSON(const std::string& input);
    std::string FormatTimestamp(const std::chrono::system_clock::time_point& time);
};

/**
 * XML output format (nmap-compatible)
 */
class XMLFormatter : public OutputFormatter {
public:
    std::string Format(const ScanResult& result) override;
    std::string GetFileExtension() const override { return "xml"; }
    std::string GetMimeType() const override { return "application/xml"; }
    
private:
    std::string EscapeXML(const std::string& input);
    std::string FormatTimestamp(const std::chrono::system_clock::time_point& time);
};

/**
 * CSV output format for spreadsheet analysis
 */
class CSVFormatter : public OutputFormatter {
public:
    std::string Format(const ScanResult& result) override;
    std::string GetFileExtension() const override { return "csv"; }
    std::string GetMimeType() const override { return "text/csv"; }
    
private:
    std::string EscapeCSV(const std::string& input);
};

/**
 * Greppable output format (similar to nmap -oG)
 */
class GreppableFormatter : public OutputFormatter {
public:
    std::string Format(const ScanResult& result) override;
    std::string GetFileExtension() const override { return "gnmap"; }
    std::string GetMimeType() const override { return "text/plain"; }
};

/**
 * Output manager for handling multiple formats and file operations
 */
class OutputManager {
private:
    std::unordered_map<std::string, std::unique_ptr<OutputFormatter>> formatters_;
    std::string output_directory_;
    bool console_output_;
    
public:
    OutputManager(const std::string& output_dir = "", bool console = true);
    
    void RegisterFormatter(const std::string& name, std::unique_ptr<OutputFormatter> formatter);
    void SetOutputDirectory(const std::string& directory);
    void EnableConsoleOutput(bool enable);
    
    bool OutputResults(const ScanResult& result, const std::string& format_name, 
                      const std::string& filename = "");
    bool OutputResults(const ScanResult& result, const std::vector<std::string>& formats,
                      const std::string& base_filename = "");
    
    std::vector<std::string> GetAvailableFormats() const;
    
private:
    std::string GenerateFilename(const ScanResult& result, const std::string& extension);
    bool WriteToFile(const std::string& content, const std::string& filepath);
    void OutputToConsole(const std::string& content, const std::string& format_name);
};

/**
 * Compliance reporting for regulatory standards
 */
class ComplianceReporter {
public:
    enum class Standard {
        PCI_DSS,
        HIPAA,
        SOX,
        NIST,
        ISO27001
    };
    
private:
    struct ComplianceRule {
        std::string rule_id;
        std::string description;
        std::vector<int> prohibited_ports;
        std::vector<std::string> required_services;
        std::vector<std::string> prohibited_services;
        bool require_encryption;
    };
    
    std::unordered_map<Standard, std::vector<ComplianceRule>> compliance_rules_;
    
public:
    ComplianceReporter();
    
    void LoadComplianceRules(Standard standard);
    std::string GenerateComplianceReport(const ScanResult& result, Standard standard);
    std::vector<std::string> CheckCompliance(const ScanResult& result, Standard standard);
    
private:
    void InitializePCIDSSRules();
    void InitializeHIPAARules();
    void InitializeSOXRules();
    void InitializeNISTRules();
    void InitializeISO27001Rules();
    
    std::string StandardToString(Standard standard);
    bool IsPortProhibited(int port, const std::vector<ComplianceRule>& rules);
    bool IsServiceProhibited(const std::string& service, const std::vector<ComplianceRule>& rules);
    bool RequiresEncryption(int port, const std::vector<ComplianceRule>& rules);
};

/**
 * Vulnerability correlation and risk assessment
 */
class VulnerabilityCorrelator {
private:
    struct VulnerabilityInfo {
        std::string cve_id;
        std::string description;
        float cvss_score;
        std::string severity;
        std::vector<std::string> affected_services;
        std::vector<std::string> affected_versions;
    };
    
    std::vector<VulnerabilityInfo> vulnerability_db_;
    
public:
    VulnerabilityCorrelator();
    
    bool LoadVulnerabilityDatabase(const std::string& db_path);
    std::vector<VulnerabilityInfo> FindVulnerabilities(const ScanResult::PortResult& port);
    std::string GenerateVulnerabilityReport(const ScanResult& result);
    float CalculateRiskScore(const ScanResult& result);
    
private:
    bool ServiceMatches(const std::string& service, const std::string& version, 
                       const VulnerabilityInfo& vuln);
    std::string SeverityFromCVSS(float cvss_score);
};

// Global output manager instance
extern std::unique_ptr<OutputManager> output_manager;
extern std::unique_ptr<ComplianceReporter> compliance_reporter;
extern std::unique_ptr<VulnerabilityCorrelator> vulnerability_correlator;
