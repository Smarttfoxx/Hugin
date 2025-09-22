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

#include "enhanced_logging.h"
#include <iostream>
#include <ctime>

// Global instances
std::unique_ptr<EnhancedLogger> enhanced_logger = nullptr;
std::unique_ptr<PerformanceMonitor> performance_monitor = nullptr;

// Enhanced Logger Implementation
EnhancedLogger::EnhancedLogger(LogLevel min_level, bool console, const std::string& log_file)
    : min_level_(min_level), console_output_(console), file_output_(false), output_format_(OutputFormat::HUMAN_READABLE) {
    
    if (!log_file.empty()) {
        EnableFileLogging(log_file);
    }
}

EnhancedLogger::~EnhancedLogger() {
    if (log_file_) {
        log_file_->close();
    }
}

void EnhancedLogger::SetLogLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    min_level_ = level;
}

void EnhancedLogger::SetOutputFormat(OutputFormat format) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    output_format_ = format;
}

void EnhancedLogger::EnableFileLogging(const std::string& filename) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    log_file_ = std::make_unique<std::ofstream>(filename, std::ios::app);
    file_output_ = log_file_->is_open();
}

void EnhancedLogger::DisableFileLogging() {
    std::lock_guard<std::mutex> lock(log_mutex_);
    if (log_file_) {
        log_file_->close();
        log_file_.reset();
    }
    file_output_ = false;
}

template<typename... Args>
void EnhancedLogger::Log(LogLevel level, const std::string& message, Args&&... args) {
    if (level < min_level_) return;
    
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    std::string formatted_message = BuildMessage(message, std::forward<Args>(args)...);
    std::string output;
    
    switch (output_format_) {
        case OutputFormat::JSON:
            output = FormatJSON(level, formatted_message);
            break;
        case OutputFormat::XML:
            output = FormatXML(level, formatted_message);
            break;
        default:
            output = FormatMessage(level, formatted_message);
            break;
    }
    
    if (console_output_) {
        std::cout << output << std::endl;
    }
    
    if (file_output_ && log_file_) {
        *log_file_ << output << std::endl;
        log_file_->flush();
    }
}

template<typename... Args>
void EnhancedLogger::Debug(const std::string& message, Args&&... args) {
    Log(LogLevel::DEBUG, message, std::forward<Args>(args)...);
}

template<typename... Args>
void EnhancedLogger::Info(const std::string& message, Args&&... args) {
    Log(LogLevel::INFO, message, std::forward<Args>(args)...);
}

template<typename... Args>
void EnhancedLogger::Warning(const std::string& message, Args&&... args) {
    Log(LogLevel::WARNING, message, std::forward<Args>(args)...);
}

template<typename... Args>
void EnhancedLogger::Error(const std::string& message, Args&&... args) {
    Log(LogLevel::ERROR, message, std::forward<Args>(args)...);
}

template<typename... Args>
void EnhancedLogger::Critical(const std::string& message, Args&&... args) {
    Log(LogLevel::CRITICAL, message, std::forward<Args>(args)...);
}

void EnhancedLogger::LogScanStart(const std::string& target, const std::vector<int>& ports) {
    std::ostringstream oss;
    oss << "Scan started for target " << target << " with " << ports.size() << " ports";
    Log(LogLevel::INFO, oss.str());
}

void EnhancedLogger::LogScanComplete(const std::string& target, int duration_seconds, int ports_scanned) {
    std::ostringstream oss;
    oss << "Scan completed for target " << target << " in " << duration_seconds 
        << " seconds, " << ports_scanned << " ports scanned";
    Log(LogLevel::INFO, oss.str());
}

void EnhancedLogger::LogPortFound(const std::string& target, int port, const std::string& protocol, const std::string& state) {
    std::ostringstream oss;
    oss << "Port " << port << "/" << protocol << " " << state << " on " << target;
    Log(LogLevel::INFO, oss.str());
}

void EnhancedLogger::LogServiceDetected(const std::string& target, int port, const std::string& service, 
                                       const std::string& version, float confidence) {
    std::ostringstream oss;
    oss << "Service detected on " << target << ":" << port << " - " << service;
    if (!version.empty()) {
        oss << " v" << version;
    }
    oss << " (confidence: " << std::fixed << std::setprecision(2) << confidence << ")";
    Log(LogLevel::INFO, oss.str());
}

void EnhancedLogger::LogOSDetected(const std::string& target, const std::string& os, float confidence) {
    std::ostringstream oss;
    oss << "OS detected for " << target << ": " << os 
        << " (confidence: " << std::fixed << std::setprecision(2) << confidence << ")";
    Log(LogLevel::INFO, oss.str());
}

void EnhancedLogger::LogError(const std::string& component, const std::string& error_message, const std::string& context) {
    std::ostringstream oss;
    oss << "[" << component << "] " << error_message;
    if (!context.empty()) {
        oss << " - Context: " << context;
    }
    Log(LogLevel::ERROR, oss.str());
}

std::string EnhancedLogger::GetTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    oss << "." << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}

std::string EnhancedLogger::LevelToString(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARNING";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

std::string EnhancedLogger::FormatMessage(LogLevel level, const std::string& message) {
    std::ostringstream oss;
    oss << "[" << GetTimestamp() << "] [" << LevelToString(level) << "] " << message;
    return oss.str();
}

std::string EnhancedLogger::FormatJSON(LogLevel level, const std::string& message, const std::string& component) {
    std::ostringstream oss;
    oss << "{";
    oss << "\"timestamp\":\"" << GetTimestamp() << "\",";
    oss << "\"level\":\"" << LevelToString(level) << "\",";
    oss << "\"message\":\"" << message << "\"";
    if (!component.empty()) {
        oss << ",\"component\":\"" << component << "\"";
    }
    oss << "}";
    return oss.str();
}

std::string EnhancedLogger::FormatXML(LogLevel level, const std::string& message, const std::string& component) {
    std::ostringstream oss;
    oss << "<log>";
    oss << "<timestamp>" << GetTimestamp() << "</timestamp>";
    oss << "<level>" << LevelToString(level) << "</level>";
    oss << "<message>" << message << "</message>";
    if (!component.empty()) {
        oss << "<component>" << component << "</component>";
    }
    oss << "</log>";
    return oss.str();
}

template<typename T>
std::string EnhancedLogger::ToString(T&& value) {
    std::ostringstream oss;
    oss << value;
    return oss.str();
}

template<typename T, typename... Args>
std::string EnhancedLogger::BuildMessage(const std::string& format, T&& first, Args&&... args) {
    std::string result = format;
    std::string placeholder = "{}";
    size_t pos = result.find(placeholder);
    if (pos != std::string::npos) {
        result.replace(pos, placeholder.length(), ToString(std::forward<T>(first)));
        return BuildMessage(result, std::forward<Args>(args)...);
    }
    return result;
}

std::string EnhancedLogger::BuildMessage(const std::string& format) {
    return format;
}

// Performance Monitor Implementation
PerformanceMonitor::PerformanceMonitor() {
    ResetMetrics();
}

void PerformanceMonitor::StartScan() {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    start_time_ = std::chrono::steady_clock::now();
    ResetMetrics();
}

void PerformanceMonitor::EndScan() {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time_);
    metrics_.scan_duration_ms = duration.count();
    
    if (metrics_.total_ports_scanned > 0) {
        metrics_.average_port_scan_time_ms = 
            static_cast<float>(metrics_.scan_duration_ms) / metrics_.total_ports_scanned;
    }
}

void PerformanceMonitor::RecordPortScanned() {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    metrics_.total_ports_scanned++;
}

void PerformanceMonitor::RecordOpenPort() {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    metrics_.open_ports_found++;
}

void PerformanceMonitor::RecordServiceDetected(float confidence) {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    metrics_.services_detected++;
    
    // Update running average of service detection accuracy
    float total_confidence = metrics_.service_detection_accuracy * (metrics_.services_detected - 1) + confidence;
    metrics_.service_detection_accuracy = total_confidence / metrics_.services_detected;
}

void PerformanceMonitor::RecordSSLService() {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    metrics_.ssl_services_detected++;
}

PerformanceMonitor::ScanMetrics PerformanceMonitor::GetMetrics() const {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    return metrics_;
}

void PerformanceMonitor::ResetMetrics() {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    metrics_ = ScanMetrics{};
}

void PerformanceMonitor::LogPerformanceReport(EnhancedLogger& logger) {
    auto metrics = GetMetrics();
    
    logger.Info("=== Performance Report ===");
    logger.Info("Scan Duration: {} ms", metrics.scan_duration_ms);
    logger.Info("Ports Scanned: {}", metrics.total_ports_scanned);
    logger.Info("Open Ports Found: {}", metrics.open_ports_found);
    logger.Info("Services Detected: {}", metrics.services_detected);
    logger.Info("SSL Services: {}", metrics.ssl_services_detected);
    logger.Info("Average Port Time: {:.2f} ms", metrics.average_port_scan_time_ms);
    logger.Info("Service Detection Accuracy: {:.2f}%", metrics.service_detection_accuracy * 100);
}

std::vector<std::string> PerformanceMonitor::GetOptimizationSuggestions() const {
    auto metrics = GetMetrics();
    std::vector<std::string> suggestions;
    
    if (metrics.average_port_scan_time_ms > 10.0f) {
        suggestions.push_back("Consider reducing timeout values for faster scanning");
    }
    
    if (metrics.service_detection_accuracy < 0.7f) {
        suggestions.push_back("Consider increasing service detection timeout for better accuracy");
    }
    
    if (metrics.total_ports_scanned > 10000 && metrics.average_port_scan_time_ms > 5.0f) {
        suggestions.push_back("For large scans, consider using targeted port lists");
    }
    
    if (metrics.ssl_services_detected > 0 && metrics.services_detected > 0) {
        float ssl_ratio = static_cast<float>(metrics.ssl_services_detected) / metrics.services_detected;
        if (ssl_ratio > 0.5f) {
            suggestions.push_back("High SSL usage detected - consider enabling SSL-specific optimizations");
        }
    }
    
    return suggestions;
}

// Explicit template instantiations for common types
template void EnhancedLogger::Log<>(LogLevel, const std::string&);
template void EnhancedLogger::Log<int>(LogLevel, const std::string&, int&&);
template void EnhancedLogger::Log<float>(LogLevel, const std::string&, float&&);
template void EnhancedLogger::Log<std::string>(LogLevel, const std::string&, std::string&&);

template void EnhancedLogger::Debug<>(const std::string&);
template void EnhancedLogger::Info<>(const std::string&);
template void EnhancedLogger::Warning<>(const std::string&);
template void EnhancedLogger::Error<>(const std::string&);
template void EnhancedLogger::Critical<>(const std::string&);
