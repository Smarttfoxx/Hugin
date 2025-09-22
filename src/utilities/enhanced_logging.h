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
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <mutex>
#include <memory>

enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3,
    CRITICAL = 4
};

enum class OutputFormat {
    HUMAN_READABLE,
    JSON,
    XML,
    CSV
};

/**
 * Enhanced logging system with structured output and audit trails
 */
class EnhancedLogger {
private:
    LogLevel min_level_;
    std::unique_ptr<std::ofstream> log_file_;
    std::mutex log_mutex_;
    bool console_output_;
    bool file_output_;
    OutputFormat output_format_;
    
public:
    EnhancedLogger(LogLevel min_level = LogLevel::INFO, 
                   bool console = true, 
                   const std::string& log_file = "");
    ~EnhancedLogger();
    
    void SetLogLevel(LogLevel level);
    void SetOutputFormat(OutputFormat format);
    void EnableFileLogging(const std::string& filename);
    void DisableFileLogging();
    
    template<typename... Args>
    void Log(LogLevel level, const std::string& message, Args&&... args);
    
    template<typename... Args>
    void Debug(const std::string& message, Args&&... args);
    
    template<typename... Args>
    void Info(const std::string& message, Args&&... args);
    
    template<typename... Args>
    void Warning(const std::string& message, Args&&... args);
    
    template<typename... Args>
    void Error(const std::string& message, Args&&... args);
    
    template<typename... Args>
    void Critical(const std::string& message, Args&&... args);
    
    // Structured logging for scan events
    void LogScanStart(const std::string& target, const std::vector<int>& ports);
    void LogScanComplete(const std::string& target, int duration_seconds, int ports_scanned);
    void LogPortFound(const std::string& target, int port, const std::string& protocol, const std::string& state);
    void LogServiceDetected(const std::string& target, int port, const std::string& service, 
                           const std::string& version, float confidence);
    void LogOSDetected(const std::string& target, const std::string& os, float confidence);
    void LogError(const std::string& component, const std::string& error_message, const std::string& context = "");
    
private:
    std::string GetTimestamp();
    std::string LevelToString(LogLevel level);
    std::string FormatMessage(LogLevel level, const std::string& message);
    std::string FormatJSON(LogLevel level, const std::string& message, const std::string& component = "");
    std::string FormatXML(LogLevel level, const std::string& message, const std::string& component = "");
    
    template<typename T>
    std::string ToString(T&& value);
    
    template<typename T, typename... Args>
    std::string BuildMessage(const std::string& format, T&& first, Args&&... args);
    
    std::string BuildMessage(const std::string& format);
};

/**
 * Exception classes for better error handling
 */
class HuginException : public std::exception {
protected:
    std::string message_;
    std::string component_;
    
public:
    HuginException(const std::string& message, const std::string& component = "")
        : message_(message), component_(component) {}
    
    virtual const char* what() const noexcept override {
        return message_.c_str();
    }
    
    const std::string& GetComponent() const { return component_; }
};

class NetworkException : public HuginException {
public:
    NetworkException(const std::string& message, const std::string& component = "Network")
        : HuginException(message, component) {}
};

class ServiceDetectionException : public HuginException {
public:
    ServiceDetectionException(const std::string& message, const std::string& component = "ServiceDetection")
        : HuginException(message, component) {}
};

class ConfigurationException : public HuginException {
public:
    ConfigurationException(const std::string& message, const std::string& component = "Configuration")
        : HuginException(message, component) {}
};

/**
 * Performance monitoring and metrics collection
 */
class PerformanceMonitor {
private:
    std::chrono::steady_clock::time_point start_time_;
    std::mutex metrics_mutex_;
    
    struct ScanMetrics {
        int total_ports_scanned = 0;
        int open_ports_found = 0;
        int services_detected = 0;
        int ssl_services_detected = 0;
        int scan_duration_ms = 0;
        float average_port_scan_time_ms = 0.0f;
        float service_detection_accuracy = 0.0f;
    } metrics_;
    
public:
    PerformanceMonitor();
    
    void StartScan();
    void EndScan();
    void RecordPortScanned();
    void RecordOpenPort();
    void RecordServiceDetected(float confidence);
    void RecordSSLService();
    
    ScanMetrics GetMetrics() const;
    void ResetMetrics();
    void LogPerformanceReport(EnhancedLogger& logger);
    
    // Performance optimization suggestions
    std::vector<std::string> GetOptimizationSuggestions() const;
};

// Global enhanced logger instance
extern std::unique_ptr<EnhancedLogger> enhanced_logger;
extern std::unique_ptr<PerformanceMonitor> performance_monitor;

// Convenience macros for enhanced logging
#define LOG_DEBUG(msg, ...) if(enhanced_logger) enhanced_logger->Debug(msg, ##__VA_ARGS__)
#define LOG_INFO(msg, ...) if(enhanced_logger) enhanced_logger->Info(msg, ##__VA_ARGS__)
#define LOG_WARNING(msg, ...) if(enhanced_logger) enhanced_logger->Warning(msg, ##__VA_ARGS__)
#define LOG_ERROR(msg, ...) if(enhanced_logger) enhanced_logger->Error(msg, ##__VA_ARGS__)
#define LOG_CRITICAL(msg, ...) if(enhanced_logger) enhanced_logger->Critical(msg, ##__VA_ARGS__)

// Exception handling macros
#define THROW_NETWORK_ERROR(msg) throw NetworkException(msg, __FUNCTION__)
#define THROW_SERVICE_ERROR(msg) throw ServiceDetectionException(msg, __FUNCTION__)
#define THROW_CONFIG_ERROR(msg) throw ConfigurationException(msg, __FUNCTION__)

// Performance monitoring macros
#define PERF_START_SCAN() if(performance_monitor) performance_monitor->StartScan()
#define PERF_END_SCAN() if(performance_monitor) performance_monitor->EndScan()
#define PERF_RECORD_PORT() if(performance_monitor) performance_monitor->RecordPortScanned()
#define PERF_RECORD_OPEN_PORT() if(performance_monitor) performance_monitor->RecordOpenPort()
#define PERF_RECORD_SERVICE(conf) if(performance_monitor) performance_monitor->RecordServiceDetected(conf)
#define PERF_RECORD_SSL() if(performance_monitor) performance_monitor->RecordSSLService()
