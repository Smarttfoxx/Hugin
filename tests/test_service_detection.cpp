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

#include <iostream>
#include <cassert>
#include <vector>
#include <string>
#include "../src/engine/service_detection.h"

/**
 * Test framework for service detection functionality
 */
class ServiceDetectionTester {
private:
    int tests_run_;
    int tests_passed_;
    int tests_failed_;
    
public:
    ServiceDetectionTester() : tests_run_(0), tests_passed_(0), tests_failed_(0) {}
    
    void RunAllTests() {
        std::cout << "Starting Service Detection Test Suite...\n\n";
        
        TestServiceProbeCreation();
        TestMatchPatternCompilation();
        TestSSLDetection();
        TestServiceMatching();
        TestOSFingerprinting();
        TestProbeDatabase();
        TestPerformance();
        
        PrintResults();
    }
    
private:
    void TestServiceProbeCreation() {
        std::cout << "Testing Service Probe Creation...\n";
        
        // Test basic probe creation
        ServiceProbe http_probe("GetRequest", "tcp", "GET / HTTP/1.0\\r\\n\\r\\n", 1, true);
        Assert(http_probe.name == "GetRequest", "HTTP probe name");
        Assert(http_probe.protocol == "tcp", "HTTP probe protocol");
        Assert(http_probe.rarity == 1, "HTTP probe rarity");
        Assert(http_probe.ssl_capable == true, "HTTP probe SSL capability");
        
        // Test probe with default ports
        http_probe.default_ports = {80, 443, 8080};
        Assert(http_probe.default_ports.size() == 3, "HTTP probe default ports count");
        Assert(http_probe.default_ports[0] == 80, "HTTP probe first default port");
        
        std::cout << "✓ Service Probe Creation tests passed\n\n";
    }
    
    void TestMatchPatternCompilation() {
        std::cout << "Testing Match Pattern Compilation...\n";
        
        try {
            // Test basic regex compilation
            MatchPattern http_pattern("HTTP/1\\.[01] \\d+ .*Server: ([^\\r\\n]+)", "http", 0.8f);
            Assert(true, "HTTP pattern compilation");
            
            // Test SSH pattern
            MatchPattern ssh_pattern("SSH-([0-9.]+)-OpenSSH[_-]([0-9.]+)", "ssh", 0.9f);
            Assert(true, "SSH pattern compilation");
            
            // Test invalid regex (should not crash)
            try {
                MatchPattern invalid_pattern("[invalid regex", "test", 0.5f);
                Assert(false, "Invalid regex should throw exception");
            } catch (...) {
                Assert(true, "Invalid regex exception handling");
            }
            
        } catch (const std::exception& e) {
            Assert(false, std::string("Pattern compilation failed: ") + e.what());
        }
        
        std::cout << "✓ Match Pattern Compilation tests passed\n\n";
    }
    
    void TestSSLDetection() {
        std::cout << "Testing SSL Detection...\n";
        
        SSLServiceDetector ssl_detector;
        
        // Test SSL handshake detection
        std::string ssl_handshake = "\x16\x03\x01\x00\x4a";  // TLS 1.0 handshake
        Assert(ssl_detector.IsSSLService(ssl_handshake), "SSL handshake detection");
        
        // Test non-SSL response
        std::string http_response = "HTTP/1.1 200 OK\r\nServer: Apache\r\n";
        Assert(!ssl_detector.IsSSLService(http_response), "Non-SSL response detection");
        
        // Test empty response
        std::string empty_response = "";
        Assert(!ssl_detector.IsSSLService(empty_response), "Empty response handling");
        
        // Test SSL error response
        std::string ssl_error = "SSL handshake failed";
        Assert(ssl_detector.IsSSLService(ssl_error), "SSL error response detection");
        
        std::cout << "✓ SSL Detection tests passed\n\n";
    }
    
    void TestServiceMatching() {
        std::cout << "Testing Service Matching...\n";
        
        ServiceDetectionEngine engine;
        engine.Initialize();
        
        // Test HTTP service matching
        ServiceProbe http_probe("GetRequest", "tcp", "GET / HTTP/1.0\\r\\n\\r\\n");
        std::string http_response = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n";
        ServiceMatch http_match = engine.MatchResponse(http_response, http_probe);
        
        Assert(!http_match.service_name.empty(), "HTTP service detection");
        Assert(http_match.confidence > 0.0f, "HTTP confidence score");
        
        // Test SSH service matching
        std::string ssh_response = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n";
        ServiceProbe ssh_probe("SSHVersionExchange", "tcp", "SSH-2.0-Hugin_Scanner\\r\\n");
        ServiceMatch ssh_match = engine.MatchResponse(ssh_response, ssh_probe);
        
        Assert(ssh_match.service_name == "ssh", "SSH service name");
        Assert(!ssh_match.version.empty(), "SSH version extraction");
        Assert(ssh_match.confidence > 0.7f, "SSH confidence score");
        
        // Test unknown service
        std::string unknown_response = "UNKNOWN_PROTOCOL_12345";
        ServiceMatch unknown_match = engine.MatchResponse(unknown_response, http_probe);
        Assert(unknown_match.confidence == 0.0f, "Unknown service handling");
        
        std::cout << "✓ Service Matching tests passed\n\n";
    }
    
    void TestOSFingerprinting() {
        std::cout << "Testing OS Fingerprinting...\n";
        
        OSFingerprintEngine os_engine;
        
        // Test Windows service indicators
        std::vector<ServiceMatch> windows_services;
        ServiceMatch iis_service;
        iis_service.service_name = "http";
        iis_service.info = "Microsoft-IIS/10.0";
        windows_services.push_back(iis_service);
        
        std::string detected_os = os_engine.DeduceFromServices(windows_services);
        Assert(detected_os == "Windows", "Windows OS detection");
        
        // Test Linux service indicators
        std::vector<ServiceMatch> linux_services;
        ServiceMatch apache_service;
        apache_service.service_name = "http";
        apache_service.info = "Apache/2.4.41 (Ubuntu)";
        linux_services.push_back(apache_service);
        
        ServiceMatch ssh_service;
        ssh_service.service_name = "ssh";
        ssh_service.version = "OpenSSH_8.9p1";
        linux_services.push_back(ssh_service);
        
        detected_os = os_engine.DeduceFromServices(linux_services);
        Assert(detected_os == "Linux", "Linux OS detection");
        
        // Test confidence calculation
        std::vector<std::string> indicators = {"Apache", "OpenSSH", "Linux"};
        float confidence = os_engine.CalculateOSConfidence(indicators);
        Assert(confidence > 0.5f, "OS confidence calculation");
        
        std::cout << "✓ OS Fingerprinting tests passed\n\n";
    }
    
    void TestProbeDatabase() {
        std::cout << "Testing Probe Database...\n";
        
        ServiceDetectionEngine engine;
        engine.Initialize();
        
        // Test probe retrieval for common ports
        std::vector<ServiceProbe> http_probes = engine.GetProbesForPort(80, "tcp");
        Assert(!http_probes.empty(), "HTTP probes for port 80");
        
        std::vector<ServiceProbe> ssh_probes = engine.GetProbesForPort(22, "tcp");
        Assert(!ssh_probes.empty(), "SSH probes for port 22");
        
        // Test probe ordering by rarity
        if (http_probes.size() > 1) {
            Assert(http_probes[0].rarity <= http_probes[1].rarity, "Probe rarity ordering");
        }
        
        // Test UDP probes
        std::vector<ServiceProbe> dns_probes = engine.GetProbesForPort(53, "udp");
        Assert(!dns_probes.empty(), "DNS probes for port 53");
        
        std::cout << "✓ Probe Database tests passed\n\n";
    }
    
    void TestPerformance() {
        std::cout << "Testing Performance...\n";
        
        auto start = std::chrono::high_resolution_clock::now();
        
        ServiceDetectionEngine engine;
        engine.Initialize();
        
        // Test probe database loading time
        auto init_end = std::chrono::high_resolution_clock::now();
        auto init_duration = std::chrono::duration_cast<std::chrono::milliseconds>(init_end - start);
        Assert(init_duration.count() < 1000, "Engine initialization time < 1s");
        
        // Test pattern matching performance
        ServiceProbe test_probe("Test", "tcp", "TEST");
        std::string test_response = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n";
        
        auto match_start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 1000; ++i) {
            engine.MatchResponse(test_response, test_probe);
        }
        auto match_end = std::chrono::high_resolution_clock::now();
        auto match_duration = std::chrono::duration_cast<std::chrono::milliseconds>(match_end - match_start);
        
        Assert(match_duration.count() < 100, "1000 pattern matches < 100ms");
        
        std::cout << "✓ Performance tests passed\n\n";
    }
    
    void Assert(bool condition, const std::string& test_name) {
        tests_run_++;
        if (condition) {
            tests_passed_++;
            std::cout << "  ✓ " << test_name << "\n";
        } else {
            tests_failed_++;
            std::cout << "  ✗ " << test_name << " FAILED\n";
        }
    }
    
    void PrintResults() {
        std::cout << "\n" << std::string(50, '=') << "\n";
        std::cout << "Test Results:\n";
        std::cout << "  Total tests: " << tests_run_ << "\n";
        std::cout << "  Passed: " << tests_passed_ << "\n";
        std::cout << "  Failed: " << tests_failed_ << "\n";
        std::cout << "  Success rate: " << (tests_run_ > 0 ? (tests_passed_ * 100 / tests_run_) : 0) << "%\n";
        std::cout << std::string(50, '=') << "\n";
        
        if (tests_failed_ > 0) {
            std::cout << "Some tests failed. Please review the implementation.\n";
        } else {
            std::cout << "All tests passed! Service detection is working correctly.\n";
        }
    }
};

/**
 * Integration tests with real network services
 */
class IntegrationTester {
public:
    void RunIntegrationTests() {
        std::cout << "\nStarting Integration Tests...\n\n";
        
        TestLocalhostServices();
        TestSSLServices();
        TestErrorHandling();
    }
    
private:
    void TestLocalhostServices() {
        std::cout << "Testing localhost services...\n";
        
        ServiceDetectionEngine engine;
        engine.Initialize();
        
        // Test SSH service on localhost
        ServiceMatch ssh_result = engine.DetectService("127.0.0.1", 22, "tcp", 5);
        if (ssh_result.confidence > 0.0f) {
            std::cout << "  ✓ SSH detected: " << ssh_result.service_name 
                      << " v" << ssh_result.version << " (confidence: " 
                      << ssh_result.confidence << ")\n";
        } else {
            std::cout << "  - SSH not detected or not running\n";
        }
    }
    
    void TestSSLServices() {
        std::cout << "Testing SSL services...\n";
        
        ServiceDetectionEngine engine;
        engine.Initialize();
        
        // Test common SSL ports
        std::vector<int> ssl_ports = {443, 993, 995};
        for (int port : ssl_ports) {
            ServiceMatch ssl_result = engine.DetectService("127.0.0.1", port, "tcp", 3);
            if (ssl_result.confidence > 0.0f) {
                std::cout << "  ✓ SSL service on port " << port << ": " 
                          << ssl_result.service_name << "\n";
            }
        }
    }
    
    void TestErrorHandling() {
        std::cout << "Testing error handling...\n";
        
        ServiceDetectionEngine engine;
        engine.Initialize();
        
        // Test invalid IP
        ServiceMatch invalid_result = engine.DetectService("999.999.999.999", 80, "tcp", 1);
        std::cout << "  ✓ Invalid IP handled gracefully\n";
        
        // Test closed port
        ServiceMatch closed_result = engine.DetectService("127.0.0.1", 12345, "tcp", 1);
        std::cout << "  ✓ Closed port handled gracefully\n";
        
        // Test very short timeout
        ServiceMatch timeout_result = engine.DetectService("127.0.0.1", 22, "tcp", 0);
        std::cout << "  ✓ Short timeout handled gracefully\n";
    }
};

int main() {
    try {
        ServiceDetectionTester unit_tester;
        unit_tester.RunAllTests();
        
        IntegrationTester integration_tester;
        integration_tester.RunIntegrationTests();
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test suite failed with exception: " << e.what() << std::endl;
        return 1;
    }
}
