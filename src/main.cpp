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

// C++ libraries
#include <chrono>
#include <mutex>
#include <functional>
#include <unistd.h>

// Custom libraries
#include "interfaces/visuals.h"
#include "engine/scan_engine.h"
#include "engine/service_detection.h"
#include "engine/ad_detection.h"
#include "engine/intelligent_service_detection.h"
#include "cli/arg_parser.h"
#include "utilities/helper_functions.h"
#include "utilities/log_system.h"
#include "utilities/nmap_parser.h"

int main(int argc, char* argv[]) {

    if (getuid() != 0) {
        logsys.Warning("Hugin should be executed with sudo privileges. Exiting...");
        return 1;
    }

    ProgramConfig config;
    std::mutex result_mutex;
    std::atomic<int> scannedPortsCount{0}, scannedServicesCount{0};

    RenderBanner();

    // --- Argument Parsing ---
    if (!ParseArguments(argc, argv, config)) {
        return 1;
    }

    // --- Web Interface Mode ---
    if (config.enableWebInterface) {
        logsys.Info("Starting Hugin Web Interface...");
        logsys.Info("Port:", config.webPort);
        logsys.Info("SSL:", config.enableSSL ? "Enabled" : "Disabled");
        logsys.Info("Access URL:", config.enableSSL ? "https" : "http", "://localhost:" + std::to_string(config.webPort));
        logsys.Info("Press Ctrl+C to stop the web interface");
        
        // TODO: Start web server here
        logsys.Warning("Web interface is not yet fully implemented");
        logsys.Info("This feature will be available in a future release");
        return 0;
    }

    // --- Host Discovery Phase ---
    for (const HostInstance& HostObject : config.HostInstances) {
        if (!IsValidIP(HostObject.ipValue)) {
            logsys.Warning("Invalid address was provided.");
            return 1;
        }

        if (config.enableARPScan) {
            if (IsHostUpARP(HostObject.ipValue, config.networkInterface))
                logsys.Info("The host", HostObject.ipValue, "is up");
            else
                logsys.Warning("The host is down.");

        // Fallback to default ICMP check
        } else if (!config.isHostUp) {
            if (IsHostUpICMP(HostObject.ipValue))
                logsys.Info("The host", HostObject.ipValue, "is up");
            else
                logsys.Warning("The host is down or blocking ICMP. Continuing anyways...");
        }
    }

    if (config.portsToScan.empty()) {
        config.portsToScan = common_ports_thousand;
    }

    ThreadPool pool(config.threadAmount);
    auto scanStartTime = std::chrono::steady_clock::now();
    auto NmapUdpPayloads = ParseNmapPayloads("/usr/share/hugin/nmap/nmap-payloads.txt");

    #ifdef DEBUG
    if (config.enableUDPScan) {
        for (const auto& [port, payloads] : NmapUdpPayloads) {
            std::cout << "Loaded payloads for UDP port " << port << ":\n";
            for (const auto& payload : payloads) {
                std::cout << "  -> " << std::hex;
                for (unsigned char c : payload)
                    std::cout << "\\x" << std::setw(2) << std::setfill('0') << static_cast<int>(c);
                std::cout << std::dec << "\n";
            }
        }
    }
    #endif

    logsys.Info("Using a total of", config.threadAmount, "threads for the scan.");

    // --- Port Scanning Phase ---
    for (HostInstance& HostObject : config.HostInstances) {
        auto pOpenPorts = &HostObject.openPorts;

        logsys.Info("Scanning for open ports on host", HostObject.ipValue);

        // TCP connect scan (parallelized)
        if (config.enableTCPConnectScan) {
            logsys.Info("Scanning", config.portsToScan.size(), "ports via TCP Connect.");

            for (int port : config.portsToScan) {
                pool.enqueue([=, &result_mutex, &scannedPortsCount, &config]() {
                    bool isPortOpen = PortScanTCPConnect(HostObject.ipValue, port, config.portScan_timeout);
                    if (isPortOpen) {
                        std::lock_guard<std::mutex> lock(result_mutex);
                        pOpenPorts->push_back(port);
                        config.isHostUp = true;
                    }
                    ++scannedPortsCount;
                });
            }

            // Wait for all ports to be scanned
            while (scannedPortsCount.load() < static_cast<int>(config.portsToScan.size()))
                ts.SleepMilliseconds(500);

            scannedPortsCount = 0;

        // UDP port scan
        } else if (config.enableUDPScan) {
            int totalUdpTasks = 0;

            for (int port : config.portsToScan) {
                // Use NMAP UDP payloads if available
                if (NmapUdpPayloads.count(port)) {
                    for (const auto& payload : NmapUdpPayloads[port]) {
                        ++totalUdpTasks;
                        pool.enqueue([=, &result_mutex, &scannedPortsCount, &config]() {
                            if (SendNmapUDPPayload(HostObject.ipValue, port, payload, config.portScan_timeout)) {
                                std::lock_guard<std::mutex> lock(result_mutex);
                                pOpenPorts->push_back(port);
                                config.isHostUp = true;
                            }

                            #ifdef DEBUG
                            {
                                std::ostringstream oss;
                                oss << "Sending payload to " << HostObject.ipValue << ":" << port << " -> ";
                                for (unsigned char c : payload)
                                    oss << "\\x" << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(c);
                                oss << std::dec;
                                std::cout << oss.str();
                            }
                            #endif

                            ++scannedPortsCount;
                        });
                    }
                }
            }

            // Wait for all ports to be scanned
            while (scannedPortsCount.load() < totalUdpTasks)
                ts.SleepMilliseconds(500);

            scannedPortsCount = 0;
        } else {
            // TCP SYN scan (batch-based)
            std::vector<int> openPort = PortScanTCPSyn(HostObject.ipValue, config.portsToScan, config.portScan_timeout);

            logsys.Info("Scanning", config.portsToScan.size(), "ports via SYN.");

            if (!openPort.empty()) {
                std::lock_guard<std::mutex> lock(result_mutex);
                pOpenPorts->insert(pOpenPorts->end(), openPort.begin(), openPort.end());
                config.isHostUp = true;

                for (int port : openPort)
                    logsys.NewEvent("Found open port", (std::to_string(port) + "/tcp on host"), HostObject.ipValue);
            } else
                logsys.Warning("No open ports found via SYN.");
        }

        if (!config.isHostUp)
            logsys.Warning("No open ports were found, is the host online?");

        // --- Enhanced Service Detection ---   
        if ((config.enableFindService || config.enableLUA) && !(HostObject.openPorts.empty())) {
            auto portServiceMap = ParseNmapServices("/usr/share/hugin/nmap/nmap-services.txt", "tcp");
            
            // Initialize the intelligent service detection engine
            IntelligentServiceDetector intelligentDetector;
            intelligentDetector.LoadNmapPayloads("nmap-payloads.txt");
            
            std::cout << "\n";
            logsys.Info("Starting enhanced service detection on host", HostObject.ipValue);
            
            std::cout << std::left;
            std::cout << std::setw(12) << "PORT" << std::setw(8) << "STATE" 
                      << std::setw(20) << "SERVICE" << std::setw(50) << "VERSION" 
                      << "INFO\n";
            
            // Use intelligent service detection for all open ports
            std::vector<uint16_t> ports_uint16;
            for (int port : HostObject.openPorts) {
                ports_uint16.push_back(static_cast<uint16_t>(port));
            }
            
            auto serviceResults = intelligentDetector.DetectServices(HostObject.ipValue, ports_uint16, config.servScan_timeout);
            
            // Collect all service detection results for OS fingerprinting
            std::vector<ServiceMatch> allServiceMatches;
            
            // Display results
            for (int port : HostObject.openPorts) {
                auto it = serviceResults.find(static_cast<uint16_t>(port));
                if (it != serviceResults.end()) {
                    const ServiceMatch& match = it->second;
                    
                    std::string serviceName = match.service_name.empty() ? "unknown" : match.service_name;
                    std::string serviceVersion = match.version.empty() ? "N/A" : match.version;
                    std::string serviceInfo = match.info;
                    
                    // Store for OS detection
                    if (match.confidence > 0.0f) {
                        allServiceMatches.push_back(match);
                    }
                    
                    // Calculate dynamic spacing based on VERSION length
                    int versionWidth = std::max(50, static_cast<int>(serviceVersion.length()) + 5);
                    
                    std::cout << std::setw(12) << (std::to_string(port) + "/tcp") 
                            << std::setw(8) << "open" 
                            << std::setw(20) << serviceName
                            << std::setw(versionWidth) << serviceVersion;
                    
                    if (!serviceInfo.empty()) {
                        std::cout << serviceInfo;
                    }
                    std::cout << "\n";
                } else {
                    // Fallback for ports not detected
                    std::string serviceName = "unknown";
                    if (portServiceMap.count(port)) {
                        serviceName = portServiceMap[port];
                    }
                    
                    std::cout << std::setw(12) << (std::to_string(port) + "/tcp") 
                            << std::setw(8) << "open" 
                            << std::setw(20) << serviceName
                            << std::setw(50) << "N/A"
                            << "\n";
                }
            }

            // Handle Lua scripts if enabled
            if (config.enableLUA) {
                for (int port : HostObject.openPorts) {
                    for (const std::string& script : config.luaScripts) {
                        logsys.Info("Running script", script, "on", HostObject.ipValue, "port", port);
                        RunLuaScript(script, HostObject.ipValue, port);
                    }
                }
            }
            
            // Perform OS detection based on service fingerprints
            if (!allServiceMatches.empty()) {
                // Create a temporary service engine for OS detection
                ServiceDetectionEngine tempEngine;
                tempEngine.Initialize();
                std::string detectedOS = tempEngine.DetectOperatingSystem(HostObject.ipValue, allServiceMatches);
                if (detectedOS != "Unknown") {
                    std::cout << "\nOS Detection: " << detectedOS << "\n";
                    logsys.Info("Detected operating system:", detectedOS);
                }
            }
        }
    }

    // --- Scan Summary ---
    auto scanEndTime = std::chrono::steady_clock::now();
    auto scanElapsedTime = std::chrono::duration_cast<std::chrono::seconds>(scanEndTime - scanStartTime).count();

    std::cout << "\n";
    logsys.Info("Scan completed in", scanElapsedTime, "seconds.");
    logsys.Info("A total of", config.portsToScan.size(), "ports were scanned.");

    return 0;
}