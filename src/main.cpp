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
#include <mutex>
#include <functional>
#include <unistd.h>

// Custom libraries
#include "interfaces/visuals.h"
#include "engine/scan_engine.h"
#include "cli/arg_parser.h"
#include "utilities/helper_functions.h"
#include "utilities/log_system.h"
#include "utilities/nmap_parser.h"

int main(int argc, char* argv[]) {

    if (getuid() != 0) {
        logsys.Warning("Hugin should be executed with sudo privileges.");
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

    logsys.Info("Using a total of", config.threadAmount, "threads for the scan.");
    auto udpPayloads = ParseNmapPayloads("/usr/share/hugin/nmap/nmap-payloads.txt");

    // --- Port Scanning Phase ---
    for (HostInstance& HostObject : config.HostInstances) {
        auto pOpenPorts = &HostObject.openPorts;

        logsys.Info("Scanning for open ports on host", HostObject.ipValue);

        // TCP connect scan (parallelized)
        if (config.enableTCPScan) {
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

        } else if (config.enableUDPScan) {
            for (int port : config.portsToScan) {
                if (udpPayloads.count(port)) {
                    for (const auto& payload : udpPayloads[port]) {
                        pool.enqueue([=]() {
                            SendNmapUDPPayload(HostObject.ipValue, port, payload);
                        });
                    }
                }
            }
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

        // --- Service scanning ---   
        if ((config.enableFindService || config.enableLUA) && !(HostObject.openPorts.empty())) {
            auto portServiceMap = ParseNmapServices("/usr/share/hugin/nmap/nmap-services.txt", "tcp");
            
            std::cout << "\n";
            logsys.Info("Starting service scanner on host", HostObject.ipValue);
            
            std::cout << std::left;
            std::cout << std::setw(12) << "PORT" << std::setw(8) << "STATE" 
                      << std::setw(20) << "SERVICE" << std::setw(8) << "VERSION\n";
            
            for (int port : HostObject.openPorts) {
                if (!config.enableLUA) {
                    // Adjust timeout for FTP services
                    if (FindIn(common_ftp_ports, port))
                        config.servScan_timeout = 12;
        
                    // Grab service banner in parallel
                    pool.enqueue([&, port]() {
                        std::string serviceName = "unknown";
                        std::string serviceVersion;
                        bool isPortOpen = true;
                        
                        serviceVersion = ServiceVersionInfo(HostObject.ipValue, port, config.servScan_timeout);

                        if (portServiceMap.count(port))
                            serviceName = portServiceMap[port];

                        if (isPortOpen) {
                            std::lock_guard<std::mutex> lock(result_mutex);
                            std::cout << std::setw(12) << (std::to_string(port) + "/tcp") 
                                    << std::setw(8) << "open" 
                                    << std::setw(20) << serviceName
                                    << std::setw(60)
                                    << (serviceVersion.empty() ? "No version found" : serviceVersion) 
                                    << "\n";
                        }
                        scannedServicesCount++;
                    });
                } else {
                    // Run Lua scripts
                    for (const std::string& script : config.luaScripts) {
                        logsys.Info("Running script", script, "on", HostObject.ipValue, "port", port);
                        RunLuaScript(script, HostObject.ipValue, port);
                    }
                }
            }
            // Wait for service scanning to finish
            while (scannedServicesCount.load() < static_cast<int>(HostObject.openPorts.size()))
                ts.SleepMilliseconds(500);

            if (scannedServicesCount.load() >= static_cast<int>(HostObject.openPorts.size()))
                scannedServicesCount = 0;
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