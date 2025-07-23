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

#include "arg_parser.h"

bool ParseArguments(int argc, char* argv[], ProgramConfig& config) {

    if (argc <= 1) {
        logsys.Error("No arguments were entered.");
        logsys.Info("Usage: hugin -i <IP> -p <PORT(s)> <options>");
        logsys.Info("Run hugin -h to see the help section.");
        return false;
    }

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        // Handles IPs to be scanned
        if ((arg == "-i" || arg == "--ip") && i + 1 < argc) {
            std::string IPValue = argv[++i];
            std::stringstream ss(IPValue);
            std::string buffer;

            if (IPValue.empty()) {
                logsys.Warning("No IP provided.");
                logsys.Info("Usage: hugin -i <IP> -p <PORT(s)> <options>");
                return false;
            }

            // If more than one IP is entered
            if (IPValue.find(',') != std::string::npos) {
                while (std::getline(ss, buffer, ',')) {
                    config.HostInstances.emplace_back(HostInstance{buffer});
                }
            // If a subnet has been entered
            } else if (IPValue.find('/') != std::string::npos) {
                std::string ipPart;
                std::getline(ss, ipPart, '/');
                std::getline(ss, buffer, '/');
                int subnetBits = std::stoi(buffer);
                int hostAmount = 0;

                in_addr addr{};
                inet_pton(AF_INET, ipPart.c_str(), &addr);
                uint32_t baseIP = ntohl(addr.s_addr);

                if (subnetBits >= 1 && subnetBits <= 30)
                    hostAmount = (1u << (32 - subnetBits)) - 2;
                else if (subnetBits == 31)
                    hostAmount = 2;
                else if (subnetBits == 32)
                    hostAmount = 1;

                for (int j = 1; j <= hostAmount; ++j) {
                    uint32_t subnetMask = ~((1u << (32 - subnetBits)) - 1);
                    uint32_t hostIP = (baseIP & subnetMask) + j;
                    addr.s_addr = htonl(hostIP);
                    char ipString[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &addr, ipString, INET_ADDRSTRLEN);
                    config.HostInstances.emplace_back(HostInstance(std::string(ipString)));
                }
            // If the above is false
            } else {
                config.HostInstances.emplace_back(HostInstance{IPValue});
            }

        // Set ports to be scanned
        } else if ((arg == "-p" || arg == "--ports") && i + 1 < argc) {
            std::string portValue = argv[++i];
            std::stringstream ss(portValue);
            std::string buffer;

            // If multiple ports have been entered
            if (portValue.find(',') != std::string::npos) {
                while (std::getline(ss, buffer, ',')) {
                    if (!isInteger(buffer))
                        return false;
                    config.portsToScan.push_back(std::stoi(buffer));
                }
            // If a port range have been entered
            } else if (portValue.find('-') != std::string::npos) {
                int start, end;
                std::getline(ss, buffer, '-');
                start = std::stoi(buffer);
                std::getline(ss, buffer, '-');
                end = std::stoi(buffer);
                for (int j = start; j <= end; ++j)
                    config.portsToScan.push_back(j);
            // If the above is false
            } else {
                if (!isInteger(portValue))
                    return false;
                config.portsToScan.push_back(std::stoi(portValue));
            }

        // Set delay for timeout within scan
        } else if ((arg == "-d" || arg == "--delay" || arg == "--scan-delay") && i + 1 < argc) {
            config.portScan_timeout = std::stoi(argv[++i]);

        // Enable service/version finder
        } else if (arg == "-S" || arg == "--service" || arg == "-sV") {
            config.enableFindService = true;

        // Scan the x amount of top TCP ports
        } else if ((arg == "-Tp" || arg == "--top-ports") && i + 1 < argc) {
            int portAmount = std::stoi(argv[++i]);
            config.portsToScan.assign(common_ports_thousand.begin(), common_ports_thousand.begin() 
            + std::min(portAmount, (int)common_ports_thousand.size()));

        // Scans all TCP ports
        } else if (arg == "-Ap" || arg == "--all-ports") {
            for (int j = 1; j <= 65535; ++j)
                config.portsToScan.push_back(j);

        // Performs full TCP scan for port discovery
        } else if (arg == "-sT" || arg == "--tcp-scan") {
            config.enableTCPScan = true;

        // Performs ARP scan
        } else if (arg == "-Ar" || arg == "--arp-scan") {
            config.enableARPScan = true;

        // Set the network interface for ARP scan
        } else if ((arg == "--interface") && i + 1 < argc) {
            config.networkInterface = argv[++i];

        // Set the amount of threads
        } else if ((arg == "-Th" || arg == "--threads") && i + 1 < argc) {
            config.threadAmount = std::stoi(argv[++i]);

        // Enable LUA scripting engine
        } else if ((arg == "-L" || arg == "--script-lua") && i + 1 < argc) {
            config.enableLUA = true;
            config.luaScripts.push_back(argv[++i]);

        // Enable UDP port discovery
        } else if (arg == "-U" || arg == "--udp") {
            config.enableUDPScan = true;

        // Skip host discovery
        } else if (arg == "-Pn") {
            config.isHostUp = true;

        // Print help section
        } else if (arg == "-h" || arg == "--help") {
            RenderHelp();
            return false;

        // If the argument is invalid
        } else {
            logsys.Warning("Unknown argument was entered.");
            logsys.Info("Usage: hugin -i <IP> -p <PORT(s)> <options>");
            return false;
        }
    }

    return true;
}