// utilities/nmap_payload_parser.cpp
#include "nmap_parser.h"
#include <fstream>
#include <regex>

std::unordered_map<int, std::vector<std::string>> ParseNmapPayloads(const std::string& filePath) {
    std::unordered_map<int, std::vector<std::string>> payloads;
    std::ifstream file(filePath);
    if (!file.is_open()) return payloads;

    std::string line;
    std::vector<int> currentPorts;
    while (std::getline(file, line)) {
        line = std::regex_replace(line, std::regex("^\\s+|\\s+$"), "");  // trim
        if (line.empty() || line[0] == '#') continue;

        if (line.substr(0, 3) == "udp") {
            currentPorts.clear();
            std::smatch match;
            if (std::regex_search(line, match, std::regex(R"(udp\s+([\d,]+))"))) {
                std::stringstream ss(match[1].str());
                std::string portStr;
                while (std::getline(ss, portStr, ',')) {
                    currentPorts.push_back(std::stoi(portStr));
                }
            }
        }

        std::smatch payloadMatch;
        if (std::regex_search(line, payloadMatch, std::regex(R"(((?:\\x[0-9A-Fa-f]{2})+))"))) {
            std::string raw = payloadMatch[1];
            std::string decoded;
            for (size_t i = 0; i < raw.length(); i += 4) {
                std::string byteStr = raw.substr(i + 2, 2);
                char byte = static_cast<char>(std::stoi(byteStr, nullptr, 16));
                decoded.push_back(byte);
            }
            for (int port : currentPorts) {
                payloads[port].push_back(decoded);
            }
        }

    }

    return payloads;
}

std::map<int, std::string> ParseNmapServices(const std::string& filename, const std::string& proto) {
    std::ifstream file(filename);
    std::map<int, std::string> portToService;
    std::string line;

    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        std::istringstream iss(line);
        std::string service, portProto;
        if (!(iss >> service >> portProto)) continue;

        auto slashPos = portProto.find('/');
        if (slashPos == std::string::npos) continue;

        int port = std::stoi(portProto.substr(0, slashPos));
        std::string protocol = portProto.substr(slashPos + 1);

        if (protocol == proto) {
            portToService[port] = service;
        }
    }

    return portToService;
}