// utilities/nmap_payload_parser.h
#pragma once
#include <unordered_map>
#include <vector>
#include <string>
#include <map>
#include <fstream>
#include <sstream>

std::unordered_map<int, std::vector<std::string>> ParseNmapPayloads(const std::string& filePath);
std::map<int, std::string> ParseNmapServices(const std::string& filename, const std::string& proto);