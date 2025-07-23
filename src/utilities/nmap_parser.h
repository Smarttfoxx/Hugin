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
#include <unordered_map>
#include <vector>
#include <string>
#include <map>
#include <fstream>
#include <sstream>

/**
 * Parse the NMAP payloads from its file DB
 * @param filePath The full path to the NMAP file containing payloads.
 */
std::unordered_map<int, std::vector<std::string>> ParseNmapPayloads(const std::string& filePath);

/**
 * Parse the NMAP services from its file DB
 * @param filename The full path to the NMAP file containing payloads.
 * @param proto The protocol to be used.
 */
std::map<int, std::string> ParseNmapServices(const std::string& filename, const std::string& proto);