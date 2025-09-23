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

#include "helper_functions.h"

// Custom libraries
#include "../utilities/log_system.h"

// C++ libraries
#include <sstream>
#include <algorithm>
#include <iostream>
#include <fstream>

/**
 * @brief Checks if a given string is a valid integer.
 * @param str The input string.
 * @return True if the string is a valid integer, false otherwise.
 */
bool isInteger(const std::string& str) {
    std::istringstream iss(str);
    int num;
    char c;

    if (!(iss >> num)) {
        logsys.Warning("Invalid port value. Only integers are accepted.");
        return false;
    }

    if (iss >> c) {
        logsys.Warning("Invalid port value. Only integers are accepted.");
        return false;
    }

    return true;
}

/**
 * @brief Searches for a value in a vector.
 * @param list Vector of integers.
 * @param buf Integer to search for.
 * @return True if found, false otherwise.
 */
bool FindIn(std::vector<int>& list, int buf) {

    if (std::find(list.begin(), list.end(), buf) == list.end())
        return false;
    
    return true;
}

/**
 * @brief Reads a file line-by-line and extracts integers from it.
 * @param filename Path to the file.
 * @return Vector of integers read from the file.
 */
std::vector<int> ReadFile(const std::string& filename) {
    std::vector<int> output;
    std::ifstream file(filename);
    std::string line;

    if (!file.is_open()){
        logsys.Error("Could not open file:", filename);
        return output;
    }

    while (std::getline(file, line)) {
        std::stringstream ss(line);
        int n;

        while (ss >> n) {
            output.push_back(n);
        }
    }

    return output;
}
// Additional includes for hostname resolution
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <cstring>

/**
 * @brief Resolves a hostname to an IP address.
 * @param hostname The hostname or IP address to resolve.
 * @return The resolved IP address as a string, or the original input if it's already an IP.
 *         Returns empty string if resolution fails.
 */
std::string ResolveHostname(const std::string& hostname) {
    // First check if the input is already a valid IP address
    sockaddr_in addr;
    if (inet_pton(AF_INET, hostname.c_str(), &(addr.sin_addr)) == 1) {
        // Input is already a valid IP address, return as-is
        return hostname;
    }
    
    // Try to resolve hostname to IP address
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;
    
    int status = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
    if (status != 0) {
        logsys.Warning("Failed to resolve hostname:", hostname, "- Error:", gai_strerror(status));
        return "";
    }
    
    // Extract IP address from the result
    struct sockaddr_in* addr_in = (struct sockaddr_in*)result->ai_addr;
    char ip_str[INET_ADDRSTRLEN];
    
    if (inet_ntop(AF_INET, &(addr_in->sin_addr), ip_str, INET_ADDRSTRLEN) == nullptr) {
        logsys.Warning("Failed to convert resolved address to string for hostname:", hostname);
        freeaddrinfo(result);
        return "";
    }
    
    freeaddrinfo(result);
    logsys.Info("Resolved hostname", hostname, "to IP address", ip_str);
    return std::string(ip_str);
}
