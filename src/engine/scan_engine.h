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

// Support for lua scripting
extern "C" {
#include <lua5.4/lua.h>
#include <lua5.4/lualib.h>
#include <lua5.4/lauxlib.h>
}

// C++ libraries
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <chrono>
#include <thread>
#include <cstring>
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <errno.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <atomic>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>

#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>

#include <ldns/ldns.h>

// Custom libraries
#include "../utilities/helper_functions.h"
#include "default_ports.h"
#include "../utilities/log_system.h"

struct HostInstance {
    std::string ipValue;
    std::vector<int> openPorts;

    HostInstance(const std::string& ip) : ipValue(ip){};
};

struct pseudo_header {
    uint32_t sourceIP;
    uint32_t targetIP;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

/**
 * Calculates the Internet checksum for a buffer of bytes.
 * @param ptr Pointer to the data buffer.
 * @param nbytes Number of bytes in the buffer.
 * @return The computed checksum.
 */
unsigned short checksum(unsigned short *ptr, int nbytes);

/**
 * Overloaded version of checksum function using a void pointer.
 * @param b Pointer to the data buffer.
 * @param len Length of the data in bytes.
 * @return The computed checksum.
 */
unsigned short checksum(void* b, int len);

/**
 * Determines the local IP address used to reach a specified remote IP.
 * @param ipValue The target IP address.
 * @return Local IP address as a string.
 */
std::string GetLocalIP(const std::string& ipValue);

/**
 * Send NMAP UDP payloads to services
 * @param ipValue The target IP address.
 * @param port The target port.
 * @param payload The NMAP payload to be sent.
 */
bool SendNmapUDPPayload(const std::string& ipValue, int port, const std::string& payload, int timeoutValue);

/**
 * Connects to an LDAP server and attempts to enumerate the domain, site, and hostname.
 * Prints results if enumeration is successful.
 * @param host Target IP address or hostname.
 * @param port LDAP port (typically 389 or 636).
 * @return True if enumeration was successful, false otherwise.
 */
std::string EnumerateLDAP(const std::string& host, int port);

/**
 * TCP service probe for DNS
 */
std::string TCPDNSProbe(const std::string& ipValue, int port);

/**
 * Enhanced DNS Service: detection
 * @param ipValue Target DNS server IP
 * @param port DNS server port
 * @return Detailed service string
 */
std::string DetectDNSService(const std::string& ipValue, int port);

/**
 * Connects to a TCP port and attempts to grab a service banner.
 * @param ipValue IP address of the target.
 * @param port Target port number.
 * @param timeoutValue Connection timeout in seconds.
 * @return Banner string or empty if none was received.
 */
std::string ServiceVersionInfo(const std::string& ipValue, int port, int timeoutValue);

/**
 * Checks if a TCP port is open by attempting a full connection.
 * @param ipValue IP address of the target.
 * @param port Target port.
 * @param timeoutValue Timeout in seconds.
 * @return True if port is open, false otherwise.
 */
bool PortScanTCPConnect(const std::string& ipValue, int port, int timeoutValue);

/**
 * Performs a TCP SYN scan using raw sockets and epoll for asynchronous response detection.
 * Sends crafted SYN packets and listens for SYN-ACK replies.
 * @param ipValue Target IP address.
 * @param ports List of ports to scan.
 * @param timeoutValue Timeout for receiving responses.
 * @return Vector of ports that responded with SYN-ACK (open).
 */
std::vector<int> PortScanTCPSyn(const std::string& ipValue, const std::vector<int>& ports, float timeoutValue);

/**
 * Sends an ICMP Echo Request ("ping") to determine if a host is up.
 * @param ipValue Target IP address.
 * @return True if the host replies to the ping, false otherwise.
 */
bool IsHostUpICMP(const std::string& ipValue);

/**
 * Sends an ARP request at Layer 2 to determine if a host is up on a local network.
 * @param ipValue Target IP address.
 * @param interface Network interface to use (e.g., "eth0").
 * @return True if the ARP reply is received, false otherwise.
 */
bool IsHostUpARP(const std::string& ipValue, const std::string& interface);

/**
 * Checks whether a given string is a valid IPv4 address.
 * @param ipValue IP address string.
 * @return True if valid IPv4, false otherwise.
 */
bool IsValidIP(const std::string& ipValue);

/**
 * Executes a Lua script with injected global variables: target_ip and target_port.
 * Useful for scripting post-scan actions like banner parsing, service detection, etc.
 * @param scriptPath Path to the Lua script.
 * @param targetIP IP address to pass to the script.
 * @param port Port number to pass to the script.
 * @return True if script executed successfully, false otherwise.
 */
bool RunLuaScript(const std::string& scriptPath, const std::string& targetIP, int port);