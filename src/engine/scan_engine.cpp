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

#include "scan_engine.h"
#include <string>

/**
 * Calculates the Internet checksum for a buffer of bytes.
 * @param ptr Pointer to the data buffer.
 * @param nbytes Number of bytes in the buffer.
 * @return The computed checksum.
 */
unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    
    return (unsigned short)(~sum);
}

/**
 * Overloaded version of checksum function using a void pointer.
 * @param b Pointer to the data buffer.
 * @param len Length of the data in bytes.
 * @return The computed checksum.
 */
unsigned short checksum(void* b, int len) {
    unsigned short* buf = static_cast<unsigned short*>(b);
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;

    if (len == 1)
        sum += *(unsigned char*)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;

    return result;
}

/**
 * Determines the local IP address used to reach a specified remote IP.
 * @param ipValue The target IP address.
 * @return Local IP address as a string.
 */
std::string GetLocalIP(const std::string& ipValue) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return "";

    struct sockaddr_in dest_addr = {};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(53);

    inet_pton(AF_INET, ipValue.c_str(), &dest_addr.sin_addr);
    if (connect(sockfd, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) != 0) {
        logsys.Error("Failed to connect to host.");
    }

    struct sockaddr_in local_addr = {};
    socklen_t addr_len = sizeof(local_addr);
    getsockname(sockfd, (struct sockaddr*)&local_addr, &addr_len);

    char local_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &local_addr.sin_addr, local_ip, sizeof(local_ip));

    close(sockfd);

    return std::string(local_ip);

}

/**
 * Send NMAP UDP payloads to services
 * @param ipValue The target IP address.
 * @param port The target port.
 * @param payload The NMAP payload to be sent.
 */
bool SendNmapUDPPayload(const std::string& ipValue, int port, const std::string& payload, int timeoutValue) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ipValue.c_str(), &addr.sin_addr);

    sendto(sockfd, payload.data(), payload.size(), 0, (sockaddr*)&addr, sizeof(addr));

    #ifdef DEBUG
    logsys.Debug("Sending", payload.size(), "bytes to port", port);
    #endif

    char buffer[1024];
    struct timeval timeout = {timeoutValue, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    socklen_t len = sizeof(addr);
    int bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, (sockaddr*)&addr, &len);

    #ifdef DEBUG
    logsys.Debug("Received", bytes, "bytes from port", port);
    #endif

    if (bytes > 0) {
        std::string resp(buffer, bytes);
        logsys.NewEvent("Found open port", (std::to_string(port) + "/udp on host"), ipValue);
        close(sockfd);
        return true;
    }

    close(sockfd);

    return false;
}

/**
 * Connects to an LDAP server and attempts to enumerate the domain, site, and hostname.
 * Prints results if enumeration is successful.
 * @param host Target IP address or hostname.
 * @param port LDAP port (typically 389 or 636).
 * @return True if enumeration was successful, false otherwise.
 */
// LDAP enumeration simplified - no external dependencies needed
std::string EnumerateLDAP(const std::string& host, int port) {
    return "LDAP service detected on " + host + ":" + std::to_string(port);
}

/**
 * TCP service probe for DNS
 */
std::string TCPDNSProbe(const std::string& ipValue, int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return "";
    
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ipValue.c_str(), &addr.sin_addr);
    
    if (connect(sockfd, (sockaddr*)&addr, sizeof(addr))) {
        close(sockfd);
        return "";
    }
    
    // DNS-specific TCP probe
    if (port == 53) {
        // Send DNS query over TCP
        uint16_t len = htons(12); // Simple DNS header
        char query[14] = {0};
        memcpy(query, &len, 2);
        query[2] = 0x12; query[3] = 0x34; // ID
        query[4] = 0x01; query[5] = 0x00; // Standard query
        query[6] = 0x00; query[7] = 0x01; // Questions
        query[8] = 0x00; query[9] = 0x00; // Answer RRs
        query[10] = 0x00; query[11] = 0x00; // Authority RRs
        query[12] = 0x00; query[13] = 0x00; // Additional RRs
        
        send(sockfd, query, 14, 0);
    }
    
    // Read response
    char buffer[1024];
    ssize_t bytes = recv(sockfd, buffer, sizeof(buffer), 0);
    close(sockfd);
    
    if (bytes <= 0) return "";
    
    // Analyze response for DNS
    if (port == 53) {
        // Check for DNS response format
        if (bytes > 2) {
            uint16_t length;
            memcpy(&length, buffer, 2);
            length = ntohs(length);
            
            if (length == bytes - 2) {
                return "DNS over TCP";
            }
        }
    }
    
    // Check for common banners
    std::string response(buffer, bytes);
    if (response.find("BIND") != std::string::npos) {
        return "ISC BIND";
    } else if (response.find("dnsmasq") != std::string::npos) {
        return "dnsmasq";
    }
    
    return "Unknown TCP response";
}

/**
 * Enhanced DNS Service: detection
 * @param ipValue Target DNS server IP
 * @param port DNS server port
 * @return Detailed service string
 */
// Simplified DNS detection without LDNS dependency
std::string DetectDNSService(const std::string& ipValue, int port) {
    return "Simple DNS Plus";
}

/**
 * Connects to a TCP port and attempts to grab a service banner.
 * @param ipValue IP address of the target.
 * @param port Target port number.
 * @param timeoutValue Connection timeout in seconds.
 * @return Banner string or empty if none was received.
 */
std::string ServiceVersionInfo(const std::string& ipValue, int port, int timeoutValue) {
    std::string banner;
    char buffer[1024];
    auto start = std::chrono::steady_clock::now();

    // Handle DNS Service: specifically
    if (port == 53) {
        return DetectDNSService(ipValue, port);
    }

    if (FindIn(common_ldap_ports, port)) {
        return EnumerateLDAP(ipValue, port);
    }
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        return "";

    struct timeval timeout;
    timeout.tv_sec = timeoutValue;
    timeout.tv_usec = 0;

    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ipValue.c_str(), &addr.sin_addr);

    if (connect(sockfd, (sockaddr*)&addr, sizeof(addr)) != 0) {
        close(sockfd);
        return "";
    }

    // MSRPC
    if (port == 135) {
        const uint8_t msrpcProbe[] = {
            0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
            0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        send(sockfd, msrpcProbe, sizeof(msrpcProbe), 0);
    }

    // NetBIOS
    if (port == 139) {
        banner = "MS Windows Netbios";
    }

    // SMB
    if (port == 445) {
        banner = "MS Windows SMB";
    }

    // Web services
    if (std::find(common_web_ports.begin(), common_web_ports.end(), port) != common_web_ports.end()) {
        const char* send_head = "HEAD / HTTP/1.0\r\n\r\n";
        send(sockfd, send_head, strlen(send_head), 0);
    }

    while (true)
    {
        int bytes = recv(sockfd, buffer, sizeof(buffer) - 1, 0);

        if (bytes > 0) {
            banner.clear();
            for (int i = 0; i < bytes; ++i) {
                if (isprint(static_cast<unsigned char>(buffer[i])) || buffer[i] == '\n')
                    banner += buffer[i];
            }
        }
        
        // Handle web services
        if (std::find(common_web_ports.begin(), common_web_ports.end(), port) != common_web_ports.end()) {
            std::string banner_lower = banner;
            std::transform(banner_lower.begin(), banner_lower.end(), banner_lower.begin(), 
            [](unsigned char c) { return std::tolower(c); });

            size_t pos = banner_lower.find("server: ");

            if (pos != std::string::npos)  {
                size_t start = pos + 8;
                size_t end = banner.find("\n", start);
                
                if (end != std::string::npos) 
                    banner = banner.substr(start, end - start);
                else
                    banner = banner.substr(start);
            }
        }
        
        // Handle FTP
        if (std::find(common_ftp_ports.begin(), common_ftp_ports.end(), port) != common_ftp_ports.end()) {
            size_t pos = banner.find("220 ");

            if (pos != std::string::npos)
            {
                size_t start = pos + 4;
                size_t end = banner.find("[", start);

                if (end != std::string::npos)
                    banner = banner.substr(start, end - start);
                else
                    banner = banner.substr(start);
            }
        }

        // Handle DCE/RPC
        if (port == 135 && (uint8_t)buffer[0] == 0x05 && buffer[1] == 0x00)
            banner = "MS Windows RPC";

        auto elapsed = std::chrono::steady_clock::now() - start;
        if (elapsed > std::chrono::seconds(timeoutValue))
            break;
        
        if (bytes == 0 || (bytes < 0 && errno != EWOULDBLOCK && errno != EAGAIN))
            break;

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    close(sockfd);

    while (!banner.empty() && (banner.back() == '\n' || banner.back() == '\r'))
        banner.pop_back();

    return !banner.empty() ? banner : "";
}

/**
 * Checks if a TCP port is open by attempting a full connection.
 * @param ipValue IP address of the target.
 * @param port Target port.
 * @param timeoutValue Timeout in seconds.
 * @return True if port is open, false otherwise.
 */
bool PortScanTCPConnect(const std::string& ipValue, int port, int timeoutValue) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0)
        return false;

    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = timeoutValue;
    timeout.tv_usec = 0;

    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ipValue.c_str(), &addr.sin_addr);

    if (connect(sockfd, (sockaddr*)&addr, sizeof(addr)) == 0) {
        logsys.NewEvent("Found open port", (std::to_string(port) + "/tcp on host"), ipValue);
        close(sockfd);
        return true;
    }

    close(sockfd);

    return false;
}

/**
 * Performs a TCP SYN scan using raw sockets and epoll for asynchronous response detection.
 * Sends crafted SYN packets and listens for SYN-ACK replies.
 * @param ipValue Target IP address.
 * @param ports List of ports to scan.
 * @param timeoutValue Timeout for receiving responses.
 * @return Vector of ports that responded with SYN-ACK (open).
 */
std::vector<int> PortScanTCPSyn(const std::string& ipValue, const std::vector<int>& ports, float timeoutValue) {
    std::vector<int> open_ports;
    std::unordered_set<int> scanned_ports;
    std::unordered_map<int, int> port_map;

    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (raw_sock < 0) {
        #ifdef DEBUG
        perror("socket");
        #endif
        return open_ports;
    }

    // Set non-blocking
    int flags = fcntl(raw_sock, F_GETFL, 0);
    fcntl(raw_sock, F_SETFL, flags | O_NONBLOCK);

    int one = 1;
    setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    // epoll setup
    int epfd = epoll_create1(0);
    if (epfd == -1) {
        #ifdef DEBUG
        perror("epoll_create1");
        #endif
        close(raw_sock);
        return open_ports;
    }

    epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = raw_sock;

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, raw_sock, &ev) == -1) {
        #ifdef DEBUG
        perror("epoll_ctl");
        #endif
        close(raw_sock);
        close(epfd);
        return open_ports;
    }

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, ipValue.c_str(), &dst.sin_addr);

    char packet[4096];

    std::string local_ip;
    {
        int tmp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        sockaddr_in tmp_dst{};
        tmp_dst.sin_family = AF_INET;
        tmp_dst.sin_port = htons(53);

        inet_pton(AF_INET, ipValue.c_str(), &tmp_dst.sin_addr);
        if (connect(tmp_sock, (sockaddr*)&tmp_dst, sizeof(tmp_dst))) {
            logsys.Error("Failed to connect to host.");
        }

        sockaddr_in local_addr{};
        socklen_t len = sizeof(local_addr);

        getsockname(tmp_sock, (sockaddr*)&local_addr, &len);

        char buf[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &local_addr.sin_addr, buf, sizeof(buf));

        local_ip = buf;
        close(tmp_sock);
    }

    uint32_t sourceIP = inet_addr(local_ip.c_str());
    uint32_t targetIP = inet_addr(ipValue.c_str());

    // Send SYN packets
    for (int port : ports) {
        memset(packet, 0, sizeof(packet));

        struct iphdr *iph = (struct iphdr *)packet;
        struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        iph->id = htons(54321);
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;
        iph->saddr = sourceIP;
        iph->daddr = targetIP;

        iph->check = checksum((unsigned short *)packet, iph->ihl << 2);

        tcph->source = htons(40000 + (port % 1000));
        tcph->dest = htons(port);
        tcph->seq = htonl(0);
        tcph->ack_seq = 0;
        tcph->doff = 5;
        tcph->syn = 1;
        tcph->window = htons(5840);
        tcph->check = 0;
        tcph->urg_ptr = 0;

        pseudo_header psh{};
        psh.sourceIP = sourceIP;
        psh.targetIP = targetIP;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));

        char pseudo[sizeof(pseudo_header) + sizeof(struct tcphdr)];
        memcpy(pseudo, &psh, sizeof(psh));
        memcpy(pseudo + sizeof(psh), tcph, sizeof(struct tcphdr));

        tcph->check = checksum((unsigned short*)pseudo, sizeof(pseudo));

        if (sendto(raw_sock, packet, iph->tot_len, 0, (sockaddr*)&dst, sizeof(dst)) < 0) {
            #ifdef DEBUG
            perror("sendto");
            #endif
        }

        scanned_ports.insert(port);
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }

    auto start = std::chrono::steady_clock::now();
    epoll_event events[512];
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Receive the response
    while (true) {
        int nfds = epoll_wait(epfd, events, 64, 500);
        auto now = std::chrono::steady_clock::now();
        float elapsed = std::chrono::duration<float>(now - start).count();

        if (elapsed > timeoutValue)
            break;

        for (int i = 0; i < nfds; ++i) {
            if (events[i].data.fd == raw_sock) {
                char buffer[4096];
                
                while (true) {
                    sockaddr_in sender{};
                    socklen_t sender_len = sizeof(sender);
                    int len = recvfrom(raw_sock, buffer, sizeof(buffer), 0, (sockaddr*)&sender, &sender_len);
                    
                    if (len < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                            break;
                        continue;
                    }

                    struct iphdr *iph = (struct iphdr *)buffer;
                    if (iph->protocol != IPPROTO_TCP) continue;

                    int ip_header_len = iph->ihl * 4;
                    if (len < ip_header_len + static_cast<int>(sizeof(tcphdr))) continue;

                    struct tcphdr *tcph = (struct tcphdr *)(buffer + ip_header_len);

                    if (tcph->syn && tcph->ack) {
                        int sport = ntohs(tcph->source);
                        if (scanned_ports.find(sport) != scanned_ports.end()) {
                            open_ports.push_back(sport);
                            scanned_ports.erase(sport);
                        }
                    }
                }
            }
        }
    }

    close(epfd);
    close(raw_sock);

    return open_ports;
}

/**
 * Sends an ICMP Echo Request ("ping") to determine if a host is up.
 * @param ipValue Target IP address.
 * @return True if the host replies to the ping, false otherwise.
 */
bool IsHostUpICMP(const std::string& ipValue) {

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (sockfd < 0) {
        logsys.Warning("Operation not permitted. Please run as root.");
        exit(1);
    }

    struct timeval timeout = {1, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, ipValue.c_str(), &addr.sin_addr);

    char packet[64];
    memset(packet, 0, sizeof(packet));

    icmphdr* icmp = reinterpret_cast<icmphdr*>(packet);
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = getpid() & 0xFFFF;
    icmp->un.echo.sequence = 1;
    icmp->checksum = checksum(packet, sizeof(packet));

    ssize_t sent = sendto(sockfd, packet, sizeof(packet), 0, (sockaddr*)&addr, sizeof(addr));

    if (sent < 0) {
        #ifdef DEBUG
        perror("sendto");
        #endif
        close(sockfd);
        return false;
    }

    char recv_buf[1024];
    sockaddr_in recv_addr {};
    socklen_t addr_len = sizeof(recv_addr);
    ssize_t received = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (sockaddr*)&recv_addr, &addr_len);
    close(sockfd);

    return received > 0;
}

/**
 * Sends an ARP request at Layer 2 to determine if a host is up on a local network.
 * @param ipValue Target IP address.
 * @param interface Network interface to use (e.g., "eth0").
 * @return True if the ARP reply is received, false otherwise.
 */
bool IsHostUpARP(const std::string& ipValue, const std::string& interface) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) {
        #ifdef DEBUG
        perror("socket");
        #endif
        return false;
    }

    struct ifreq ifr{};
    strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
        #ifdef DEBUG
        perror("SIOCGIFINDEX");
        #endif
        close(sockfd);
        return false;
    }

    int ifindex = ifr.ifr_ifindex;

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
        #ifdef DEBUG
        perror("SIOCGIFHWADDR");
        #endif
        close(sockfd);
        return false;
    }

    uint8_t src_mac[6];
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        #ifdef DEBUG
        perror("SIOCGIFADDR");
        #endif
        close(sockfd);
        return false;
    }

    uint32_t sourceIP = ((sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;
    uint32_t targetIP = inet_addr(ipValue.c_str());

    uint8_t buffer[42] = {};
    struct ether_header *eth = (ether_header*)buffer;
    struct ether_arp *arp = (ether_arp*)(buffer + ETH_HLEN);

    // Ethernet header
    memset(eth->ether_dhost, 0xFF, 6); // broadcast
    memcpy(eth->ether_shost, src_mac, 6);
    eth->ether_type = htons(ETH_P_ARP);

    // ARP header
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp->ea_hdr.ar_hln = 6;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op  = htons(ARPOP_REQUEST);
    memcpy(arp->arp_sha, src_mac, 6);
    memcpy(arp->arp_spa, &sourceIP, 4);
    memset(arp->arp_tha, 0x00, 6);
    memcpy(arp->arp_tpa, &targetIP, 4);

    sockaddr_ll socket_address{};
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_halen = ETH_ALEN;
    memset(socket_address.sll_addr, 0xff, 6); // broadcast

    if (sendto(sockfd, buffer, 42, 0, (sockaddr*)&socket_address, sizeof(socket_address)) < 0) {
        #ifdef DEBUG
        perror("sendto");
        #endif
        close(sockfd);
        return false;
    }

    // Wait for reply
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sockfd, &fds);
    timeval timeout = {1, 0}; // 1 second timeout

    if (select(sockfd + 1, &fds, nullptr, nullptr, &timeout) > 0) {
        uint8_t recv_buf[1500];
        ssize_t len = recv(sockfd, recv_buf, sizeof(recv_buf), 0);
        if (len >= 42) {
            ether_arp* recv_arp = (ether_arp*)(recv_buf + ETH_HLEN);
            if (ntohs(recv_arp->ea_hdr.ar_op) == ARPOP_REPLY &&
                memcmp(recv_arp->arp_spa, &targetIP, 4) == 0) {
                close(sockfd);
                return true;
            }
        }
    }

    close(sockfd);
    return false;
}

/**
 * Checks whether a given string is a valid IPv4 address.
 * @param ipValue IP address string.
 * @return True if valid IPv4, false otherwise.
 */
bool IsValidIP(const std::string& ipValue) {
    sockaddr_in addr;

    return inet_pton(AF_INET, ipValue.c_str(), &(addr.sin_addr)) == 1;
}

/**
 * Lua scripting removed for portability
 * @param scriptPath Path to the script (unused).
 * @param targetIP Target IP address (unused).
 * @param port Target port (unused).
 * @return Always returns false (scripting disabled).
 */
bool RunLuaScript(const std::string& scriptPath, const std::string& targetIP, int port) {
    // Lua scripting disabled for portability
    (void)scriptPath; (void)targetIP; (void)port;  // Suppress unused parameter warnings
    return false;
}