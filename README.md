# Hugin - Network Scanner

**Hugin** is a high-performance, multithreaded port scanner written in C++. It supports TCP Connect, SYN and UDP port scanning modes, features ICMP and ARP host detection and service/version grabbing. It is built for speed, efficiency, and flexibility, making it a powerful tool for network reconnaissance. Hugin can scan all 65535 ports via TCP Connect (complete handshake) in 1 minute.

---

## Features

- Scan specific ports, top common ports, port range or all 65535 ports
- High-speed multithreaded architecture
- Supports Nmap arguments such as -Pn, sT and -p-.
- ICMP ping to check if a host is online before scanning
- Banner grabbing to identify services on open ports
- Raw socket support for SYN scanning
- Scan multiple IPs and subnets at once

---

## Build Instructions

### Requirements

- C++17 compiler (g++, clang++)
- Git
- Make
- Lua
- OpenLDAP
- ldns

### Installation

First, clone the repository and navigate to the project directory:

```bash
git clone https://github.com/Smarttfoxx/Hugin
cd Hugin
```

#### Debian-based Systems (Ubuntu, Debian, etc.)

Install the required dependencies:

```bash
sudo apt-get update
sudo apt-get install -y build-essential liblua5.4-dev libldap2-dev libldns-dev
```

Then, compile and install Hugin:

```bash
sudo make install
```

#### Arch-based Systems (Arch Linux, Manjaro, etc.)

Install the required dependencies:

```bash
sudo pacman -Syu --noconfirm
sudo pacman -S --noconfirm base-devel lua openldap ldns
```

Then, compile and install Hugin:

```bash
sudo make install
```

---

### Options

```
# Target IP address (required)
-i, --ip

# Ports to scan (e.g., 80, 20-25, 21,22,23 or -p- for all ports)
-p, --ports

#Scan top N common ports (e.g., -Tp 100)
-Tp, --top-ports

# Use TCP Connect scan (default is SYN scan)
-Ts, --tcp-scan, -sT

# Enable banner grabbing for service detection
-S, --service, -sV

# Timeout for port probes in seconds (default: 3)
-d, --delay

# Number of threads to use for scanning (default: 100)
-Th, --threads
```

---

### Example Usage

```
# Scan top 100 common ports on 192.168.1.1 using 200 threads
sudo hugin -i 192.168.1.1 -sT 100 -Th 200

# Full TCP SYN scan of all 65535 ports
sudo hugin -i 192.168.1.1 -p-

# TCP Connect scan with banner grabbing on selected ports
sudo hugin -i 192.168.1.1 -p 21,22,80 -Ts -S

# Scan a custom port range with default threads and SYN scan
sudo hugin -i 192.168.1.1 -p 20-30
```

---

### Legal Disclaimer

Hugin is intended for educational and authorized security testing purposes only.
Do not use this tool on networks or systems you do not own or lack explicit permission to test. Unauthorized scanning can be illegal and unethical. The author takes no responsibility for any misuse.
