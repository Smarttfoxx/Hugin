#!/bin/bash

# Test script to run enhanced Hugin against AD target from HTB environment
# This script will be executed from the HTB machine

echo "=== Enhanced Hugin AD Detection Test ==="
echo "Target: 10.129.175.191"
echo "Testing against Active Directory infrastructure"
echo ""

# Build the latest version
echo "[*] Building enhanced Hugin..."
make clean && make ENABLE_DISTRIBUTED=0 ENABLE_WEB=0

if [ $? -ne 0 ]; then
    echo "[ERROR] Build failed!"
    exit 1
fi

echo "[*] Build successful!"
echo ""

# Test 1: Basic port scan
echo "[*] Test 1: Basic port detection"
echo "Command: sudo ./hugin -i 10.129.175.191 -p 53,88,135,139,389,445,464,636,3268,3269,3389,5985,9389,47001"
sudo ./hugin -i 10.129.175.191 -p 53,88,135,139,389,445,464,636,3268,3269,3389,5985,9389,47001
echo ""

# Test 2: Service detection
echo "[*] Test 2: Enhanced service detection"
echo "Command: sudo ./hugin -i 10.129.175.191 -p 53,88,135,139,389,445,464,636,3268,3269,3389,5985,9389,47001 -S"
sudo ./hugin -i 10.129.175.191 -p 53,88,135,139,389,445,464,636,3268,3269,3389,5985,9389,47001 -S
echo ""

# Test 3: Focus on key AD ports
echo "[*] Test 3: Focus on key AD ports (389, 3389, 445)"
echo "Command: sudo ./hugin -i 10.129.175.191 -p 389,3389,445 -S"
sudo ./hugin -i 10.129.175.191 -p 389,3389,445 -S
echo ""

# Test 4: Single port detailed test
echo "[*] Test 4: Single port detailed test (LDAP 389)"
echo "Command: sudo ./hugin -i 10.129.175.191 -p 389 -S"
sudo ./hugin -i 10.129.175.191 -p 389 -S
echo ""

echo "[*] Testing complete!"
echo ""
echo "=== Comparison with nmap ==="
echo "Running nmap for comparison..."
nmap -sV -p 53,88,135,139,389,445,464,636,3268,3269,3389,5985,9389,47001 10.129.175.191
