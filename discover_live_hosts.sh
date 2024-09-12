#!/bin/bash

# Set the network range to scan
NETWORK_RANGE="192.168.0.0/24"  # Replace with your network range

# Set the output directory for the scan results
OUTPUT_DIR="/root/nmap_scans_grouped"

# Create the output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Perform a ping scan to discover live hosts
LIVE_HOSTS_FILE="${OUTPUT_DIR}/live_hosts.txt"
nmap -sn $NETWORK_RANGE > "${OUTPUT_DIR}/nmap_output.txt"

# Extract live hosts from the nmap output
grep "Nmap scan report for" "${OUTPUT_DIR}/nmap_output.txt" | awk '{print $5}' > "$LIVE_HOSTS_FILE"
