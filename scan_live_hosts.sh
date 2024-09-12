#!/bin/bash

# Set the output directory for the scan results
OUTPUT_DIR="/root/nmap_scans_grouped"
LIVE_HOSTS_FILE="${OUTPUT_DIR}/live_hosts.txt"
# Create the output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Define the nmap scans to run
SCANS=(
  "-Pn -sV --top-ports 50 --open" # quick scan
  "-Pn -sC -sV -p "20-25,53,80,88,135,139,443,445""  #TCP scan 
  "-Pn --script vuln -sV -p "20-25,53,80,88,135,139,443,445"" #scans for known vulnerabilites
  "-Pn -sC -sV -p-"  #full scan, will take some time
  "-sU -sV --top-ports 20"  # udp scan, will also take some time
)

# Function to run scans
run_scans() {
  local TARGET=$1
  local FILENAME="${OUTPUT_DIR}/${TARGET}_nmap_scans.txt"
  for SCAN in "${SCANS[@]}"; do
    echo "Starting scan: nmap $SCAN $TARGET"
    nmap $SCAN $TARGET -oN - >> "$FILENAME"
    echo "Finished scan: nmap $SCAN $TARGET"
  done
}

export -f run_scans
export OUTPUT_DIR
export SCANS

# Run each scan in parallel and save the output to a separate file per IP address
while read -r TARGET; do
  run_scans "$TARGET" &
done < "$LIVE_HOSTS_FILE" | xargs -P 5 -I {} sh -c '{}'
