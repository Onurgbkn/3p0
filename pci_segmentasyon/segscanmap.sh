#!/bin/bash

# Taranacak subnetler
subnets=(
    "192.168.0.0/24"
    "10.25.5.0/23"
)

for subnet in "${subnets[@]}"; do

    filename=$(echo "$subnet" | tr '/' '_')

    echo "======================================================"
    echo "[+] Scanning $subnet"
    echo "Started: $(date)"
    echo "======================================================"

    nmap -Pn -n --open -T4 --max-retries 1 --max-rtt-timeout 100ms --min-rate 1500 "$subnet" -oG "$filename"

    echo
    echo "[+] Finished $subnet"
    echo
done

echo "All scans completed."
