import os
import re
from collections import defaultdict

BASE_PATH = "."

# Thresholds (tweak as needed)
PORT_THRESHOLD = 10               # suspicious if above this
IP_PORT_THRESHOLD = 5          # suspicious IP if above this
FALSE_POSITIVE_THRESHOLD = 250   # ignore ports above this

summary = {}
ip_summary = {}

for subnet in os.listdir(BASE_PATH):
    subnet_path = os.path.join(BASE_PATH, subnet)

    if not os.path.isdir(subnet_path):
        continue

    port_counts = defaultdict(int)
    ip_ports = defaultdict(list)

    for file in os.listdir(subnet_path):
        file_path = os.path.join(subnet_path, file)

        if not os.path.isfile(file_path):
            continue

        current_ip = None

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()

                if not line:
                    continue

                # Extract IP
                if line.startswith("HOST"):
                    parts = line.split(":")
                    if len(parts) > 1:
                        current_ip = parts[1].strip()

                # Skip "all ports closed" lines
                elif "all ports closed" in line.lower():
                    continue

                # Extract open ports safely using regex
                else:
                    match = re.match(r"open\s+(\d+)", line)
                    if match:
                        port = match.group(1)

                        port_counts[port] += 1

                        if current_ip:
                            ip_ports[current_ip].append(port)

    summary[subnet] = dict(port_counts)
    ip_summary[subnet] = dict(ip_ports)

# =========================
# PRINT RESULTS
# =========================

for subnet in summary:
    print("=" * 60)
    print(f"Subnet: {subnet}")
    print("=" * 60)

    ports = summary[subnet]
    ips = ip_summary[subnet]

    # -------------------------
    # PORT SUMMARY
    # -------------------------
    print("\n[PORT SUMMARY]")
    for port, count in sorted(ports.items(), key=lambda x: int(x[0])):
        flag = ""
        if count > FALSE_POSITIVE_THRESHOLD:
            flag = " (ignored - too common)"
        print(f"Port {port} open {count} times{flag}")

    # -------------------------
    # PORT-BASED DETECTION
    # -------------------------
    print("\n[POTENTIAL FIREWALL RULES - PORT BASED]")
    found = False
    for port, count in ports.items():
        if count > FALSE_POSITIVE_THRESHOLD:
            continue

        if count > PORT_THRESHOLD:
            print(f"⚠️ Port {port} open {count} times → possible allow rule")
            found = True

    if not found:
        print("No suspicious ports found.")

    # -------------------------
    # IP-BASED DETECTION
    # -------------------------
    print("\n[POTENTIAL FIREWALL RULES - IP BASED]")
    found = False
    for ip, port_list in ips.items():
        unique_ports = set(port_list)

        # Remove noisy ports
        filtered_ports = [
            p for p in unique_ports
            if ports.get(p, 0) <= FALSE_POSITIVE_THRESHOLD
        ]

        if len(filtered_ports) > IP_PORT_THRESHOLD:
            print(
                f"⚠️ {len(filtered_ports)} ports open on {ip} "
                f"(excluding noisy ports) → possible allow rule for this IP"
            )
            found = True

    if not found:
        print("No suspicious IP patterns found.")

    print("\n")