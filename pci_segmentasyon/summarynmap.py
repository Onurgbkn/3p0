import os
import re
from collections import defaultdict

BASE_PATH = "."

# Thresholds (tweak as needed)
PORT_THRESHOLD = 10               # suspicious if above this
IP_PORT_THRESHOLD = 5             # suspicious IP if above this
FALSE_POSITIVE_THRESHOLD = 250    # ignore ports above this

# Matches: Host: 192.168.1.10 ()	Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
HOST_RE = re.compile(r"^Host:\s+(\S+)\s+\([^)]*\)")
PORTS_FIELD_RE = re.compile(r"Ports:\s*(.+?)(?:\tIgnored State:|$)")
# Each port entry: 22/open/tcp//ssh///
PORT_ENTRY_RE = re.compile(r"^(\d+)/([a-zA-Z|]+)/")

summary = {}
ip_summary = {}

for file in sorted(os.listdir(BASE_PATH)):
    file_path = os.path.join(BASE_PATH, file)

    if not os.path.isfile(file_path):
        continue

    # subnet name derived from the filename, e.g. 192.168.1.0_24.txt -> 192.168.1.0_24
    subnet = os.path.splitext(file)[0]

    port_counts = defaultdict(int)
    ip_ports = defaultdict(list)

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.rstrip("\n")

            if not line or line.startswith("#"):
                continue

            host_match = HOST_RE.match(line)
            if not host_match:
                continue

            current_ip = host_match.group(1)

            ports_match = PORTS_FIELD_RE.search(line)
            if not ports_match:
                # e.g. a bare "Status: Up" line with no Ports field
                continue

            ports_field = ports_match.group(1)

            # Entries are comma-space separated
            for entry in ports_field.split(", "):
                entry = entry.strip()
                if not entry:
                    continue

                port_match = PORT_ENTRY_RE.match(entry)
                if not port_match:
                    continue

                port = port_match.group(1)
                state = port_match.group(2)

                # --open already filters scan-side, but double check
                if "open" not in state.split("|"):
                    continue

                port_counts[port] += 1
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