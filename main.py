# ==========================================
# NETWORK TRAFFIC ANALYZER
# Version: 1.0
# ==========================================

# Sample network packets
packets = [
    {"protocol": "TCP", "size": 500},
    {"protocol": "UDP", "size": 300},
    {"protocol": "TCP", "size": 750},
    {"protocol": "ICMP", "size": 100},
    {"protocol": "UDP", "size": 400},
]

# Initialize counters
tcp_count = 0
udp_count = 0
icmp_count = 0
total_bytes = 0

# Analyze packets
for packet in packets:

    protocol = packet["protocol"]
    size = packet["size"]

    total_bytes += size

    if protocol == "TCP":
        tcp_count += 1

    elif protocol == "UDP":
        udp_count += 1

    elif protocol == "ICMP":
        icmp_count += 1

# Display the report
print("=" * 40)
print("       NETWORK TRAFFIC ANALYZER")
print("=" * 40)

print("\nNETWORK TRAFFIC REPORT")
print("-" * 40)

print("TCP packets:", tcp_count)
print("UDP packets:", udp_count)
print("ICMP packets:", icmp_count)

print("-" * 40)

print("Total packets:", len(packets))
print("Total data:", total_bytes, "bytes")

print("=" * 40)
