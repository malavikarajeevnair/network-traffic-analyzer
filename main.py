# Network Traffic Analyzer

packets = [
    {"protocol": "TCP", "size": 500},
    {"protocol": "UDP", "size": 300},
    {"protocol": "TCP", "size": 750},
    {"protocol": "ICMP", "size": 100},
    {"protocol": "UDP", "size": 400},
]

tcp_count = 0
udp_count = 0
icmp_count = 0

for packet in packets:
    if packet["protocol"] == "TCP":
        tcp_count += 1
    elif packet["protocol"] == "UDP":
        udp_count += 1
    elif packet["protocol"] == "ICMP":
        icmp_count += 1

print("NETWORK TRAFFIC REPORT")
print("----------------------")
print("TCP packets:", tcp_count)
print("UDP packets:", udp_count)
print("ICMP packets:", icmp_count)
print("Total packets:", len(packets))
