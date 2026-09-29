from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import Counter

# NETWORK TRAFFIC ANALYZER
# Version: 2.0

packet_count = 0
total_bytes = 0
protocol_counts = Counter()


def analyze_packet(packet):
    global packet_count, total_bytes

    packet_count += 1
    total_bytes += len(packet)

    if IP in packet:
        source = packet[IP].src
        destination = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "Other IP"

        protocol_counts[protocol] += 1

        print(
            f"Packet {packet_count}: "
            f"{source} -> {destination} | "
            f"{protocol} | "
            f"{len(packet)} bytes"
        )


def main():
    print("=" * 50)
    print("          NETWORK TRAFFIC ANALYZER")
    print("=" * 50)

    print("\nCapturing network traffic...")
    print("Press Ctrl+C to stop capturing.\n")

    try:
        sniff(
            prn=analyze_packet,
            store=False
        )

    except KeyboardInterrupt:
        print("\nCapture stopped.")

    print("\nNETWORK TRAFFIC REPORT")
    print("-" * 50)
    print("Total packets:", packet_count)
    print("Total data:", total_bytes, "bytes")

    print("\nProtocol breakdown:")

    for protocol, count in protocol_counts.items():
        print(f"{protocol}: {count}")

    print("=" * 50)


if __name__ == "__main__":
    main()
