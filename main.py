from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import Counter

# ==========================================
# NETWORK TRAFFIC ANALYZER
# Version: 2.2
# ==========================================

packet_count = 0
total_bytes = 0
protocol_counts = Counter()


def analyze_packet(packet):
    global packet_count, total_bytes

    if IP not in packet:
        return

    packet_count += 1
    total_bytes += len(packet)

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

    print("\nSelect a protocol to capture:")
    print("1. All IP traffic")
    print("2. TCP")
    print("3. UDP")
    print("4. ICMP")

    choice = input("\nEnter your choice (1-4): ")

    filters = {
        "1": "ip",
        "2": "tcp",
        "3": "udp",
        "4": "icmp"
    }

    if choice not in filters:
        print("Invalid choice.")
        return

    selected_filter = filters[choice]

    try:
        duration = int(input("Capture duration in seconds: "))

        if duration <= 0:
            print("Duration must be greater than zero.")
            return

    except ValueError:
        print("Please enter a valid whole number.")
        return

    print(f"\nCapturing {selected_filter.upper()} traffic")
    print(f"Duration: {duration} seconds")
    print("Please wait...\n")

    try:
        sniff(
            filter=selected_filter,
            prn=analyze_packet,
            store=False,
            timeout=duration
        )

    except Exception as error:
        print("\nCapture error:", error)
        return

    print("\nCapture completed.")

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
