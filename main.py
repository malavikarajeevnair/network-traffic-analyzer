from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import Counter
import csv
from datetime import datetime

# ==========================================
# NETWORK TRAFFIC ANALYZER
# Version: 2.3
# ==========================================

packet_count = 0
total_bytes = 0
protocol_counts = Counter()
captured_packets = []


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
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
    elif ICMP in packet:
        protocol = "ICMP"
        source_port = ""
        destination_port = ""
    else:
        protocol = "Other IP"
        source_port = ""
        destination_port = ""

    size = len(packet)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    protocol_counts[protocol] += 1

    captured_packets.append({
        "timestamp": timestamp,
        "source_ip": source,
        "destination_ip": destination,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "size_bytes": size
    })

    print(
        f"Packet {packet_count}: "
        f"{source} -> {destination} | "
        f"{protocol} | {size} bytes"
    )


def export_csv():
    if not captured_packets:
        print("\nNo packets available to export.")
        return

    filename = "captured_traffic.csv"

    with open(filename, "w", newline="") as file:
        fieldnames = [
            "timestamp",
            "source_ip",
            "destination_ip",
            "protocol",
            "source_port",
            "destination_port",
            "size_bytes"
        ]

        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(captured_packets)

    print(f"\nTraffic exported successfully to {filename}")


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

    export_choice = input("\nExport captured packets to CSV? (y/n): ")

    if export_choice.lower() == "y":
        export_csv()


if __name__ == "__main__":
    main()
