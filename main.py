from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
from collections import defaultdict
import csv
import matplotlib.pyplot as plt


packets = []
protocol_counts = {}
total_bytes = 0

source_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})
destination_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})
packet_sizes = []


def analyze_packet(packet):
    global total_bytes

    if IP not in packet:
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    source = packet[IP].src
    destination = packet[IP].dst
    size = len(packet)

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
        source_port = "-"
        destination_port = "-"

    else:
        protocol = "Other IP"
        source_port = "-"
        destination_port = "-"

    record = {
        "Timestamp": timestamp,
        "Source": source,
        "Destination": destination,
        "Protocol": protocol,
        "Source Port": source_port,
        "Destination Port": destination_port,
        "Size": size
    }

    packets.append(record)
    packet_sizes.append(size)

    protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
    total_bytes += size

    source_stats[source]["packets"] += 1
    source_stats[source]["bytes"] += size

    destination_stats[destination]["packets"] += 1
    destination_stats[destination]["bytes"] += size

    print(
        f"{timestamp} | {source} -> {destination} | "
        f"{protocol} | {size} bytes"
    )


def export_csv():
    if not packets:
        print("No packets to export.")
        return

    filename = "captured_traffic.csv"

    with open(filename, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=packets[0].keys())
        writer.writeheader()
        writer.writerows(packets)

    print(f"Traffic exported to {filename}")


def show_statistics():
    print("\n--- Traffic Statistics ---")
    print(f"Total packets: {len(packets)}")
    print(f"Total data: {total_bytes} bytes")

    print("\nPackets by protocol:")
    for protocol, count in protocol_counts.items():
        print(f"{protocol}: {count}")


def show_ip_analysis():
    if not packets:
        print("\nNo IP traffic captured.")
        return

    print("\n--- Top 5 Source IP Addresses ---")

    top_sources = sorted(
        source_stats.items(),
        key=lambda item: item[1]["packets"],
        reverse=True
    )[:5]

    for ip, stats in top_sources:
        print(
            f"{ip}: {stats['packets']} packets, "
            f"{stats['bytes']} bytes sent"
        )

    print("\n--- Top 5 Destination IP Addresses ---")

    top_destinations = sorted(
        destination_stats.items(),
        key=lambda item: item[1]["packets"],
        reverse=True
    )[:5]

    for ip, stats in top_destinations:
        print(
            f"{ip}: {stats['packets']} packets, "
            f"{stats['bytes']} bytes received"
        )


def show_packet_size_analysis():
    if not packet_sizes:
        print("\nNo packet sizes available.")
        return

    average_size = sum(packet_sizes) / len(packet_sizes)
    minimum_size = min(packet_sizes)
    maximum_size = max(packet_sizes)

    print("\n--- Packet Size Analysis ---")
    print(f"Average packet size: {average_size:.2f} bytes")
    print(f"Smallest packet: {minimum_size} bytes")
    print(f"Largest packet: {maximum_size} bytes")


def show_chart():
    if not protocol_counts:
        print("No traffic captured. There is nothing to visualize.")
        return

    protocols = list(protocol_counts.keys())
    counts = list(protocol_counts.values())

    plt.figure(figsize=(8, 5))
    plt.bar(protocols, counts)

    plt.title("Network Traffic by Protocol")
    plt.xlabel("Protocol")
    plt.ylabel("Number of Packets")
    plt.grid(axis="y", linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.show()


def show_packet_size_chart():
    if not packet_sizes:
        print("No packet sizes available.")
        return

    plt.figure(figsize=(8, 5))
    plt.hist(packet_sizes, bins=20)

    plt.title("Packet Size Distribution")
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("Number of Packets")
    plt.grid(axis="y", linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.show()


def main():
    print("=== Network Traffic Analyzer ===")

    print("\nChoose a protocol:")
    print("1. All IP traffic")
    print("2. TCP")
    print("3. UDP")
    print("4. ICMP")

    choice = input("Enter your choice (1-4): ")

    filters = {
        "1": "ip",
        "2": "tcp",
        "3": "udp",
        "4": "icmp"
    }

    if choice not in filters:
        print("Invalid choice.")
        return

    try:
        duration = int(input("Enter capture duration in seconds: "))

        if duration <= 0:
            print("Duration must be greater than zero.")
            return

    except ValueError:
        print("Please enter a valid number.")
        return

    print(
        f"\nCapturing {filters[choice]} traffic "
        f"for {duration} seconds..."
    )
    print("Press Ctrl+C to stop early.\n")

    try:
        sniff(
            filter=filters[choice],
            prn=analyze_packet,
            timeout=duration,
            store=False
        )

    except PermissionError:
        print("Permission denied. Try running IDLE as administrator.")
        return

    except Exception as error:
        print(f"Capture error: {error}")
        return

    show_statistics()
    show_ip_analysis()
    show_packet_size_analysis()

    export_choice = input("\nExport packets to CSV? (y/n): ").lower()

    if export_choice == "y":
        export_csv()

    chart_choice = input("\nShow protocol chart? (y/n): ").lower()

    if chart_choice == "y":
        show_chart()

    size_chart_choice = input(
        "\nShow packet size distribution? (y/n): "
    ).lower()

    if size_chart_choice == "y":
        show_packet_size_chart()


if __name__ == "__main__":
    main()
