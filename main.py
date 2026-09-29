from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
from datetime import datetime
import csv
import matplotlib.pyplot as plt
import time


packets = []
protocol_counts = defaultdict(int)
total_bytes = 0

source_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})
destination_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})
packet_sizes = []

# Packets captured in each one-second interval
traffic_timeline = defaultdict(lambda: defaultdict(int))

PACKET_THRESHOLD = 100
capture_start = None


def analyze_packet(packet):
    global total_bytes

    if IP not in packet:
        return

    timestamp = datetime.now()
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
        "Timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S.%f"),
        "Source": source,
        "Destination": destination,
        "Protocol": protocol,
        "Source Port": source_port,
        "Destination Port": destination_port,
        "Size": size
    }

    packets.append(record)
    packet_sizes.append(size)

    protocol_counts[protocol] += 1
    total_bytes += size

    source_stats[source]["packets"] += 1
    source_stats[source]["bytes"] += size

    destination_stats[destination]["packets"] += 1
    destination_stats[destination]["bytes"] += size

    # Group packets into one-second intervals
    if capture_start is not None:
        elapsed = int((time.monotonic() - capture_start))
        traffic_timeline[elapsed][protocol] += 1

    print(
        f"{timestamp.strftime('%H:%M:%S')} | "
        f"{source} -> {destination} | "
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

    print("\n--- Packet Size Analysis ---")
    print(f"Average packet size: {sum(packet_sizes) / len(packet_sizes):.2f} bytes")
    print(f"Smallest packet: {min(packet_sizes)} bytes")
    print(f"Largest packet: {max(packet_sizes)} bytes")


def detect_anomalies():
    print("\n--- Basic Anomaly Detection ---")
    print(f"Packet threshold: {PACKET_THRESHOLD}")

    suspicious_ips = [
        (ip, stats["packets"])
        for ip, stats in source_stats.items()
        if stats["packets"] > PACKET_THRESHOLD
    ]

    if suspicious_ips:
        print("\nHigh packet counts detected:")
        for ip, count in suspicious_ips:
            print(f"WARNING: {ip} sent {count} packets.")
    else:
        print("No IP addresses exceeded the packet threshold.")

    print("Note: High packet counts do not prove malicious activity.")


def show_chart():
    if not protocol_counts:
        print("No traffic captured.")
        return

    plt.figure(figsize=(8, 5))
    plt.bar(protocol_counts.keys(), protocol_counts.values())
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


def show_traffic_timeline():
    if not traffic_timeline:
        print("No traffic timeline available.")
        return

    duration = max(traffic_timeline.keys()) + 1
    seconds = list(range(duration))

    protocols = sorted(protocol_counts.keys())

    plt.figure(figsize=(10, 5))

    for protocol in protocols:
        counts = [
            traffic_timeline[second].get(protocol, 0)
            for second in seconds
        ]
        plt.plot(seconds, counts, marker="o", label=protocol)

    plt.title("Network Traffic Over Time")
    plt.xlabel("Seconds Since Capture Started")
    plt.ylabel("Packets per Second")
    plt.xticks(seconds)
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.legend()
    plt.tight_layout()
    plt.show()


def main():
    global capture_start

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

    print(f"\nCapturing {filters[choice]} traffic for {duration} seconds...")
    print("Press Ctrl+C to stop early.\n")

    capture_start = time.monotonic()

    try:
        sniff(
            filter=filters[choice],
            prn=analyze_packet,
            timeout=duration,
            store=False
        )
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except Exception as error:
        print(f"Capture error: {error}")
        return

    show_statistics()
    show_ip_analysis()
    show_packet_size_analysis()
    detect_anomalies()

    if input("\nExport packets to CSV? (y/n): ").lower() == "y":
        export_csv()

    if input("\nShow protocol chart? (y/n): ").lower() == "y":
        show_chart()

    if input("\nShow packet size chart? (y/n): ").lower() == "y":
        show_packet_size_chart()

    if input("\nShow traffic timeline? (y/n): ").lower() == "y":
        show_traffic_timeline()


if __name__ == "__main__":
    main()
