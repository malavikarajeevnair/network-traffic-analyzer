from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import csv
import matplotlib.pyplot as plt


packets = []
protocol_counts = {}
total_bytes = 0


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

    protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
    total_bytes += size

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

    print(f"\nCapturing {filters[choice]} traffic for {duration} seconds...")
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

    export_choice = input("\nExport packets to CSV? (y/n): ").lower()

    if export_choice == "y":
        export_csv()

    chart_choice = input("\nShow traffic chart? (y/n): ").lower()

    if chart_choice == "y":
        show_chart()


if __name__ == "__main__":
    main()
