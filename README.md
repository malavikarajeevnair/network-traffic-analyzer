# Network Traffic Analyzer

A Python-based network traffic analyzer that captures,
filters, and visualizes live network packets using Scapy
and Matplotlib.

## Features

- Live network packet capture
- Protocol filtering (TCP, UDP, ICMP, and all IP traffic)
- Configurable packet capture duration
- Packet statistics and total data calculation
- CSV export of captured packet metadata
- Graphical visualization of traffic by protocol

## Technologies Used

- Python
- Scapy
- Matplotlib
- CSV

## Requirements

- Python 3
- Npcap (Windows)
- Scapy
- Matplotlib

## Installation

1. Clone this repository:

   git clone (https://github.com/malavikarajeevnair/network-traffic-analyzer)

2. Navigate to the project directory:

   cd network-traffic-analyzer

3. Install the dependencies:

   python -m pip install -r requirements.txt

## Usage

Run the program:

    python main.py

Choose a protocol to capture:
- All IP traffic
- TCP
- UDP
- ICMP

Enter the capture duration in seconds.

After the capture finishes, the program displays
traffic statistics and offers CSV export and
graphical visualization.

## Output

The analyzer provides:
- Total packets captured
- Total captured data in bytes
- Packet counts by protocol
- CSV file containing packet metadata
- Bar chart showing traffic by protocol

## Limitations

- Requires appropriate permissions for packet capture.
- Captures packet metadata, not full traffic payloads.
- Basic protocol classification is used.
- Does not currently provide advanced intrusion detection.

## Future Improvements

- IP address-based traffic analysis
- Packet size distribution
- Top communicating hosts
- Basic anomaly detection
- Automated testing

## Disclaimer

Use this tool only on networks you own or have
permission to monitor.
