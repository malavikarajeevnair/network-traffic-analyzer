# Network Traffic Analyzer

A Python-based network traffic analyzer that captures,
analyzes, and visualizes live network packets.

The project uses Scapy for packet capture and analysis,
and Matplotlib for traffic visualization.

## Features

- Live network packet capture
- TCP, UDP, ICMP, and all-IP traffic filtering
- Configurable capture duration
- Packet counts and total traffic statistics
- Source and destination IP analysis
- Top 5 source and destination IP addresses
- Packet-size statistics
- Protocol traffic visualization
- Packet-size distribution histogram
- CSV export of packet metadata
- Basic packet-count anomaly detection
- Automated unit tests

## Technologies

- Python
- Scapy
- Matplotlib
- unittest
- CSV

## Requirements

- Python 3
- Npcap (Windows)
- Scapy
- Matplotlib

## Installation

Clone the repository:

    git clone (https://github.com/malavikarajeevnair/network-traffic-analyzer.git)

Navigate to the project directory:

    cd network-traffic-analyzer

Install dependencies:

    python -m pip install -r requirements.txt

## Usage

Run the analyzer:

    python main.py

Choose a traffic filter and enter the capture duration.

After capturing traffic, the program displays:
- Total packets
- Total captured bytes
- Protocol distribution
- Top source and destination IP addresses
- Packet-size statistics
- Basic anomaly detection results

You can also export packet metadata to CSV and
display traffic charts.

## Running Tests

Run the automated tests with:

    python -m unittest test_analyzer.py

The tests cover packet classification, packet-size
tracking, byte counting, and anomaly-threshold logic.

## Anomaly Detection

The analyzer includes a basic rule-based detector
that flags source IP addresses exceeding a configured
packet-count threshold.

This is a demonstration of simple anomaly detection.
It is not a complete intrusion detection system.

## Project Structure

    network-traffic-analyzer/
    |
    |-- main.py
    |-- test_analyzer.py
    |-- requirements.txt
    |-- README.md

## Limitations

- Requires appropriate permissions for live capture.
- Captures packet metadata rather than application payloads.
- Anomaly detection uses a fixed packet-count threshold.
- High packet counts do not necessarily indicate malicious activity.
- Live capture and automated tests are separate operations.

## Future Improvements

- Configurable anomaly thresholds
- Traffic analysis over time
- More advanced anomaly detection
- Improved graphical interface
- Additional automated tests

## Disclaimer

Use this tool only on networks you own or have
permission to monitor.
