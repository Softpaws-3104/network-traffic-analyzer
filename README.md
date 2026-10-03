# Network Traffic Analyzer

A Python-based network traffic analysis project built using Kali Linux, Scapy, tcpdump, and Wireshark.

## Features

- PCAP file analysis
- Protocol identification
- Source and destination IP statistics
- Basic threshold-based anomaly detection
- Time-based traffic spike detection
- CSV report generation

## Requirements

- Kali Linux
- Python 3
- Scapy
- tcpdump
- Wireshark

## Usage

Navigate to the project directory:

```bash
cd network-traffic-analyzer
```

Run the analyzer:

```bash
python3 analyzer.py
```

The script reads `capture.pcap` and generates a traffic report at:

`reports/traffic_report.csv`

## Project Status

Initial prototype completed.

## Disclaimer

For educational use and authorized network traffic analysis only.
