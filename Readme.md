Unified Network Sniffer and Port Scanner
🚀 A Python tool to discover live hosts, capture network packets, and scan open TCP ports — all in one workflow!

Features
ARP-based host discovery

Packet sniffing with Scapy

Asynchronous, high-speed TCP port scanning

Command-line interface (CLI) for easy use

Progress bars using tqdm

Export scan results to JSON

Requirements

pip install scapy tqdm
Also requires Python 3.8+.

Usage

python main.py
Follow the prompts:

Enter network CIDR (example: 192.168.1.0/24)

Specify interface (optional)

Enter port range (example: 20-1024)

Output
Displays live hosts

Shows packet details (source -> destination)

Scans open ports with real-time progress

Optionally saves results to scan_results.json

License
Free for educational and research purposes.

