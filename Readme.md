# Unified Network Sniffer & Port Scanner 🚀

A compact Python toolkit for local network reconnaissance: discover live hosts with ARP, capture packets with **Scapy**, and scan TCP ports asynchronously — all in one workflow. Designed for learning, research, and lab environments.

> **Intended use:** educational, research, and authorized security testing only. Do not run against networks you do not own or have explicit permission to test.

---

## Features

* ARP-based host discovery (fast local-LAN discovery)
* Packet sniffing using **Scapy** (live packet summaries)
* Asynchronous, high-speed TCP port scanning with progress bars (`tqdm`)
* Simple CLI + optional non-interactive flags
* Exportable JSON results for later analysis

---

## Quick start

### Requirements

* Python **3.8+**
* `scapy`, `tqdm` (install with `pip`)
* Root/Administrator privileges for ARP scanning and packet capture

```bash
pip install scapy tqdm
```

> On Windows, run inside WSL or ensure Scapy and WinPcap/Npcap are configured properly. Linux/macOS are recommended for full functionality.

### Clone

```bash
git clone https://github.com/a1ex18/Advanced-Network-Reconnaissance-Tool.git
cd Advanced-Network-Reconnaissance-Tool
```

---

## Usage

The repository's interactive entry point is `main.py` (or another similarly named script). Run it with elevated privileges:

```bash
sudo python main.py
```

You will be prompted for:

* Network CIDR (example: `192.168.1.0/24`)
* Interface (optional; e.g., `eth0` or `wlan0`)
* Port range (example: `20-1024`)

During the run the tool will:

1. Perform an ARP scan and list live hosts.
2. Start packet sniffing and display packet summaries (CTRL+C to stop sniffing).
3. Run asynchronous TCP scans on discovered hosts and show a `tqdm` progress bar.
4. Optionally save results to a JSON file (default: `scan_results.json`).

---

## Non-interactive / CLI flags

You can run the tools non-interactively using flags. Example pattern (also shown below in the `argparse` snippet):

```bash
sudo python main.py --network 192.168.1.0/24 --iface wlan0 --ports 20-1024 --json-out scan_results.json --no-sniff
```

This is useful for automation or CI-like runs in a lab environment.

---

## `scan_results.json` (schema example)

A consistent JSON output helps downstream automation. A recommended schema:

```json
{
  "scan_timestamp": "2025-09-15T00:00:00Z",
  "network": "192.168.1.0/24",
  "interface": "wlan0",
  "hosts": [
    {
      "ip": "192.168.1.10",
      "mac": "AA:BB:CC:11:22:33",
      "open_ports": [
        {"port": 22, "service": "ssh", "banner": null, "state": "open"}
      ],
      "notes": "ARP discovered"
    }
  ]
}
```

---

## Troubleshooting & tips

* **Permissions:** Scapy and ARP require root. Use `sudo` on Linux.
* **Interface issues:** Use `ip a` / `ifconfig` to list available interfaces and pass via `--iface`.
* **Windows users:** Scapy on native Windows has restrictions—prefer WSL2 with Npcap installed.
* **Slow scans:** Reduce port-range or tune the scanner concurrency parameter (documented in code).

---

## Safety & ethics

**Do not use this tool** on networks you do not own or have explicit authorization to test. Network scanning and sniffing may be illegal or violate terms of service. Keep logs of written permission when performing tests for third parties.

---

## Contributing

Contributions are welcome: bug reports, documentation improvements, and feature PRs. Suggested features: UDP scanning, service detection, banner grabbing, rate-limiting, and unit tests.

---

## License

This project is provided for educational and research use. See the repository license file for full terms.

---

*Repo source: `a1ex18/Advanced-Network-Reconnaissance-Tool` on GitHub.*
