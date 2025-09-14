import asyncio
import socket
import ssl
import json
import os
import time
import requests
from collections import defaultdict
from tqdm import tqdm
from scapy.all import sniff, IP, ARP, Ether, srp, traceroute

captured_ips = set()
results = {}
ttl_data = {}
mac_data = {}
semaphore = asyncio.Semaphore(2)
port_usage = defaultdict(int)
start_time = None

def guess_os(ttl):
    if ttl >= 255:
        return "Router/IoT"
    elif ttl >= 128:
        return "Windows"
    elif ttl >= 64:
        return "Linux/Unix"
    return "Unknown"

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def geoip_lookup(ip):
    try:
        res = requests.get(f"https://ipapi.co/{ip}/json", timeout=5)
        data = res.json()
        return f"{data.get('city')}, {data.get('country_name')}"
    except:
        return "Unknown"

def get_ssl_info(ip):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                return {
                    "CN": cert.get("subject", [[("", "")]])[0][0][1],
                    "Issuer": cert.get("issuer", [[("", "")]])[0][0][1],
                    "Expiry": cert.get("notAfter")
                }
    except:
        return {}

async def grab_banner(ip, port):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2)
        await asyncio.sleep(1)
        banner = await reader.read(1024)
        writer.close()
        await writer.wait_closed()
        return banner.decode(errors="ignore").strip()
    except:
        return "Unknown"

async def scan_port(ip, port, timeout=1):
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return port
    except:
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return port
        except:
            return None

async def scan_host_ports(ip, ports):
    open_ports = {}
    tasks = [scan_port(ip, port) for port in ports]
    for f in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc=f"Scanning {ip}"):
        port = await f
        if port:
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            banner = await grab_banner(ip, port)
            open_ports[port] = {"service": service, "banner": banner}
            port_usage[port] += 1
    return open_ports

def run_traceroute(ip):
    try:
        res, _ = traceroute(ip, maxttl=10, verbose=False)
        return [r[1].src for r in res]
    except:
        return []

async def handle_ip(ip, ports):
    async with semaphore:
        print(f"\n[SCAN STARTED] {ip}")
        hostname = reverse_dns(ip)
        guessed_os = guess_os(ttl_data.get(ip, 0))
        mac = mac_data.get(ip, "Unknown")
        geo = geoip_lookup(ip) if not ip.startswith("192.168.") else "Local"
        ssl_info = get_ssl_info(ip) if 443 in ports else {}
        traceroute_path = run_traceroute(ip)

        open_ports = await scan_host_ports(ip, ports)

        results[ip] = {
            "hostname": hostname,
            "guessed_os": guessed_os,
            "mac": mac,
            "geoip": geo,
            "ssl": ssl_info,
            "traceroute": traceroute_path,
            "open_ports": open_ports
        }

        with open("scan_results.json", "w") as f:
            json.dump(results, f, indent=4)

        print(f"[SCAN COMPLETE] {ip}")

def passive_sniff(interface, count, ports):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    tasks = set()

    def process_packet(pkt):
        if IP in pkt:
            for ip in [pkt[IP].src, pkt[IP].dst]:
                if ip not in captured_ips:
                    print(f"[NEW IP FOUND] {ip}")
                    captured_ips.add(ip)
                    ttl_data[ip] = pkt[IP].ttl
                    task = asyncio.ensure_future(handle_ip(ip, ports))
                    tasks.add(task)

    sniff(prn=process_packet, iface=interface, filter="ip", store=False, count=count)
    if tasks:
        loop.run_until_complete(asyncio.wait(tasks))

def arp_discovery(interface):
    print(f"[*] Sending ARP requests on {interface}...")
    ip_range = "192.168.1.0/24"
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=ip_range)
    packet = ether / arp
    ans, _ = srp(packet, timeout=2, iface=interface, verbose=False)
    for _, rcv in ans:
        ip = rcv.psrc
        mac = rcv.hwsrc
        captured_ips.add(ip)
        mac_data[ip] = mac
        ttl_data[ip] = 64 

def show_port_trends():
    print("\n[*] Port Activity Trend (most common open ports):")
    for port, count in sorted(port_usage.items(), key=lambda x: x[1], reverse=True):
        print(f"Port {port}: Open on {count} device(s)")

def show_network_map():
    print("\n[*] Network Map (Simplified):")
    for ip, data in results.items():
        print(f"└── {ip} ({data['hostname']}) [{data['mac']}] → {data['guessed_os']}")

def main():
    global start_time

    mode = input("Choose mode:\n1. Passive Sniffing\n2. Active ARP Discovery\n> ").strip()
    interface = input("Enter network interface (default=wlan0): ").strip() or "wlan0"

    port_range = input("Enter port range to scan (default=20-1024): ").strip()
    if port_range:
        try:
            start_port, end_port = map(int, port_range.split("-"))
            ports = list(range(start_port, end_port + 1))
        except:
            print("[!] Invalid range. Using default 20–1024.")
            ports = list(range(20, 1025))
    else:
        ports = list(range(20, 1025))

    if os.path.exists("scan_results.json"):
        os.remove("scan_results.json")

    start_time = time.time()

    if mode == "1":
        try:
            pkt_count = int(input("Packets to sniff (default=100): ").strip() or "100")
        except:
            pkt_count = 100
        passive_sniff(interface, pkt_count, ports)
    elif mode == "2":
        arp_discovery(interface)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        tasks = [handle_ip(ip, ports) for ip in captured_ips]
        loop.run_until_complete(asyncio.gather(*tasks))
        show_port_trends()
        show_network_map()
    else:
        print("[!] Invalid mode selected.")

    elapsed = round(time.time() - start_time, 2)
    print(f"\n[*] SCAN COMPLETE: {len(results)} IPs scanned")
    print(f"[*] Total open ports found: {sum(len(r['open_ports']) for r in results.values())}")
    print(f"[*] Duration: {elapsed} seconds")
    print("[*] Results saved to scan_results.json")

if __name__ == "__main__":
    main()
