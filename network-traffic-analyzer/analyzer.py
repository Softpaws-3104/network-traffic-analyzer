import csv
from datetime import datetime
from collections import defaultdict
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS
from collections import Counter

packets = rdpcap("capture.pcap")

protocols = Counter()
sources = Counter()
destinations = Counter()

for packet in packets:
    if ARP in packet:
        protocols["ARP"] += 1

    if IP in packet:
        ip = packet[IP]
        sources[ip.src] += 1
        destinations[ip.dst] += 1

        if ICMP in packet:
            protocols["ICMP"] += 1
        elif TCP in packet:
            protocols["TCP"] += 1
        elif UDP in packet:
            if DNS in packet:
                protocols["DNS"] += 1
            else:
                protocols["UDP"] += 1

print("NETWORK TRAFFIC REPORT")
print("=" * 30)

print(f"Total packets: {len(packets)}")

print("\nProtocol distribution:")
for protocol, count in protocols.most_common():
    print(f"{protocol}: {count}")

print("\nTop source IPs:")
for ip, count in sources.most_common(5):
    print(f"{ip}: {count} packets")

print("\nTop destination IPs:")
for ip, count in destinations.most_common(5):
    print(f"{ip}: {count} packets")
print("\nTRAFFIC ANOMALY CHECK")
print("=" * 30)

threshold = 20

for ip, count in sources.most_common():
    if count > threshold:
        print(f"[ALERT] {ip}: {count} packets")
    else:
        print(f"[NORMAL] {ip}: {count} packets")
print("\nTRAFFIC RATE ANALYSIS")
print("=" * 30)

time_windows = defaultdict(int)

start_time = float(packets[0].time)

for packet in packets:
    if IP in packet:
        elapsed = int(float(packet.time) - start_time)
        time_windows[elapsed] += 1

threshold = 5

for second, count in sorted(time_windows.items()):
    status = "[SPIKE]" if count > threshold else "[NORMAL]"
    print(f"{second:>4}s | {count:>3} packets | {status}")

print("\nPEAK TRAFFIC")
print("=" * 30)

if time_windows:
    peak_second = max(time_windows, key=time_windows.get)
    peak_count = time_windows[peak_second]
    print(f"Peak: {peak_count} packets")
    print(f"Elapsed time: {peak_second} seconds")
print("\nEXPORTING TRAFFIC REPORT")
print("=" * 30)

with open("traffic_report.csv", "w", newline="") as file:
    writer = csv.writer(file)

    writer.writerow([
        "Elapsed Second",
        "Packet Count",
        "Status"
    ])

    for second, count in sorted(time_windows.items()):
        status = "SPIKE" if count > threshold else "NORMAL"

        writer.writerow([
            second,
            count,
            status
        ])

print("Report saved as traffic_report.csv")
print("\nEXPORTING TRAFFIC REPORT")
print("=" * 30)

with open("traffic_report.csv", "w", newline="") as file:
    writer = csv.writer(file)

    writer.writerow([
        "Elapsed Second",
        "Packet Count",
        "Status"
    ])

    for second, count in sorted(time_windows.items()):
        status = "SPIKE" if count > threshold else "NORMAL"

        writer.writerow([
            second,
            count,
            status
        ])

print("Report saved as traffic_report.csv")
