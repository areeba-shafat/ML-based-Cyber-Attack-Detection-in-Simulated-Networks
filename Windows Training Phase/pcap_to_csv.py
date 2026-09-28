from scapy.all import rdpcap, IP, TCP, UDP, ICMP
import pandas as pd
import os
import statistics
from collections import Counter
import math

PCAP_DIR = "pcaps"
OUTPUT_CSV = "output/ids_dataset.csv"

FILES_AND_LABELS = {
    "normal_ping.pcap": 0,
    "normal_http.pcap": 0,
    "normal_ssh.pcap": 0,
    "normal_ftp.pcap": 0,
    "attack_ping_dos.pcap": 1,
    "attack_syn_flood.pcap": 2,
    "attack_nmap_scan.pcap": 3,
    "attack_bruteforce.pcap": 4,
}

WINDOW_SIZE = 1.0


def extract_window_features(packets, label, traffic_type):
    rows = []

    ip_packets = [p for p in packets if IP in p]
    if not ip_packets:
        return rows

    start_time = float(ip_packets[0].time)
    current_window_start = start_time
    current_window_packets = []

    for pkt in ip_packets:
        pkt_time = float(pkt.time)

        if pkt_time - current_window_start <= WINDOW_SIZE:
            current_window_packets.append(pkt)
        else:
            row = calculate_features(current_window_packets, label, traffic_type)
            if row:
                rows.append(row)

            current_window_start = pkt_time
            current_window_packets = [pkt]

    if current_window_packets:
        row = calculate_features(current_window_packets, label, traffic_type)
        if row:
            rows.append(row)

    return rows


def calculate_features(pkts, label, traffic_type):
    if not pkts:
        return None

    lengths = [len(p) for p in pkts]
    times = [float(p.time) for p in pkts]

    duration = max(times) - min(times) if len(times) > 1 else 0.001
    packet_count = len(pkts)
    total_bytes = sum(lengths)

    tcp_count = 0
    udp_count = 0
    icmp_count = 0

    syn_count = 0
    ack_count = 0
    rst_count = 0
    fin_count = 0
    psh_count = 0
    urg_count = 0

    src_ports = set()
    dst_ports = set()
    src_ips = set()
    dst_ips = set()
    port_20_count = 0
    port_21_count = 0
    port_22_count = 0
    port_80_count = 0
    port_443_count = 0

    dst_port_list = []

    for pkt in pkts:
        if IP in pkt:
            src_ips.add(pkt[IP].src)
            dst_ips.add(pkt[IP].dst)

        if TCP in pkt:
            tcp_count += 1
            src_ports.add(pkt[TCP].sport)
            dst_ports.add(pkt[TCP].dport)

            dst_port = pkt[TCP].dport
            dst_port_list.append(dst_port)

            if dst_port == 20:
                port_20_count += 1
            elif dst_port == 21:
                port_21_count += 1
            elif dst_port == 22:
                port_22_count += 1
            elif dst_port == 80:
                port_80_count += 1
            elif dst_port == 443:
                port_443_count += 1

            flags = pkt[TCP].flags

            if flags & 0x02:
                syn_count += 1
            if flags & 0x10:
                ack_count += 1
            if flags & 0x04:
                rst_count += 1
            if flags & 0x01:
                fin_count += 1
            if flags & 0x08:
                psh_count += 1
            if flags & 0x20:
                urg_count += 1

        elif UDP in pkt:
            udp_count += 1
            src_ports.add(pkt[UDP].sport)
            dst_ports.add(pkt[UDP].dport)

            dst_port = pkt[UDP].dport
            dst_port_list.append(dst_port)

            if dst_port == 20:
                port_20_count += 1
            elif dst_port == 21:
                port_21_count += 1
            elif dst_port == 22:
                port_22_count += 1
            elif dst_port == 80:
                port_80_count += 1
            elif dst_port == 443:
                port_443_count += 1

        elif ICMP in pkt:
            icmp_count += 1

    avg_packet_length = statistics.mean(lengths)
    min_packet_length = min(lengths)
    max_packet_length = max(lengths)

    packets_per_second = packet_count / duration
    bytes_per_second = total_bytes / duration
    top_dst_port = Counter(dst_port_list).most_common(1)[0][0] if dst_port_list else 0

    avg_bytes_per_pkt    = total_bytes / (packet_count + 1)
    rst_syn_ratio        = rst_count / (syn_count + 1)
    rst_per_second       = rst_count / (duration + 0.001)
    unique_src_ports_log = math.log1p(len(src_ports))
    port_entropy         = len(dst_ports) / (packet_count + 1)
    port22_rst_product   = port_22_count * rst_count
    port22_src_diversity = port_22_count * len(src_ports)

    return {
        "traffic_type": traffic_type,
        "packet_count": packet_count,
        "total_bytes": total_bytes,
        "avg_packet_length": avg_packet_length,
        "min_packet_length": min_packet_length,
        "max_packet_length": max_packet_length,
        "duration": duration,
        "packets_per_second": packets_per_second,
        "bytes_per_second": bytes_per_second,
        "tcp_count": tcp_count,
        "udp_count": udp_count,
        "icmp_count": icmp_count,
        "syn_count": syn_count,
        "ack_count": ack_count,
        "rst_count": rst_count,
        "fin_count": fin_count,
        "psh_count": psh_count,
        "urg_count": urg_count,
        "unique_src_ports": len(src_ports),
        "unique_dst_ports": len(dst_ports),
        "unique_src_ips": len(src_ips),
        "unique_dst_ips": len(dst_ips),
        "port_20_count": port_20_count,
        "port_21_count": port_21_count,
        "port_22_count": port_22_count,
        "port_80_count": port_80_count,
        "port_443_count": port_443_count,
        "top_dst_port": top_dst_port,
        "avg_bytes_per_pkt":    avg_bytes_per_pkt,
        "rst_syn_ratio":        rst_syn_ratio,
        "rst_per_second":       rst_per_second,
        "unique_src_ports_log": unique_src_ports_log,
        "port_entropy":         port_entropy,
        "port22_rst_product":   port22_rst_product,
        "port22_src_diversity": port22_src_diversity,
        "label": label,
    }


def main():
    all_rows = []

    os.makedirs("output", exist_ok=True)

    for filename, label in FILES_AND_LABELS.items():
        pcap_path = os.path.join(PCAP_DIR, filename)

        if not os.path.exists(pcap_path):
            print(f"[MISSING] {pcap_path}")
            continue

        print(f"[READING] {filename}")

        packets = rdpcap(pcap_path)
        traffic_type = filename.replace(".pcap", "")

        rows = extract_window_features(packets, label, traffic_type)
        all_rows.extend(rows)

        print(f"[DONE] {filename}: {len(rows)} rows extracted")

    df = pd.DataFrame(all_rows)
    df.to_csv(OUTPUT_CSV, index=False)

    print("\nDataset created successfully!")
    print(f"Saved to: {OUTPUT_CSV}")
    print(f"Total rows: {len(df)}")
    print("\nLabel distribution:")
    print(df["label"].value_counts())


if __name__ == "__main__":
    main()