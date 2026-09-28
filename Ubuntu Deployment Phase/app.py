from flask import Flask, jsonify, render_template_string, render_template
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import time
import joblib
import json
import pandas as pd
import os
import csv
from collections import Counter, deque
import math

INTERFACE = "ens33"

BPF_FILTER = (
    "ip and "
    "(host 192.168.188.130 or host 192.168.188.131 or host 192.168.188.133) "
    "and not host 192.168.188.132 "
    "and not host 192.168.188.128 "
    "and not host 192.168.188.1 "
    "and not net 192.168.17.0/24 "
    "and not net 192.168.59.0/24 "
    "and not net 192.168.187.0/24 "
    "and not net 224.0.0.0/4 "
    "and not host 255.255.255.255"
)

WINDOW_SIZE = 1.0
ALERT_HOLD_TIME = 5

TIMELINE_BUCKET_SECONDS = 60

SESSION_DATE = time.strftime("%Y-%m-%d")
SESSION_TIME = time.strftime("%H_%M_%S")
CSV_LOG_PATH = f"logs/{SESSION_DATE}/{SESSION_TIME}_traffic_log.csv"

MODEL_PATH = "models/best_ids_model.pkl"
FEATURE_COLUMNS_PATH = "models/feature_columns.pkl"
LABEL_MAPPING_PATH = "models/label_mapping.json"

model = joblib.load(MODEL_PATH)
feature_columns = joblib.load(FEATURE_COLUMNS_PATH)

with open(LABEL_MAPPING_PATH, "r") as f:
    label_mapping = json.load(f)

label_mapping = {int(k): v for k, v in label_mapping.items()}

app = Flask(__name__)

lock = threading.Lock()

latest_status = {
    "status": "SAFE",
    "color": "green",
    "attack_type": "No traffic",
    "source_ip": "-",
    "destination_ip": "-",
    "protocol": "-",
    "packet_count": 0,
    "total_bytes": 0,
    "packets_per_second": 0,
    "timestamp": time.strftime("%H:%M:%S"),
}

last_attack_time = 0
last_attack_status = None

recent_attacks = {}

stats = {
    "total_packets": 0,
    "normal_packets": 0,
    "attack_packets": 0,
    "detected_threats": 0,
}

class_counts = {
    "Normal": 0,
    "Ping DoS": 0,
    "SYN Flood": 0,
    "Nmap Scan": 0,
    "Brute Force": 0,
}

timeline_labels = deque(maxlen=12)
timeline_volume = deque(maxlen=12)
timeline_threats = deque(maxlen=12)
timeline_bucket_ids = deque(maxlen=12)

detection_history = deque(maxlen=10)
recent_alerts = deque(maxlen=6)


def init_csv_log():
    log_dir = os.path.dirname(CSV_LOG_PATH)
    os.makedirs(log_dir, exist_ok=True)

    with open(CSV_LOG_PATH, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([
                "timestamp",
                "status",
                "prediction_label",
                "attack_type",
                "source_ip",
                "destination_ip",
                "protocol",
                "packet_count",
                "total_bytes",
                "packets_per_second"
            ])


def write_csv_log(status_data, prediction):
    log_dir = os.path.dirname(CSV_LOG_PATH)
    os.makedirs("logs", exist_ok=True)

    with open(CSV_LOG_PATH, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            time.strftime("%Y-%m-%d %H:%M:%S"),
            status_data.get("status", "-"),
            prediction,
            status_data.get("attack_type", "-"),
            status_data.get("source_ip", "-"),
            status_data.get("destination_ip", "-"),
            status_data.get("protocol", "-"),
            status_data.get("packet_count", 0),
            status_data.get("total_bytes", 0),
            status_data.get("packets_per_second", 0),
        ])

def detect_protocol(features):
    if features["icmp_count"] > 0 and features["tcp_count"] == 0:
        return "ICMP"

    if features["tcp_count"] > 0:
        return "TCP"

    if features["udp_count"] > 0:
        return "UDP"

    return "IP"


def get_threat_level(attack_type):
    if attack_type == "SYN Flood":
        return "Critical"

    if attack_type in ["Ping DoS", "Brute Force"]:
        return "High"

    if attack_type == "Nmap Scan":
        return "Medium"

    return "Low"

def determine_flow_direction(ip_packets):
    service_ports = {20, 21, 22, 80, 443}

    for pkt in ip_packets:
        if IP in pkt and TCP in pkt:
            flags = pkt[TCP].flags

            syn_set = bool(flags & 0x02)
            ack_set = bool(flags & 0x10)

            if syn_set and not ack_set:
                return pkt[IP].src, pkt[IP].dst

    for pkt in ip_packets:
        if IP in pkt and ICMP in pkt:
            if pkt[ICMP].type == 8:
                return pkt[IP].src, pkt[IP].dst

    for pkt in ip_packets:
        if IP in pkt and TCP in pkt:
            if pkt[TCP].dport in service_ports:
                return pkt[IP].src, pkt[IP].dst

        if IP in pkt and UDP in pkt:
            if pkt[UDP].dport in service_ports:
                return pkt[IP].src, pkt[IP].dst

    ip_pairs = [(pkt[IP].src, pkt[IP].dst) for pkt in ip_packets if IP in pkt]

    if ip_pairs:
        return Counter(ip_pairs).most_common(1)[0][0]

    return "-", "-"

def get_flow_key(pkt):
    if IP not in pkt:
        return None

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    if TCP in pkt:
        protocol = "TCP"
        dst_port = pkt[TCP].dport

    elif UDP in pkt:
        protocol = "UDP"
        dst_port = pkt[UDP].dport

    elif ICMP in pkt:
        protocol = "ICMP"
        dst_port = 0

    else:
        protocol = "IP"
        dst_port = 0

    return (src_ip, dst_ip, protocol, dst_port)

def group_packets_by_flow(packets):
    flows = {}

    for pkt in packets:
        key = get_flow_key(pkt)

        if key is None:
            continue

        if key not in flows:
            flows[key] = []

        flows[key].append(pkt)

    return flows

def calculate_features(pkts):
    if not pkts:
        return None

    ip_packets = [p for p in pkts if IP in p]

    if not ip_packets:
        return None

    lengths = [len(p) for p in ip_packets]
    times = [float(p.time) for p in ip_packets]

    duration = max(times) - min(times) if len(times) > 1 else 0.001
    packet_count = len(ip_packets)
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
    
    dst_port_list = []

    src_ports = set()
    dst_ports = set()
    src_ips = set()
    dst_ips = set()
    port_20_count = 0
    port_21_count = 0
    port_22_count = 0
    port_80_count = 0
    port_443_count = 0
    ip_pairs = []

    for pkt in ip_packets:
        src_ips.add(pkt[IP].src)
        dst_ips.add(pkt[IP].dst)
        ip_pairs.append((pkt[IP].src, pkt[IP].dst))

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

    avg_packet_length = sum(lengths) / len(lengths)
    min_packet_length = min(lengths)
    max_packet_length = max(lengths)

    packets_per_second = packet_count / duration
    bytes_per_second = total_bytes / duration
    
    top_dst_port = Counter(dst_port_list).most_common(1)[0][0] if dst_port_list else 0

    top_src_ip, top_dst_ip = determine_flow_direction(ip_packets)
    avg_bytes_per_pkt    = total_bytes / (packet_count + 1)
    rst_syn_ratio        = rst_count / (syn_count + 1)
    rst_per_second       = rst_count / (duration + 0.001)
    unique_src_ports_log = math.log1p(len(src_ports))
    port_entropy         = len(dst_ports) / (packet_count + 1)
    port22_rst_product   = port_22_count * rst_count
    port22_src_diversity = port_22_count * len(src_ports)

    features = {
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
    }

    protocol = detect_protocol(features)

    return features, top_src_ip, top_dst_ip, protocol

def add_history_item(status_data):
    threat_level = get_threat_level(status_data["attack_type"])

    item = {
        "time": status_data["timestamp"],
        "source_ip": status_data["source_ip"],
        "destination_ip": status_data["destination_ip"],
        "protocol": status_data["protocol"],
        "packet_count": status_data["packet_count"],
        "prediction": status_data["attack_type"],
        "level": threat_level,
        "status": status_data["status"],
    }

    detection_history.appendleft(item)


def add_alert_item(status_data):
    threat_level = get_threat_level(status_data["attack_type"])

    if status_data["status"] == "ALERT":
        message = (
            f"{status_data['attack_type']} detected from "
            f"{status_data['source_ip']} targeting {status_data['destination_ip']}"
        )
    else:
        message = f"Normal traffic classified successfully from {status_data['source_ip']}"

    item = {
        "time": status_data["timestamp"],
        "message": message,
        "level": threat_level if status_data["status"] == "ALERT" else "Info",
        "status": status_data["status"],
    }

    recent_alerts.appendleft(item)


def update_timeline(packet_count, threat_count):
    current_time = int(time.time())
    bucket_id = current_time // TIMELINE_BUCKET_SECONDS
    bucket_start = bucket_id * TIMELINE_BUCKET_SECONDS
    bucket_label = time.strftime("%H:%M", time.localtime(bucket_start))

    if timeline_bucket_ids and timeline_bucket_ids[-1] == bucket_id:
        timeline_volume[-1] += packet_count
        timeline_threats[-1] += threat_count
    else:
        timeline_bucket_ids.append(bucket_id)
        timeline_labels.append(bucket_label)
        timeline_volume.append(packet_count)
        timeline_threats.append(threat_count)


def make_safe_status(attack_type="No traffic", src_ip="-", dst_ip="-", protocol="-", features=None):
    if features is None:
        packet_count = 0
        total_bytes = 0
        packets_per_second = 0
    else:
        packet_count = int(features["packet_count"])
        total_bytes = int(features["total_bytes"])
        packets_per_second = round(features["packets_per_second"], 2)

    return {
        "status": "SAFE",
        "color": "green",
        "attack_type": attack_type,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "protocol": protocol,
        "packet_count": packet_count,
        "total_bytes": total_bytes,
        "packets_per_second": packets_per_second,
        "timestamp": time.strftime("%H:%M:%S"),
    }


def make_alert_status(attack_type, src_ip, dst_ip, protocol, features):
    return {
        "status": "ALERT",
        "color": "red",
        "attack_type": attack_type,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "protocol": protocol,
        "packet_count": int(features["packet_count"]),
        "total_bytes": int(features["total_bytes"]),
        "packets_per_second": round(features["packets_per_second"], 2),
        "timestamp": time.strftime("%H:%M:%S"),
    }


def update_global_status(new_status, prediction, features=None):
    global latest_status, last_attack_time, last_attack_status

    latest_status = new_status

    if features is not None:
        packet_count = int(features["packet_count"])
    else:
        packet_count = 0

    stats["total_packets"] += packet_count

    if prediction == 0:
        stats["normal_packets"] += packet_count
        class_counts["Normal"] += packet_count
        update_timeline(packet_count, 0)

    elif prediction is not None:
        stats["attack_packets"] += packet_count
        stats["detected_threats"] += 1

        attack_name = new_status["attack_type"]

        if attack_name in class_counts:
            class_counts[attack_name] += packet_count

        update_timeline(packet_count, packet_count)

    if packet_count > 0:
        write_csv_log(new_status, prediction)
        add_history_item(new_status)

        if new_status["status"] == "ALERT":
            add_alert_item(new_status)

def detector_loop():
    global latest_status, last_attack_time, last_attack_status, recent_attacks

    print("[INFO] Real time IDS started")
    print(f"[INFO] Interface: {INTERFACE}")
    print(f"[INFO] BPF Filter: {BPF_FILTER}")
    print(f"[INFO] Alert hold time: {ALERT_HOLD_TIME} seconds")
    print(f"[INFO] Timeline bucket: {TIMELINE_BUCKET_SECONDS} seconds")
    print(f"[INFO] CSV log path: {CSV_LOG_PATH}")

    while True:
        try:
            packets = sniff(
                iface=INTERFACE,
                filter=BPF_FILTER,
                timeout=WINDOW_SIZE,
                store=True
            )

            flows = group_packets_by_flow(packets)

            with lock:
                current_time = time.time()

                if not flows:
                    if last_attack_status is not None and current_time - last_attack_time < ALERT_HOLD_TIME:
                        latest_status = last_attack_status
                    else:
                        latest_status = make_safe_status("No traffic")
                    continue

                flow_results = []
                attack_map = {}

                recent_attacks = {
                    pair: info
                    for pair, info in recent_attacks.items()
                    if current_time - info["time"] < ALERT_HOLD_TIME
                }

                for flow_key, flow_packets in flows.items():
                    result = calculate_features(flow_packets)

                    if result is None:
                        continue

                    features, src_ip, dst_ip, protocol = result

                    row = pd.DataFrame([features])
                    row = row[feature_columns]

                    prediction = int(model.predict(row)[0])
                    attack_type = label_mapping.get(prediction, "Unknown")

                    AUTH_PORTS = {20, 21, 22, 23, 25, 110, 143, 3306, 3389, 5432}

                    targets_auth_service = (
                        features["tcp_count"] > 0
                        and features["top_dst_port"] in AUTH_PORTS
                    )

                    brute_force_signal = (
                        features["unique_src_ports"] > 20
                        or features["syn_count"] > 20
                        or features["rst_count"] > 5
                    )


                    if attack_type == "Nmap Scan" and features["packet_count"] < 5:
                        prediction = 0
                        attack_type = "Normal"

                    icmp_flood_signal = (
                        features["tcp_count"] == 0
                        and features["udp_count"] == 0
                        and features["icmp_count"] >= 15
                    )

                    if icmp_flood_signal:
                        prediction = 1
                        attack_type = "Ping DoS"

                    flow_results.append({
                        "features": features,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": protocol,
                        "prediction": prediction,
                        "attack_type": attack_type,
                    })

                    if prediction != 0:
                        attack_map[(src_ip, dst_ip)] = (prediction, attack_type)

                        recent_attacks[frozenset((src_ip, dst_ip))] = {
                            "time": current_time,
                            "prediction": prediction,
                            "attack_type": attack_type,
                            "attacker": src_ip,
                            "victim": dst_ip,
                        }

                window_attack_status = None
                window_normal_status = None

                for fr in flow_results:
                    features = fr["features"]
                    src_ip = fr["src_ip"]
                    dst_ip = fr["dst_ip"]
                    protocol = fr["protocol"]
                    prediction = fr["prediction"]
                    attack_type = fr["attack_type"]

                    if prediction == 0:
                        info = recent_attacks.get(frozenset((src_ip, dst_ip)))
                        if info is not None and current_time - info["time"] < ALERT_HOLD_TIME:
                            prediction = info["prediction"]
                            attack_type = info["attack_type"]
                            src_ip = info["attacker"]
                            dst_ip = info["victim"]

                    if prediction != 0:
                        status_data = make_alert_status(
                            attack_type,
                            src_ip,
                            dst_ip,
                            protocol,
                            features
                        )

                        last_attack_time = current_time
                        last_attack_status = status_data
                        window_attack_status = status_data
                    else:
                        status_data = make_safe_status(
                            "Normal",
                            src_ip,
                            dst_ip,
                            protocol,
                            features
                        )

                        window_normal_status = status_data

                    update_global_status(status_data, prediction, features)

                if window_attack_status is not None:
                    latest_status = window_attack_status
                elif last_attack_status is not None and current_time - last_attack_time < ALERT_HOLD_TIME:
                    latest_status = last_attack_status
                elif window_normal_status is not None:
                    latest_status = window_normal_status

        except Exception as e:
            print("[ERROR]", e)
            time.sleep(1)

HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IDS Dashboard | ML Based Cyber Attack Detection</title>
    <link rel="icon" type="image/png" href="/static/security.png">
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

        :root {
            --bg-main: #0b0e14;
            --bg-card: #151921;
            --border-color: #202632;
            --text-muted: #8b949e;
            --accent-blue: #0ea5e9;
            --accent-cyan: #06b6d4;
            --accent-green: #22c55e;
            --accent-red: #ef4444;
            --accent-orange: #f97316;
        }

        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-main);
            color: #e6edf3;
        }

        .font-mono {
            font-family: 'JetBrains Mono', monospace;
        }

        .glass-card {
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 0.75rem;
        }

        .stat-card {
            background: linear-gradient(135deg, #161b22 0%, #0d1117 100%);
            border: 1px solid var(--border-color);
        }

        .badge-pill {
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }

        .badge-online {
            background: rgba(34, 197, 94, 0.1);
            color: #22c55e;
            border: 1px solid rgba(34, 197, 94, 0.2);
        }

        .badge-alert {
            background: rgba(239, 68, 68, 0.12);
            color: #ef4444;
            border: 1px solid rgba(239, 68, 68, 0.25);
        }

        .badge-model {
            background: rgba(14, 165, 233, 0.1);
            color: #0ea5e9;
            border: 1px solid rgba(14, 165, 233, 0.2);
        }

        .badge-accuracy {
            background: rgba(30, 58, 138, 0.4);
            color: #60a5fa;
            border: 1px solid rgba(30, 58, 138, 0.5);
        }

        .threat-critical {
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .threat-high {
            background: rgba(249, 115, 22, 0.2);
            color: #f97316;
            border: 1px solid rgba(249, 115, 22, 0.3);
        }

        .threat-medium {
            background: rgba(234, 179, 8, 0.2);
            color: #eab308;
            border: 1px solid rgba(234, 179, 8, 0.3);
        }

        .threat-low {
            background: rgba(34, 197, 94, 0.2);
            color: #22c55e;
            border: 1px solid rgba(34, 197, 94, 0.3);
        }

        .threat-info {
            background: rgba(59, 130, 246, 0.2);
            color: #3b82f6;
            border: 1px solid rgba(59, 130, 246, 0.3);
        }

        .pulse {
            animation: pulse-dot 2s infinite;
        }

        @keyframes pulse-dot {
            0% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.5; transform: scale(1.2); }
            100% { opacity: 1; transform: scale(1); }
        }

        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: var(--bg-main); }
        ::-webkit-scrollbar-thumb { background: var(--border-color); border-radius: 3px; }

        #notification-container {
            position: fixed;
            top: 1.5rem;
            right: 1.5rem;
            z-index: 9999;
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
            pointer-events: none;
        }

        .toast {
            pointer-events: auto;
            width: 350px;
            background: #1c2128;
            border: 1px solid var(--border-color);
            border-left: 4px solid var(--accent-red);
            border-radius: 0.5rem;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.4);
            padding: 1rem;
            transform: translateX(120%);
            transition: transform 0.3s ease;
            display: flex;
            gap: 1rem;
        }

        .toast.show {
            transform: translateX(0);
        }

        .alert-glow {
            box-shadow: 0 0 30px rgba(239, 68, 68, 0.25);
            border-color: rgba(239, 68, 68, 0.55);
        }

        .safe-glow {
            box-shadow: 0 0 25px rgba(34, 197, 94, 0.10);
            border-color: rgba(34, 197, 94, 0.25);
        }
    </style>
</head>
<body class="p-4 md:p-6 overflow-x-hidden">
    <div id="notification-container"></div>

    <header class="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4 mb-8">
        <div class="flex items-center gap-4">
            <div class="w-10 h-10 bg-cyan-500/10 border border-cyan-500/30 rounded-lg flex items-center justify-center">
                <img src="{{ url_for('static',filename='security.png') }}" alt="Security Icon" class="w-7 h-7 object-contain">
            </div>
            <div>
                <h1 class="text-xl font-bold tracking-tight">ML Based Cyber Attack Detection System</h1>
                <p class="text-xs text-slate-500 uppercase tracking-widest font-medium">Live Network Traffic Monitoring Dashboard</p>
            </div>
        </div>

        <div class="flex flex-wrap items-center gap-3">
            <div class="text-slate-500 text-xs font-mono bg-slate-800/30 px-3 py-1.5 rounded-md border border-slate-800 flex items-center gap-2">
                <i class="far fa-clock"></i> <span id="clock">--:--:--</span>
            </div>
            <div class="text-slate-500 text-xs uppercase font-semibold bg-slate-800/30 px-3 py-1.5 rounded-md border border-slate-800">
                PROJECT: <span class="text-slate-300 ml-1">F25PROJECT08A18</span>
            </div>
            <div class="text-slate-500 text-xs uppercase font-semibold bg-slate-800/30 px-3 py-1.5 rounded-md border border-slate-800">
                STUDENT IDs: <span class="text-slate-300 ml-1">BC220420516 & BC220406417</span>
            </div>
            <div id="systemBadge" class="badge-pill badge-online">
                <span class="w-1.5 h-1.5 rounded-full bg-green-500 pulse"></span>
                System Online
            </div>
            <div class="badge-pill badge-model"><i class="fas fa-brain"></i> Random Forest Active</div>
            <div class="badge-pill badge-accuracy"><i class="fas fa-bullseye"></i> 99.74% Accuracy</div>
        </div>
    </header>

    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4 mb-8">
        <div class="stat-card p-4 rounded-xl relative overflow-hidden">
            <div class="absolute top-0 right-0 p-3 opacity-20"><i class="fas fa-wave-square text-cyan-400"></i></div>
            <p class="text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-2">Total Packets Analyzed</p>
            <h3 id="totalPackets" class="text-2xl font-bold mb-1">0</h3>
            <p class="text-[10px] text-slate-500">Live from monitor node</p>
            <div class="absolute bottom-0 left-0 h-1 bg-cyan-500/30 w-full"></div>
        </div>

        <div class="stat-card p-4 rounded-xl relative overflow-hidden">
            <div class="absolute top-0 right-0 p-3 opacity-20"><i class="fas fa-check-shield text-green-400"></i></div>
            <p class="text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-2">Normal Traffic</p>
            <h3 id="normalPackets" class="text-2xl font-bold mb-1 text-green-400">0</h3>
            <p id="normalPercent" class="text-[10px] text-slate-500">0% of total</p>
            <div class="absolute bottom-0 left-0 h-1 bg-green-500/30 w-full"></div>
        </div>

        <div class="stat-card p-4 rounded-xl relative overflow-hidden">
            <div class="absolute top-0 right-0 p-3 opacity-20"><i class="fas fa-virus text-red-400"></i></div>
            <p class="text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-2">Attack Traffic</p>
            <h3 id="attackPackets" class="text-2xl font-bold mb-1 text-red-400">0</h3>
            <p id="attackPercent" class="text-[10px] text-slate-500">0% of total</p>
            <div class="absolute bottom-0 left-0 h-1 bg-red-500/30 w-full"></div>
        </div>

        <div class="stat-card p-4 rounded-xl relative overflow-hidden border-orange-500/20">
            <div class="absolute top-0 right-0 p-3 opacity-20"><i class="fas fa-exclamation-triangle text-orange-400"></i></div>
            <p class="text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-2">Detected Threats</p>
            <h3 id="detectedThreats" class="text-2xl font-bold mb-1 text-orange-400">0</h3>
            <p class="text-[10px] text-slate-500">ML classified alerts</p>
            <div class="absolute bottom-0 left-0 h-1 bg-orange-500/30 w-full"></div>
        </div>

        <div class="stat-card p-4 rounded-xl relative overflow-hidden border-blue-500/20">
            <div class="absolute top-0 right-0 p-3 opacity-20"><i class="fas fa-microchip text-blue-400"></i></div>
            <p class="text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-2">Model Accuracy</p>
            <h3 class="text-2xl font-bold mb-1 text-blue-400">99.74%</h3>
            <p class="text-[10px] text-slate-500">Random Forest</p>
            <div class="absolute bottom-0 left-0 h-1 bg-blue-500/30 w-full"></div>
        </div>

        <div id="liveCard" class="stat-card p-4 rounded-xl relative overflow-hidden border-green-500/20">
            <div class="absolute top-0 right-0 p-3 opacity-20"><i class="fas fa-desktop text-green-400"></i></div>
            <p class="text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-2">Live Monitoring</p>
            <div class="flex items-center gap-2 mb-1">
                <h3 id="liveStatus" class="text-2xl font-bold text-green-400">Safe</h3>
                <span id="liveDot" class="w-2 h-2 rounded-full bg-green-500 pulse"></span>
            </div>
            <p id="liveSubtitle" class="text-[10px] text-slate-500">No active attack</p>
            <div class="absolute bottom-0 left-0 h-1 bg-green-500/30 w-full"></div>
        </div>
    </div>

    <div id="mainStatusCard" class="glass-card p-6 mb-8 safe-glow">
        <div class="flex flex-col lg:flex-row justify-between gap-4">
            <div>
                <p class="text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-2">Current IDS Decision</p>
                <h2 id="decisionStatus" class="text-4xl font-bold text-green-400">SAFE</h2>
                <p id="decisionType" class="text-xl mt-2 text-slate-300">No traffic</p>
            </div>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                    <p class="text-slate-500 text-xs uppercase font-bold">Source IP</p>
                    <p id="currentSource" class="font-mono text-slate-200 mt-1">-</p>
                </div>
                <div>
                    <p class="text-slate-500 text-xs uppercase font-bold">Destination IP</p>
                    <p id="currentDestination" class="font-mono text-slate-200 mt-1">-</p>
                </div>
                <div>
                    <p class="text-slate-500 text-xs uppercase font-bold">Protocol</p>
                    <p id="currentProtocol" class="font-mono text-slate-200 mt-1">-</p>
                </div>
                <div>
                    <p class="text-slate-500 text-xs uppercase font-bold">Packets Per Second</p>
                    <p id="currentPps" class="font-mono text-slate-200 mt-1">0</p>
                </div>
            </div>
        </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <div class="glass-card p-6">
            <div class="flex justify-between items-center mb-6">
                <div class="flex items-center gap-3">
                    <div class="w-8 h-8 bg-cyan-500/10 rounded flex items-center justify-center text-cyan-400">
                        <i class="fas fa-chart-bar text-sm"></i>
                    </div>
                    <div>
                        <h3 class="text-sm font-bold">Traffic Classification</h3>
                        <p class="text-[10px] text-slate-500">Live packet distribution by class</p>
                    </div>
                </div>
            </div>
            <div class="h-[250px]">
                <canvas id="classificationChart"></canvas>
            </div>
        </div>

        <div class="glass-card p-6">
            <div class="flex items-center gap-3 mb-6">
                <div class="w-8 h-8 bg-green-500/10 rounded flex items-center justify-center text-green-400">
                    <i class="fas fa-chart-line text-sm"></i>
                </div>
                <div>
                    <h3 class="text-sm font-bold">Traffic Timeline</h3>
                    <p class="text-[10px] text-slate-500">Packet volume and attack traffic over time</p>
                </div>
            </div>
            <div class="h-[250px]">
                <canvas id="timelineChart"></canvas>
            </div>
        </div>
    </div>

    <div class="glass-card mb-8 overflow-hidden">
        <div class="p-6 border-b border-slate-800 flex justify-between items-center">
            <div class="flex items-center gap-3">
                <div class="w-8 h-8 bg-red-500/10 rounded flex items-center justify-center text-red-400">
                    <i class="fas fa-broadcast-tower text-sm"></i>
                </div>
                <div>
                    <h3 class="text-sm font-bold">Live Detection Panel <span class="w-1.5 h-1.5 rounded-full bg-red-500 inline-block ml-2 pulse"></span></h3>
                    <p class="text-[10px] text-slate-500">Latest ML classification results</p>
                </div>
            </div>
            <div class="text-[10px] text-slate-500 uppercase font-bold tracking-widest">
                <i class="fas fa-sort-amount-down mr-1"></i> Last 10 detections
            </div>
        </div>

        <div class="overflow-x-auto">
            <table class="w-full text-left text-xs font-medium">
                <thead class="bg-slate-900/50 text-slate-500 uppercase tracking-wider border-b border-slate-800">
                    <tr>
                        <th class="py-3 px-6">Time</th>
                        <th class="py-3 px-6">Source IP</th>
                        <th class="py-3 px-6">Dest IP</th>
                        <th class="py-3 px-6">Protocol</th>
                        <th class="py-3 px-6 text-right">Packets</th>
                        <th class="py-3 px-6">Prediction</th>
                        <th class="py-3 px-6">Threat</th>
                    </tr>
                </thead>
                <tbody id="liveTableBody" class="divide-y divide-slate-800">
                    <tr>
                        <td colspan="7" class="py-6 px-6 text-center text-slate-500">Waiting for live traffic...</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <div class="glass-card p-6 flex flex-col h-full min-h-[480px]">
            <div class="flex items-center gap-4 mb-10">
                <div class="w-10 h-10 bg-purple-500/10 rounded-lg flex items-center justify-center text-purple-400 border border-purple-500/20">
                    <i class="fas fa-brain text-lg"></i>
                </div>
                <div>
                    <h3 class="text-base font-bold text-white tracking-tight">Model Performance</h3>
                    <p class="text-xs text-slate-500 font-medium">ML classifier comparison results</p>
                </div>
            </div>

            <div class="space-y-10 flex-grow flex flex-col justify-center px-2">
                <div>
                    <div class="flex justify-between items-center mb-3">
                        <div class="flex items-center gap-3">
                            <span class="text-sm font-bold text-green-400">Random Forest</span>
                            <span class="text-[10px] bg-green-500/10 text-green-400 px-2 py-0.5 rounded border border-green-500/20 font-bold uppercase"><i class="fas fa-crown text-[8px] mr-1"></i> Best</span>
                        </div>
                        <span class="text-sm font-bold text-green-400 font-mono">99.74%</span>
                    </div>
                    <div class="h-2.5 w-full bg-slate-800 rounded-full overflow-hidden border border-slate-700/50">
                        <div class="h-full bg-green-500" style="width: 99.74%"></div>
                    </div>
                </div>

                <div>
                    <div class="flex justify-between items-center mb-3">
                        <span class="text-sm font-bold text-blue-400">Decision Tree</span>
                        <span class="text-sm font-bold text-blue-400 font-mono">98.95%</span>
                    </div>
                    <div class="h-2.5 w-full bg-slate-800 rounded-full overflow-hidden border border-slate-700/50">
                        <div class="h-full bg-blue-500" style="width: 98.95%"></div>
                    </div>
                </div>

                <div>
                    <div class="flex justify-between items-center mb-3">
                        <span class="text-sm font-bold text-purple-400">KNN</span>
                        <span class="text-sm font-bold text-purple-400 font-mono">97.64%</span>
                    </div>
                    <div class="h-2.5 w-full bg-slate-800 rounded-full overflow-hidden border border-slate-700/50">
                        <div class="h-full bg-purple-500" style="width: 97.64%"></div>
                    </div>
                </div>

                <div>
                    <div class="flex justify-between items-center mb-3">
                        <span class="text-sm font-bold text-orange-400">Logistic Regression</span>
                        <span class="text-sm font-bold text-orange-400 font-mono">96.85%</span>
                    </div>
                    <div class="h-2.5 w-full bg-slate-800 rounded-full overflow-hidden border border-slate-700/50">
                        <div class="h-full bg-orange-500" style="width: 96.85%"></div>
                    </div>
                </div>

                <div>
                    <div class="flex justify-between items-center mb-3">
                        <span class="text-sm font-bold text-red-400">SVM</span>
                        <span class="text-sm font-bold text-red-400 font-mono">93.70%</span>
                    </div>
                    <div class="h-2.5 w-full bg-slate-800 rounded-full overflow-hidden border border-slate-700/50">
                        <div class="h-full bg-red-500" style="width: 93.70%"></div>
                    </div>
                </div>
            </div>
        </div>

        <div class="glass-card p-6 flex flex-col h-full min-h-[480px]">
            <div class="flex items-center gap-3 mb-6">
                <div class="w-8 h-8 bg-blue-500/10 rounded flex items-center justify-center text-blue-400">
                    <i class="fas fa-network-wired text-sm"></i>
                </div>
                <div>
                    <h3 class="text-sm font-bold text-white">GNS3-Based IDS Lab Topology</h3>
                    <p class="text-[10px] text-slate-500 font-medium">ML-Based Cyber Attack Detection in Simulated Networks</p>
                </div>
            </div>

            <div class="relative flex-grow flex items-center justify-center bg-slate-900/20 rounded-xl border border-slate-800/50 overflow-hidden">
                <svg class="absolute inset-0 w-full h-full pointer-events-none" preserveAspectRatio="none">
                    <line x1="50%" y1="10%" x2="50%" y2="50%" stroke="#475569" stroke-width="1.5" />
                    <line x1="20%" y1="47%" x2="50%" y2="47%" stroke="#475569" stroke-width="1.5" />
                    <line x1="80%" y1="47%" x2="50%" y2="47%" stroke="#475569" stroke-width="1.5" />
                    <line x1="50%" y1="75%" x2="50%" y2="50%" stroke="#475569" stroke-width="1.5" />
                    <line x1="50%" y1="78%" x2="65%" y2="78%" stroke="#475569" stroke-width="1.5" />
                </svg>

                <div class="relative w-full h-full">
                    <div class="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 flex flex-col items-center">
                        <div class="w-14 h-14 bg-slate-800 border border-slate-600 rounded-xl flex items-center justify-center text-slate-200">
                            <i class="fas fa-network-wired text-xl"></i>
                        </div>
                        <span class="text-[8px] font-bold text-slate-300 uppercase mt-2 text-center leading-none">Ethernet<br>Hub</span>
                    </div>

                    <div class="absolute top-1/2 left-[15%] -translate-y-1/2 flex flex-col items-center">
                        <div class="w-12 h-12 bg-slate-800 border border-red-500/40 rounded-xl flex items-center justify-center text-red-500">
                            <i class="fas fa-skull"></i>
                        </div>
                        <span class="text-[8px] font-bold text-slate-400 uppercase mt-2 text-center leading-none">Kali Attacker<br>192.168.188.131</span>
                    </div>

                    <div class="absolute top-1/2 right-[15%] -translate-y-1/2 flex flex-col items-center">
                        <div class="w-12 h-12 bg-slate-800 border border-orange-500/40 rounded-xl flex items-center justify-center text-orange-500">
                            <i class="fas fa-server"></i>
                        </div>
                        <span class="text-[8px] font-bold text-slate-400 uppercase mt-2 text-center leading-none">Lubuntu Victim<br>192.168.188.130</span>
                    </div>

                    <div class="absolute bottom-[10%] left-1/2 -translate-x-1/2 flex flex-col items-center">
                        <div class="w-12 h-12 bg-slate-800 border border-blue-500/40 rounded-xl flex items-center justify-center text-blue-400">
                            <i class="fas fa-eye"></i>
                        </div>
                        <span class="text-[8px] font-bold text-slate-400 uppercase mt-2 text-center leading-none">IDS Monitor<br>192.168.188.132</span>
                    </div>

                    <div class="absolute top-[10%] left-1/2 -translate-x-1/2 flex flex-col items-center">
                        <div class="w-12 h-12 bg-slate-800 border border-purple-500/40 rounded-xl flex items-center justify-center text-blue-400">
                            <i class="fas fa-desktop "></i> 
                        </div>
                        <span class="text-[8px] font-bold text-slate-400 uppercase mt-2 text-center leading-none">Legitimate Client<br>192.168.188.133</span>
                    </div>

                    <div class="absolute bottom-[10%] left-[65%] flex flex-col items-center">
                        <div class="w-12 h-12 bg-slate-800 border-2 border-green-500 rounded-xl flex items-center justify-center text-green-500 animate-pulse">
                            <i class="fas fa-window-maximize"></i>
                        </div>
                        <span class="text-[8px] font-bold text-green-400 uppercase mt-2 text-center leading-none">Dashboard<br>Browser</span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="glass-card p-6 mb-8">
        <div class="flex items-center gap-3 mb-6">
            <div class="w-8 h-8 bg-orange-500/10 rounded flex items-center justify-center text-orange-400">
                <i class="fas fa-bell text-sm"></i>
            </div>
            <div>
                <h3 class="text-sm font-bold">Recent Alerts</h3>
                <p class="text-[10px] text-slate-500">System notifications and threat alerts</p>
            </div>
        </div>

        <div id="alertsList" class="space-y-4">
            <div class="text-center text-slate-500 text-xs py-4">Waiting for alerts...</div>
        </div>
    </div>

    <footer class="flex flex-col md:flex-row justify-between items-center gap-4 pt-4 border-t border-slate-800 text-slate-600 text-[10px] font-bold uppercase tracking-wider">
        <div class="flex items-center gap-2">
            <img src="/static/security.png" alt="Security Icon" class="w-5 h-5 object-contain opacity-50">
            ML Based Cyber Attack Detection in Simulated Networks
        </div>
        <div class="flex items-center gap-2">
            DEVELOPED BY STUDENTS AT VU, DEPT OF SOFTWARE ENGINEERING: ABDULLAH ZUBAIR & AREEBA SHAFAT
        </div>
        <div class="flex items-center gap-4">
            <span>Built with Python <span class="mx-1 opacity-30">|</span> Scapy <span class="mx-1 opacity-30">|</span> Scikit-learn <span class="mx-1 opacity-30">|</span> Machine Learning <span class="mx-1 opacity-30">|</span> GNS3</span>
        </div>
    </footer>

    <script>
        let lastAlertKey = "";

        function formatNumber(num) {
            return Number(num || 0).toLocaleString();
        }

        function percent(part, total) {
            if (!total || total === 0) return "0% of total";
            return ((part / total) * 100).toFixed(1) + "% of total";
        }

        function badgeClass(level) {
            if (level === "Critical") return "threat-critical";
            if (level === "High") return "threat-high";
            if (level === "Medium") return "threat-medium";
            if (level === "Low") return "threat-low";
            return "threat-info";
        }

        function showNotification(data) {
            const key = data.timestamp + data.attack_type + data.source_ip + data.destination_ip;
            if (key === lastAlertKey) return;
            lastAlertKey = key;

            const container = document.getElementById("notification-container");
            const toast = document.createElement("div");
            toast.className = "toast";

            toast.innerHTML = `
                <div class="text-red-500 mt-1"><i class="fas fa-shield-virus"></i></div>
                <div>
                    <h4 class="text-xs font-bold text-white uppercase mb-1">Intrusion Detected</h4>
                    <p class="text-[11px] text-slate-400">${data.attack_type} detected against ${data.destination_ip}</p>
                    <p class="text-[10px] text-red-400 font-mono mt-1">Source IP: ${data.source_ip}</p>
                </div>
            `;

            container.appendChild(toast);

            setTimeout(() => toast.classList.add("show"), 100);

            setTimeout(() => {
                toast.classList.remove("show");
                setTimeout(() => toast.remove(), 300);
            }, 5000);
        }

        const classCtx = document.getElementById("classificationChart").getContext("2d");
        const classificationChart = new Chart(classCtx, {
            type: "bar",
            data: {
                labels: ["Normal", "Ping DoS", "SYN Flood", "Nmap Scan", "Brute Force"],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: ["#06b6d4", "#ef4444", "#ef4444", "#f97316", "#eab308"],
                    borderRadius: 4,
                    barThickness: 35
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { color: "#475569", font: { size: 10, family: "JetBrains Mono" } },
                        grid: { color: "rgba(71, 85, 105, 0.1)" }
                    },
                    x: {
                        ticks: { color: "#94a3b8", font: { size: 9, weight: "600" } },
                        grid: { display: false }
                    }
                }
            }
        });

        const timeCtx = document.getElementById("timelineChart").getContext("2d");
        const timelineChart = new Chart(timeCtx, {
            type: "line",
            data: {
                labels: [],
                datasets: [
                    {
                        label: "Volume",
                        data: [],
                        borderColor: "#06b6d4",
                        backgroundColor: "rgba(6, 182, 212, 0.1)",
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2,
                        pointRadius: 0
                    },
                    {
                        label: "Attack Traffic",
                        data: [],
                        borderColor: "#ef4444",
                        backgroundColor: "rgba(239, 68, 68, 0.1)",
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2,
                        pointRadius: 0
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { labels: { color: "#94a3b8" } } },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { color: "#475569", font: { size: 10, family: "JetBrains Mono" } },
                        grid: { color: "rgba(71, 85, 105, 0.1)" }
                    },
                    x: {
                        ticks: { color: "#94a3b8", font: { size: 9, weight: "600" } },
                        grid: { display: false }
                    }
                }
            }
        });

        function updateHistory(history) {
            const body = document.getElementById("liveTableBody");
            body.innerHTML = "";

            if (!history || history.length === 0) {
                body.innerHTML = `<tr><td colspan="7" class="py-6 px-6 text-center text-slate-500">Waiting for live traffic...</td></tr>`;
                return;
            }

            history.forEach(item => {
                const isAlert = item.status === "ALERT";
                const row = document.createElement("tr");
                row.className = "hover:bg-slate-800/30";

                const predColor = isAlert ? "text-red-400" : "text-green-400";
                const icon = isAlert ? "▲" : "✓";

                row.innerHTML = `
                    <td class="py-4 px-6 text-slate-400 font-mono">${item.time}</td>
                    <td class="py-4 px-6 font-mono text-slate-200">${item.source_ip}</td>
                    <td class="py-4 px-6 font-mono text-slate-200">${item.destination_ip}</td>
                    <td class="py-4 px-6 uppercase text-slate-400">${item.protocol}</td>
                    <td class="py-4 px-6 text-right font-mono text-slate-400">${formatNumber(item.packet_count)}</td>
                    <td class="py-4 px-6 ${predColor} font-bold italic"><span class="mr-1">${icon}</span> ${item.prediction}</td>
                    <td class="py-4 px-6"><span class="badge-pill ${badgeClass(item.level)}">${item.level}</span></td>
                `;

                body.appendChild(row);
            });
        }

        function updateAlerts(alerts) {
            const list = document.getElementById("alertsList");
            list.innerHTML = "";

            if (!alerts || alerts.length === 0) {
                list.innerHTML = `<div class="text-center text-slate-500 text-xs py-4">Waiting for alerts...</div>`;
                return;
            }

            alerts.forEach(item => {
                const isAlert = item.status === "ALERT";
                const div = document.createElement("div");
                div.className = "flex items-center justify-between py-2 border-b border-slate-800/50";

                const iconColor = isAlert ? "text-red-500" : "text-green-500";
                const icon = isAlert ? "fa-shield-virus" : "fa-circle-check";

                div.innerHTML = `
                    <div class="flex items-center gap-4">
                        <div class="${iconColor} opacity-80"><i class="fas ${icon}"></i></div>
                        <div>
                            <p class="text-xs font-semibold text-slate-300">${item.message}</p>
                            <div class="flex items-center gap-3 mt-1">
                                <span class="text-[9px] text-slate-500 font-mono">${item.time}</span>
                                <span class="badge-pill ${badgeClass(item.level)} !px-2 !py-0 !text-[8px]">${item.level}</span>
                            </div>
                        </div>
                    </div>
                `;

                list.appendChild(div);
            });
        }

        async function updateDashboard() {
            try {
                const response = await fetch("/status");
                const data = await response.json();

                document.getElementById("clock").innerText = data.current_time;

                const status = data.latest_status;
                const stats = data.stats;

                document.getElementById("totalPackets").innerText = formatNumber(stats.total_packets);
                document.getElementById("normalPackets").innerText = formatNumber(stats.normal_packets);
                document.getElementById("attackPackets").innerText = formatNumber(stats.attack_packets);
                document.getElementById("detectedThreats").innerText = formatNumber(stats.detected_threats);

                document.getElementById("normalPercent").innerText = percent(stats.normal_packets, stats.total_packets);
                document.getElementById("attackPercent").innerText = percent(stats.attack_packets, stats.total_packets);

                document.getElementById("decisionStatus").innerText = status.status;
                document.getElementById("decisionType").innerText = status.attack_type;
                document.getElementById("currentSource").innerText = status.source_ip;
                document.getElementById("currentDestination").innerText = status.destination_ip;
                document.getElementById("currentProtocol").innerText = status.protocol;
                document.getElementById("currentPps").innerText = status.packets_per_second;

                const statusCard = document.getElementById("mainStatusCard");
                const liveStatus = document.getElementById("liveStatus");
                const liveSubtitle = document.getElementById("liveSubtitle");
                const liveDot = document.getElementById("liveDot");
                const systemBadge = document.getElementById("systemBadge");

                if (status.status === "ALERT") {
                    document.getElementById("decisionStatus").className = "text-4xl font-bold text-red-400";
                    statusCard.className = "glass-card p-6 mb-8 alert-glow";
                    liveStatus.innerText = "Alert";
                    liveStatus.className = "text-2xl font-bold text-red-400";
                    liveSubtitle.innerText = status.attack_type + " detected";
                    liveDot.className = "w-2 h-2 rounded-full bg-red-500 pulse";
                    systemBadge.className = "badge-pill badge-alert";
                    systemBadge.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-red-500 pulse"></span> Attack Detected`;
                    showNotification(status);
                } else {
                    document.getElementById("decisionStatus").className = "text-4xl font-bold text-green-400";
                    statusCard.className = "glass-card p-6 mb-8 safe-glow";
                    liveStatus.innerText = "Safe";
                    liveStatus.className = "text-2xl font-bold text-green-400";
                    liveSubtitle.innerText = "No active attack";
                    liveDot.className = "w-2 h-2 rounded-full bg-green-500 pulse";
                    systemBadge.className = "badge-pill badge-online";
                    systemBadge.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-green-500 pulse"></span> System Online`;
                }

                classificationChart.data.datasets[0].data = [
                    data.class_counts.Normal || 0,
                    data.class_counts["Ping DoS"] || 0,
                    data.class_counts["SYN Flood"] || 0,
                    data.class_counts["Nmap Scan"] || 0,
                    data.class_counts["Brute Force"] || 0
                ];
                classificationChart.update();

                timelineChart.data.labels = data.timeline.labels;
                timelineChart.data.datasets[0].data = data.timeline.volume;
                timelineChart.data.datasets[1].data = data.timeline.threats;
                timelineChart.update();

                updateHistory(data.history);
                updateAlerts(data.alerts);

            } catch (error) {
                console.log(error);
            }
        }

        setInterval(updateDashboard, 500);
        updateDashboard();
    </script>
</body>
</html>
"""
@app.route("/")
def index():
    return render_template_string(HTML_PAGE)


@app.route("/status")
def status():
    with lock:
        return jsonify({
            "current_time": time.strftime("%H:%M:%S"),
            "latest_status": latest_status,
            "stats": stats,
            "class_counts": class_counts,
            "timeline": {
                "labels": list(timeline_labels),
                "volume": list(timeline_volume),
                "threats": list(timeline_threats),
            },
            "history": list(detection_history),
            "alerts": list(recent_alerts),
        })

if __name__ == "__main__":
    init_csv_log()

    detector_thread = threading.Thread(target=detector_loop, daemon=True)
    detector_thread.start()

    app.run(host="0.0.0.0", port=5000, debug=False)
