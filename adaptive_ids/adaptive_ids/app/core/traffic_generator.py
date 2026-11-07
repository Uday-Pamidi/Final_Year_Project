import random
import uuid
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Dict, Any, List

from app.config import (
    FLOW_FEATURES,
    ATTACK_CLASSES,
    ATTACK_CLASS_TO_ID,
    DATA_DIR
)

# Known IP pools for realistic telemetry
BENIGN_IPS = [f"192.168.1.{i}" for i in range(10, 45)]
SERVER_IPS = ["10.0.0.1", "10.0.0.2", "10.0.0.5", "10.0.0.8"]
SUSPICIOUS_IPS = [
    "198.51.100.42", "203.0.113.195", "192.0.2.77",
    "198.51.100.89", "203.0.113.88", "198.51.100.120"
]
DRIFTING_ZERO_DAY_IPS = [
    "198.51.100.201", "198.51.100.202", "203.0.113.240"
]

def generate_flow_sample(traffic_type: str = "benign", is_drifting: bool = False) -> Dict[str, Any]:
    """
    Generates a single realistic network flow dictionary matching CIC-IDS2017 feature schemas.
    """
    traffic_type = traffic_type.lower()
    flow_id = f"FL-{uuid.uuid4().hex[:10].upper()}"
    timestamp = datetime.utcnow().isoformat()

    # Default Benign Profile
    src_ip = random.choice(BENIGN_IPS)
    dst_ip = random.choice(SERVER_IPS)
    src_port = random.randint(32768, 61000)
    dst_port = random.choice([80, 443, 53, 22, 8080])
    protocol = "TCP" if dst_port != 53 else "UDP"
    ground_truth = "Benign"
    label_id = 0

    duration = round(random.uniform(0.1, 15.0), 4)
    fwd_pkts = random.randint(3, 40)
    bwd_pkts = random.randint(3, 45)
    fwd_bytes = fwd_pkts * random.randint(40, 500)
    bwd_bytes = bwd_pkts * random.randint(40, 1200)
    pkt_len_mean = round(float((fwd_bytes + bwd_bytes) / max(1, fwd_pkts + bwd_pkts)), 2)
    pkt_len_std = round(random.uniform(15.0, 120.0), 2)
    flow_bytes_s = round(float((fwd_bytes + bwd_bytes) / max(0.01, duration)), 2)
    flow_pkts_s = round(float((fwd_pkts + bwd_pkts) / max(0.01, duration)), 2)

    syn_cnt = random.randint(1, 3) if protocol == "TCP" else 0
    fin_cnt = random.randint(1, 2) if protocol == "TCP" else 0
    rst_cnt = 0 if random.random() > 0.05 else 1
    psh_cnt = random.randint(1, 6)
    ack_cnt = random.randint(3, 40)
    down_up_ratio = round(float(bwd_bytes / max(1, fwd_bytes)), 2)
    payload_entropy = round(random.uniform(2.8, 4.8), 2)

    # Attack Profiles
    if traffic_type in ["dos", "dos_ddos"]:
        ground_truth = "DoS_DDoS"
        label_id = 1
        src_ip = random.choice(SUSPICIOUS_IPS[:2])
        dst_port = random.choice([80, 443])
        duration = round(random.uniform(0.005, 0.25), 4)
        fwd_pkts = random.randint(40, 300)
        bwd_pkts = random.randint(0, 5)
        fwd_bytes = fwd_pkts * random.randint(30, 80)
        bwd_bytes = bwd_pkts * random.randint(20, 60)
        pkt_len_mean = round(random.uniform(40.0, 75.0), 2)
        pkt_len_std = round(random.uniform(2.0, 15.0), 2)
        flow_bytes_s = round(float((fwd_bytes + bwd_bytes) / max(0.005, duration)), 2)
        flow_pkts_s = round(float((fwd_pkts + bwd_pkts) / max(0.005, duration)), 2)
        syn_cnt = random.randint(35, 280)
        fin_cnt = 0
        rst_cnt = random.randint(5, 40)
        psh_cnt = 0
        ack_cnt = random.randint(0, 5)
        down_up_ratio = 0.05
        payload_entropy = round(random.uniform(1.2, 3.2), 2)

    elif traffic_type == "portscan":
        ground_truth = "PortScan"
        label_id = 2
        src_ip = SUSPICIOUS_IPS[2]
        dst_port = random.choice([21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5900, 8080])
        duration = round(random.uniform(0.001, 0.08), 4)
        fwd_pkts = random.randint(1, 3)
        bwd_pkts = random.randint(0, 1)
        fwd_bytes = fwd_pkts * 44
        bwd_bytes = bwd_pkts * 40
        pkt_len_mean = 44.0
        pkt_len_std = 0.0
        flow_bytes_s = round(float((fwd_bytes + bwd_bytes) / max(0.001, duration)), 2)
        flow_pkts_s = round(float((fwd_pkts + bwd_pkts) / max(0.001, duration)), 2)
        syn_cnt = random.randint(1, 3)
        fin_cnt = 0
        rst_cnt = 1 if bwd_pkts == 0 else 0
        psh_cnt = 0
        ack_cnt = 0
        down_up_ratio = 0.0
        payload_entropy = round(random.uniform(0.5, 1.8), 2)

    elif traffic_type == "bruteforce":
        ground_truth = "BruteForce"
        label_id = 3
        src_ip = SUSPICIOUS_IPS[3]
        dst_port = random.choice([22, 3389, 21])
        duration = round(random.uniform(0.8, 3.5), 4)
        fwd_pkts = random.randint(12, 35)
        bwd_pkts = random.randint(10, 30)
        fwd_bytes = fwd_pkts * random.randint(60, 95)
        bwd_bytes = bwd_pkts * random.randint(80, 120)
        pkt_len_mean = round(float((fwd_bytes + bwd_bytes) / max(1, fwd_pkts + bwd_pkts)), 2)
        pkt_len_std = round(random.uniform(10.0, 30.0), 2)
        flow_bytes_s = round(float((fwd_bytes + bwd_bytes) / max(0.1, duration)), 2)
        flow_pkts_s = round(float((fwd_pkts + bwd_pkts) / max(0.1, duration)), 2)
        syn_cnt = 1
        fin_cnt = 1
        rst_cnt = random.randint(1, 4)
        psh_cnt = random.randint(6, 18)
        ack_cnt = random.randint(15, 45)
        down_up_ratio = round(float(bwd_bytes / max(1, fwd_bytes)), 2)
        payload_entropy = round(random.uniform(3.5, 5.2), 2)

    elif traffic_type in ["botnet", "botnet_c2"]:
        ground_truth = "Botnet_C2"
        label_id = 4
        src_ip = SUSPICIOUS_IPS[0]
        dst_port = random.choice([4444, 8443, 9001, 8080])
        duration = round(random.uniform(3.0, 25.0), 4)
        fwd_pkts = random.randint(6, 25)
        bwd_pkts = random.randint(8, 35)
        fwd_bytes = fwd_pkts * random.randint(80, 250)
        bwd_bytes = bwd_pkts * random.randint(200, 800)
        pkt_len_mean = round(float((fwd_bytes + bwd_bytes) / max(1, fwd_pkts + bwd_pkts)), 2)
        pkt_len_std = round(random.uniform(30.0, 95.0), 2)
        flow_bytes_s = round(float((fwd_bytes + bwd_bytes) / max(0.1, duration)), 2)
        flow_pkts_s = round(float((fwd_pkts + bwd_pkts) / max(0.1, duration)), 2)
        syn_cnt = 1
        fin_cnt = 1
        rst_cnt = 0
        psh_cnt = random.randint(4, 15)
        ack_cnt = random.randint(10, 40)
        down_up_ratio = round(float(bwd_bytes / max(1, fwd_bytes)), 2)
        payload_entropy = round(random.uniform(6.9, 7.85), 2)  # High entropy encrypted payload

    elif traffic_type in ["web", "infiltration_web"]:
        ground_truth = "Infiltration_Web"
        label_id = 5
        src_ip = SUSPICIOUS_IPS[4]
        dst_port = random.choice([80, 8080, 443])
        duration = round(random.uniform(0.5, 4.0), 4)
        fwd_pkts = random.randint(8, 28)
        bwd_pkts = random.randint(5, 22)
        fwd_bytes = fwd_pkts * random.randint(300, 950)  # Heavy exploit payload
        bwd_bytes = bwd_pkts * random.randint(150, 600)
        pkt_len_mean = round(float((fwd_bytes + bwd_bytes) / max(1, fwd_pkts + bwd_pkts)), 2)
        pkt_len_std = round(random.uniform(40.0, 140.0), 2)
        flow_bytes_s = round(float((fwd_bytes + bwd_bytes) / max(0.1, duration)), 2)
        flow_pkts_s = round(float((fwd_pkts + bwd_pkts) / max(0.1, duration)), 2)
        syn_cnt = 1
        fin_cnt = 1
        rst_cnt = 0
        psh_cnt = random.randint(5, 16)
        ack_cnt = random.randint(10, 35)
        down_up_ratio = round(float(bwd_bytes / max(1, fwd_bytes)), 2)
        payload_entropy = round(random.uniform(5.4, 6.7), 2)

    elif traffic_type in ["zero_day", "drifting"]:
        # Novel / Concept Drift Threat: Port hopping + polymorphic encrypted beacon
        # This will trigger Isolation Forest anomaly and Concept Drift!
        ground_truth = "Botnet_C2"
        label_id = 4
        src_ip = random.choice(DRIFTING_ZERO_DAY_IPS)
        dst_port = random.randint(10000, 30000)  # Unusual port
        duration = round(random.uniform(0.01, 0.15), 4)
        fwd_pkts = random.randint(15, 60)
        bwd_pkts = random.randint(2, 10)
        fwd_bytes = fwd_pkts * random.randint(150, 400)
        bwd_bytes = bwd_pkts * random.randint(80, 200)
        pkt_len_mean = round(float((fwd_bytes + bwd_bytes) / max(1, fwd_pkts + bwd_pkts)), 2)
        pkt_len_std = round(random.uniform(45.0, 110.0), 2)
        flow_bytes_s = round(float((fwd_bytes + bwd_bytes) / max(0.01, duration)), 2)
        flow_pkts_s = round(float((fwd_pkts + bwd_pkts) / max(0.01, duration)), 2)
        syn_cnt = random.randint(10, 35)
        fin_cnt = 0
        rst_cnt = random.randint(2, 8)
        psh_cnt = random.randint(8, 25)
        ack_cnt = random.randint(4, 15)
        down_up_ratio = 0.35
        payload_entropy = round(random.uniform(7.5, 7.98), 2)  # Extreme entropy

    features = {
        "flow_duration": duration,
        "total_fwd_packets": float(fwd_pkts),
        "total_bwd_packets": float(bwd_pkts),
        "total_fwd_bytes": float(fwd_bytes),
        "total_bwd_bytes": float(bwd_bytes),
        "packet_length_mean": pkt_len_mean,
        "packet_length_std": pkt_len_std,
        "flow_bytes_s": flow_bytes_s,
        "flow_packets_s": flow_pkts_s,
        "syn_flag_count": float(syn_cnt),
        "fin_flag_count": float(fin_cnt),
        "rst_flag_count": float(rst_cnt),
        "psh_flag_count": float(psh_cnt),
        "ack_flag_count": float(ack_cnt),
        "down_up_ratio": down_up_ratio,
        "payload_entropy": payload_entropy
    }

    return {
        "id": flow_id,
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "ground_truth": ground_truth,
        "label_id": label_id,
        "features": features
    }

def generate_base_dataset(n_samples: int = 600) -> pd.DataFrame:
    """
    Generates balanced base dataset representing initial network deployment.
    """
    records = []
    # 60% Benign, 40% known attacks (DoS, PortScan, BruteForce, Botnet, Web)
    distribution = [
        ("benign", int(n_samples * 0.55)),
        ("dos", int(n_samples * 0.12)),
        ("portscan", int(n_samples * 0.10)),
        ("bruteforce", int(n_samples * 0.08)),
        ("botnet", int(n_samples * 0.08)),
        ("web", int(n_samples * 0.07))
    ]

    for attack_type, count in distribution:
        for _ in range(count):
            flow = generate_flow_sample(attack_type)
            row = dict(flow["features"])
            row["flow_id"] = flow["id"]
            row["src_ip"] = flow["src_ip"]
            row["dst_ip"] = flow["dst_ip"]
            row["dst_port"] = flow["dst_port"]
            row["protocol"] = flow["protocol"]
            row["ground_truth"] = flow["ground_truth"]
            row["label_id"] = flow["label_id"]
            records.append(row)

    df = pd.DataFrame(records).sample(frac=1.0, random_state=42).reset_index(drop=True)
    csv_path = DATA_DIR / "base_traffic_sample.csv"
    df.to_csv(csv_path, index=False)
    return df
