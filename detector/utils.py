import os
import time
import joblib
import pandas as pd
import json
import logging
from datetime import datetime

# ==========================================
# WAZUH SIEM LOGGING CONFIGURATION
# ==========================================
siem_logger = logging.getLogger('Wazuh_Integration')
siem_logger.setLevel(logging.WARNING)
file_handler = logging.FileHandler('artis_alerts.json')
siem_logger.addHandler(file_handler)

def trigger_siem_alert(packet_data):
    """Writes a JSON alert to a local file for the Wazuh Agent to ingest."""
    alert_payload = {
        "timestamp": datetime.now().isoformat(),
        "app_name": "ARTIS_Threat_Engine",
        "event_type": "Network_Anomaly",
        "src_ip": packet_data.get('Src_IP', 'Unknown'),
        "dst_ip": packet_data.get('Dst_IP', 'Unknown'),
        "threat_score": packet_data.get('Threat_Score', 0.0),
        "action": "Flagged_Malicious"
    }
    siem_logger.warning(json.dumps(alert_payload))
# ==========================================

try:
    from scapy.all import PcapReader, IP, TCP, UDP, ICMP, DNS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

def extract_features_from_uploaded_file(file_path, filename, max_packets=5000):
    """
    Parses an uploaded PCAP or CSV file from the physical disk path.
    """
    records = []
    file_ext = os.path.splitext(filename)[1].lower()

    if file_ext in ['.pcap', '.pcapng']:
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required to inspect PCAP files.")
        
        # Stream packets using PcapReader to avoid RAM crashes
        with PcapReader(file_path) as reader:
            for idx, pkt in enumerate(reader):
                if idx >= max_packets:
                    break
                if IP in pkt:
                    proto = "OTHER"
                    sport, dport = 0, 0
                    
                    if pkt.haslayer(DNS):
                        proto = "DNS"
                        sport = pkt[UDP].sport if UDP in pkt else 0
                        dport = pkt[UDP].dport if UDP in pkt else 0
                    elif pkt.haslayer(TCP):
                        proto = "TCP"
                        sport = pkt[TCP].sport
                        dport = pkt[TCP].dport
                    elif pkt.haslayer(UDP):
                        proto = "UDP"
                        sport = pkt[UDP].sport
                        dport = pkt[UDP].dport
                    elif pkt.haslayer(ICMP):
                        proto = "ICMP"

                    records.append({
                        'Packet_ID': idx + 1,
                        'Src_IP': pkt[IP].src,
                        'Dst_IP': pkt[IP].dst,
                        'Length': len(pkt),
                        'Protocol': proto,
                        'Src_Port': sport,
                        'Dst_Port': dport,
                    })
        df = pd.DataFrame(records)

    elif file_ext == '.csv':
        df = pd.read_csv(file_path)
        
        # 1. Strip hidden spaces from CSV column headers (Crucial for CIC-IDS2017)
        df.columns = [c.strip() for c in df.columns]
        
        # Create a lowercase mapping to catch variations like 'protocol' or 'length'
        col_map = {c.lower(): c for c in df.columns}
        
        # 2. Safely map or fallback the 'Protocol' column
        if 'Protocol' not in df.columns:
            if 'protocol' in col_map:
                df['Protocol'] = df[col_map['protocol']]
            else:
                df['Protocol'] = 'TCP'  # Safe fallback if completely missing
                
        # 3. Safely map or fallback the 'Length' column
        if 'Length' not in df.columns:
            if 'length' in col_map:
                df['Length'] = df[col_map['length']]
            elif 'total length of fwd packets' in col_map: # CIC-IDS2017 specific
                df['Length'] = df[col_map['total length of fwd packets']]
            else:
                df['Length'] = 64  # Safe fallback if completely missing

        # 4. Fill in missing display data for the UI
        if 'Packet_ID' not in df.columns:
            df['Packet_ID'] = range(1, len(df) + 1)
        if 'Src_IP' not in df.columns:
            df['Src_IP'] = '192.168.1.50'
        if 'Dst_IP' not in df.columns:
            df['Dst_IP'] = '10.0.0.1'
    else:
        raise ValueError(f"Unsupported file format: {file_ext}")

    if df.empty:
        raise ValueError("No valid IP packets found in this capture file.")

    return df


def analyze_capture(df, model_path="threat_detector_rf.joblib"):
    """
    Runs inference over extracted features, records processing latency, 
    and triggers SIEM alerts for malicious packets.
    """
    if not os.path.exists(model_path):
        # Fallback dummy rule engine if you haven't generated the ML model yet
        df['Threat_Score'] = 0.05
        df['Prediction'] = 0
        df['Status'] = 'BENIGN'
        return df, 0.001

    model = joblib.load(model_path)

    proto_map = {'TCP': 0, 'UDP': 1, 'DNS': 2, 'ICMP': 3, 'OTHER': 4}
    df['Protocol_Encoded'] = df['Protocol'].map(lambda p: proto_map.get(str(p).upper(), 4))
    df['Packet_Length'] = pd.to_numeric(df['Length'], errors='coerce').fillna(0)

    X = df[['Packet_Length', 'Protocol_Encoded']]

    # Benchmark Latency
    start_time = time.time()
    predictions = model.predict(X)
    probabilities = model.predict_proba(X)
    duration = time.time() - start_time

    df['Prediction'] = predictions
    df['Threat_Score'] = [round(prob[1] * 100, 2) for prob in probabilities]
    df['Status'] = df['Prediction'].apply(lambda x: 'THREAT DETECTED' if x == 1 else 'BENIGN')

    # ==========================================
    # TRIGGER WAZUH ALERTS FOR ANOMALIES
    # ==========================================
    # Filter for packets with a threat score of 90% or higher
    malicious_packets = df[df['Threat_Score'] >= 90.0]
    
    # Iterate through only the flagged packets and write them to the JSON log
    for _, row in malicious_packets.iterrows():
        trigger_siem_alert(row.to_dict())
    # ==========================================

    return df, duration