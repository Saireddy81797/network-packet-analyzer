# analyzer.py
import os
from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import time

def is_running_on_streamlit_cloud():
    """
    Streamlit Cloud sets the env var STREAMLIT_SERVER_PORT or
    we can detect if running in a container without privileges.
    """
    # Primary check for Streamlit Cloud environment variable
    if os.environ.get("STREAMLIT_SERVER_PORT") is not None:
        return True
    # Fallback: check common CI/container indicators (optional)
    return False

def capture_packets_live(packet_count=100, iface=None):
    """
    Attempt live capture. Caller must ensure running with privileges.
    """
    print(f"🔍 Capturing {packet_count} live packets... Please wait.")
    if iface:
        packets = sniff(count=packet_count, iface=iface)
    else:
        packets = sniff(count=packet_count)
    print(f"✅ Captured {len(packets)} packets.")
    return packets

def capture_packets_from_pcap(pcap_path="sample_data/sample.pcap"):
    """
    Offline capture: read pcap from disk (safe for Streamlit Cloud)
    """
    from scapy.all import rdpcap
    print(f"📂 Reading packets from pcap: {pcap_path}")
    pkts = rdpcap(pcap_path)
    print(f"✅ Read {len(pkts)} packets from pcap.")
    return pkts

def capture_packets(packet_count=100, iface=None, force_offline=False):
    """
    Generic capture wrapper:
      - If running on Streamlit Cloud (or force_offline=True), use the pcap file.
      - Otherwise, attempt live capture.
    """
    if force_offline or is_running_on_streamlit_cloud():
        # Use offline sample pcap — ensure sample_data/sample.pcap exists in repo
        return capture_packets_from_pcap()
    else:
        return capture_packets_live(packet_count=packet_count, iface=iface)

def analyze_packets(packets):
    data = []
    for pkt in packets:
        if IP in pkt:
            protocol = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other"
            data.append({
                "Time": time.strftime("%H:%M:%S", time.localtime(pkt.time)),
                "Source IP": pkt[IP].src,
                "Destination IP": pkt[IP].dst,
                "Protocol": protocol,
                "Length": len(pkt)
            })
    df = pd.DataFrame(data)
    return df

def detect_intrusion(df):
    alerts = []
    if df.empty:
        return ["No packets captured to analyze."]
    
    src_counts = df['Source IP'].value_counts()
    for ip, count in src_counts.items():
        if count > 50:  # arbitrary threshold
            alerts.append(f"⚠️ Possible Port Scan detected from {ip} ({count} packets)")
    if not alerts:
        alerts.append("✅ No suspicious activity detected.")
    return alerts
