# app.py
import streamlit as st
from sniffer import PacketSniffer
from analyzer import Analyzer
from utils import pretty_bytes
import pandas as pd
import time
import threading

st.set_page_config(page_title="Network Packet Analyzer", layout="wide")

st.title("Network Packet Analyzer & Intrusion Detection")
st.write("Real-time packet capture, analysis, and simple intrusion detection. No frontend coding needed — Streamlit handles the UI.")

# Sidebar controls
st.sidebar.header("Capture Settings")
capture_mode = st.sidebar.selectbox("Mode", ["Live (interface)", "Offline (pcap)"])
if capture_mode == "Live (interface)":
    iface = st.sidebar.text_input("Network Interface (e.g., eth0, wlan0)", value="")
else:
    pcap_path = st.sidebar.text_input("Path to pcap file", value="sample_data/sample.pcap")

st.sidebar.header("Detection thresholds")
portscan_threshold = st.sidebar.number_input("Port-scan attempt threshold (distinct ports per src IP / 10s)", min_value=1, value=20)
high_traffic_threshold_kbps = st.sidebar.number_input("High traffic threshold (kbps)", min_value=1, value=1000)

st.sidebar.header("Capture Controls")
start_btn = st.sidebar.button("Start Capture")
stop_btn = st.sidebar.button("Stop Capture")
clear_btn = st.sidebar.button("Clear Data")

# Initialize app-level objects stored in session_state
if "sniffer" not in st.session_state:
    st.session_state.sniffer = None
if "analyzer" not in st.session_state:
    st.session_state.analyzer = Analyzer(portscan_window=10, portscan_threshold=portscan_threshold,
                                         high_traffic_threshold_kbps=high_traffic_threshold_kbps)

# Update thresholds if changed
st.session_state.analyzer.portscan_threshold = portscan_threshold
st.session_state.analyzer.high_traffic_threshold_kbps = high_traffic_threshold_kbps

cols = st.columns([2, 1])

with cols[0]:
    st.subheader("Live Packet Feed")
    packet_table = st.empty()
    stats_area = st.empty()

with cols[1]:
    st.subheader("Alerts")
    alert_box = st.empty()
    st.subheader("Summary")
    summary_box = st.empty()

# start/stop logic
if start_btn:
    if st.session_state.sniffer is None or not st.session_state.sniffer.is_running:
        st.session_state.sniffer = PacketSniffer(analyzer=st.session_state.analyzer)
        if capture_mode == "Live (interface)":
            if not iface:
                st.error("Please provide a network interface for live capture (e.g., eth0, wlan0).")
            else:
                st.session_state.sniffer.start_live(interface=iface)
        else:
            st.session_state.sniffer.start_offline(pcap_path)
        st.success("Capture started.")
    else:
        st.info("Sniffer already running.")

if stop_btn:
    if st.session_state.sniffer and st.session_state.sniffer.is_running:
        st.session_state.sniffer.stop()
        st.success("Capture stopped.")
    else:
        st.info("Sniffer not running.")

if clear_btn:
    st.session_state.analyzer.reset()
    st.success("Data cleared.")

# UI update loop
def ui_updater():
    try:
        while True:
            # live dataframe (most recent N packets)
            df = st.session_state.analyzer.get_recent_packets_df(max_rows=200)
            if df is None or df.empty:
                packet_table.write("No packets yet.")
            else:
                packet_table.dataframe(df)

            # show stats
            stats = st.session_state.analyzer.get_stats()
            stats_area.metric("Total Packets", stats.get("total_packets", 0))
            stats_area.write(pd.DataFrame([{
                "Unique Source IPs": stats.get("unique_src", 0),
                "Unique Dest IPs": stats.get("unique_dst", 0),
                "Avg kbps (recent)": round(stats.get("kbps", 0), 2)
            }]))

            # alerts
            alerts = st.session_state.analyzer.drain_alerts()
            if alerts:
                for a in alerts[-10:]:
                    alert_box.warning(f"[{a['time']}] {a['type']} - {a['desc']} (src={a.get('src')})")
            else:
                alert_box.info("No alerts")

            # summary
            summary_box.write(st.session_state.analyzer.get_summary_markdown())

            time.sleep(1.2)
    except Exception as e:
        st.error(f"UI updater error: {e}")

# Run UI updater in separate thread when capture is active
if st.session_state.sniffer and st.session_state.sniffer.is_running:
    if "ui_thread" not in st.session_state or not st.session_state.ui_thread.is_alive():
        t = threading.Thread(target=ui_updater, daemon=True)
        st.session_state.ui_thread = t
        t.start()
else:
    # Show static summary when not running
    df = st.session_state.analyzer.get_recent_packets_df(max_rows=50)
    if df is not None and not df.empty:
        packet_table.dataframe(df)
    else:
        packet_table.write("Start capture to see packets here.")

st.sidebar.info("Run Streamlit with: `streamlit run app.py` (use elevated privileges for live capture).")
