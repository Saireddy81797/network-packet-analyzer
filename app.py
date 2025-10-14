# app.py
import streamlit as st
from analyzer import capture_packets, analyze_packets, detect_intrusion, is_running_on_streamlit_cloud

st.set_page_config(page_title="Network Packet Analyzer", layout="wide")
st.title("🧠 Network Packet Analyzer & Intrusion Detection System")

st.markdown("""
Analyze network packets in real-time using Python + Scapy.

**Note:** Streamlit Cloud does not allow raw packet sniffing. The app will use an offline `sample.pcap` file when deployed. To run live capture, run locally with admin/sudo privileges.
---
""")

# UI controls
packet_count = st.slider("Select number of packets to capture (ignored in offline mode)", 10, 300, 50)
iface = st.text_input("Network interface (for local live capture, e.g., eth0)", value="")
run_local_live = st.checkbox("Force live capture (local only)", value=False)

# Detect if running on Streamlit Cloud
running_on_cloud = is_running_on_streamlit_cloud()
if running_on_cloud:
    st.warning("Running on Streamlit Cloud — live packet sniffing disabled. Using offline pcap or synthetic data.")

# Capture button
if st.button("🚀 Start Capture"):
    with st.spinner("Capturing packets..."):
        # force_offline if on cloud or user didn't check local live
        force_offline = running_on_cloud or not run_local_live
        packets = capture_packets(packet_count, iface=iface if iface else None, force_offline=force_offline)
        df = analyze_packets(packets)
        alerts = detect_intrusion(df)

    st.success(f"✅ Captured {len(df)} packet records successfully!")
    st.subheader("📊 Packet Summary")
    st.dataframe(df)

    st.subheader("🚨 Intrusion Detection Alerts")
    for alert in alerts:
        if "⚠️" in alert:
            st.error(alert)
        else:
            st.success(alert)
else:
    st.info("Click **Start Capture** to begin analyzing network packets.")
