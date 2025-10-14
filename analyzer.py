# analyzer.py
import threading
import pandas as pd
import time
from collections import deque, defaultdict, Counter
from datetime import datetime, timedelta
import hashlib

def now_iso():
    return datetime.utcnow().isoformat(sep=" ", timespec="seconds")

class Analyzer:
    """
    Holds packet records, computes statistics, and raises simple alerts:
      - Port scan detection (many distinct dest ports from same src within window)
      - High traffic detection (kbps over short window)
      - Suspicious IP blacklist match (optional)
    """
    def __init__(self, portscan_window=10, portscan_threshold=20, high_traffic_threshold_kbps=1000):
        self.lock = threading.Lock()
        self.packets = deque(maxlen=20000)  # keep recent packets
        self.alerts = deque(maxlen=1000)
        self.port_history = defaultdict(lambda: deque())  # src_ip -> deque of (timestamp, dst_port)
        self.byte_history = deque()  # (timestamp, bytes)
        self.portscan_window = portscan_window
        self.portscan_threshold = portscan_threshold
        self.high_traffic_threshold_kbps = high_traffic_threshold_kbps
        self.blacklist = set()  # put suspicious IPs here if needed

    def reset(self):
        with self.lock:
            self.packets.clear()
            self.alerts.clear()
            self.port_history.clear()
            self.byte_history.clear()

    def add_packet(self, pkt_meta: dict):
        with self.lock:
            pkt_meta['recv_time'] = datetime.utcnow()
            self.packets.appendleft(pkt_meta)
            # byte history
            self.byte_history.append((pkt_meta['recv_time'], pkt_meta.get('length', 0)))
            # port history for port-scan detection
            if pkt_meta.get('src_ip') and pkt_meta.get('dst_port'):
                self.port_history[pkt_meta['src_ip']].append((pkt_meta['recv_time'], pkt_meta['dst_port']))
            # run detectors
            self._detect_portscan(pkt_meta['src_ip'])
            self._detect_high_traffic()
            # blacklist check
            if pkt_meta.get('src_ip') in self.blacklist:
                self._raise_alert("Blacklist", f"Packet from blacklisted IP", src=pkt_meta.get('src_ip'))

    def _raise_alert(self, typ, desc, src=None):
        self.alerts.append({
            "time": now_iso(),
            "type": typ,
            "desc": desc,
            "src": src
        })

    def _detect_portscan(self, src_ip):
        if not src_ip:
            return
        window = timedelta(seconds=self.portscan_window)
        now = datetime.utcnow()
        dq = self.port_history[src_ip]

        # remove old entries
        while dq and (now - dq[0][0]) > window:
            dq.popleft()
        distinct_ports = set(p for (_, p) in dq)
        if len(distinct_ports) >= self.portscan_threshold:
            self._raise_alert("PortScan", f"Detected {len(distinct_ports)} distinct destination ports in {self.portscan_window}s", src=src_ip)
            dq.clear()  # reset after alert

    def _detect_high_traffic(self):
        # consider last 10 seconds
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=10)
        # remove old entries
        while self.byte_history and self.byte_history[0][0] < cutoff:
            self.byte_history.popleft()
        total_bytes = sum(b for (_, b) in self.byte_history)
        kbps = (total_bytes * 8) / 1000.0 / 10.0  # kilobits per second approx
        if kbps > self.high_traffic_threshold_kbps:
            self._raise_alert("HighTraffic", f"Avg {kbps:.1f} kbps over last 10s > threshold {self.high_traffic_threshold_kbps} kbps")
        # store last known kbps
        self._last_kbps = kbps

    def drain_alerts(self):
        """Return and clear alerts (up to last N)"""
        with self.lock:
            arr = list(self.alerts)
            self.alerts.clear()
        return arr

    def get_recent_packets_df(self, max_rows=200):
        with self.lock:
            if not self.packets:
                return pd.DataFrame()
            rows = list(self.packets)[:max_rows]
        df = pd.DataFrame(rows)
        # format columns
        if 'recv_time' in df.columns:
            df['recv_time'] = df['recv_time'].dt.strftime("%H:%M:%S")
        important_cols = ['recv_time', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'proto', 'length', 'info']
        cols = [c for c in important_cols if c in df.columns]
        return df[cols]

    def get_stats(self):
        with self.lock:
            total = len(self.packets)
            srcs = set(p.get('src_ip') for p in self.packets if p.get('src_ip'))
            dsts = set(p.get('dst_ip') for p in self.packets if p.get('dst_ip'))
            kbps = getattr(self, "_last_kbps", 0.0)
        return {"total_packets": total, "unique_src": len(srcs), "unique_dst": len(dsts), "kbps": kbps}

    def get_summary_markdown(self):
        s = self.get_stats()
        md = f"**Total packets:** {s['total_packets']}  \n**Unique src IPs:** {s['unique_src']}  \n**Unique dst IPs:** {s['unique_dst']}  \n**Approx kbps:** {s['kbps']:.2f}"
        return md
