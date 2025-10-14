# sniffer.py
import threading
from scapy.all import sniff, rdpcap
from analyzer import Analyzer
from datetime import datetime
import socket

def safe_get_proto(pkt):
    if pkt.haslayer("TCP"):
        return "TCP"
    if pkt.haslayer("UDP"):
        return "UDP"
    if pkt.haslayer("ICMP"):
        return "ICMP"
    return "OTHER"

def get_meta_from_pkt(pkt):
    meta = {}
    meta['length'] = len(bytes(pkt)) if hasattr(pkt, '__bytes__') else 0
    meta['proto'] = safe_get_proto(pkt)
    try:
        if pkt.haslayer("IP"):
            meta['src_ip'] = pkt["IP"].src
            meta['dst_ip'] = pkt["IP"].dst
        else:
            meta['src_ip'] = None
            meta['dst_ip'] = None
    except Exception:
        meta['src_ip'] = None
        meta['dst_ip'] = None

    try:
        if pkt.haslayer("TCP"):
            meta['src_port'] = pkt["TCP"].sport
            meta['dst_port'] = pkt["TCP"].dport
            meta['info'] = f"TCP flags={pkt['TCP'].flags}"
        elif pkt.haslayer("UDP"):
            meta['src_port'] = pkt["UDP"].sport
            meta['dst_port'] = pkt["UDP"].dport
            meta['info'] = "UDP"
        else:
            meta['src_port'] = None
            meta['dst_port'] = None
            meta['info'] = safe_get_proto(pkt)
    except Exception:
        meta['src_port'] = None
        meta['dst_port'] = None
        meta['info'] = "parse_err"

    return meta

class PacketSniffer:
    def __init__(self, analyzer: Analyzer):
        self.analyzer = analyzer
        self.thread = None
        self.is_running = False

    def _live_sniff_loop(self, interface):
        # sniff packets indefinitely - callback processes each packet
        def _cb(pkt):
            meta = get_meta_from_pkt(pkt)
            self.analyzer.add_packet(meta)
        sniff(iface=interface, prn=_cb, store=False)

    def start_live(self, interface):
        if self.is_running:
            return
        self.is_running = True
        self.thread = threading.Thread(target=self._live_sniff_loop, args=(interface,), daemon=True)
        self.thread.start()

    def start_offline(self, pcap_path):
        if self.is_running:
            return
        self.is_running = True
        self.thread = threading.Thread(target=self._offline_read, args=(pcap_path,), daemon=True)
        self.thread.start()

    def _offline_read(self, pcap_path):
        try:
            pkts = rdpcap(pcap_path)
            for pkt in pkts:
                if not self.is_running:
                    break
                meta = get_meta_from_pkt(pkt)
                self.analyzer.add_packet(meta)
        except Exception as e:
            print("Error reading pcap:", e)
        finally:
            # stop after file read
            self.is_running = False

    def stop(self):
        # scapy sniff is blocking; stopping live sniffing gracefully is environment-dependent.
        # Here we mark is_running False: for offline reading it will stop; for live sniffing, instruct user to restart.
        self.is_running = False
        # Note: if sniff is blocking, it may not stop immediately. On Linux you can do more advanced approaches.
