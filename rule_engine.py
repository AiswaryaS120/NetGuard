# rule_engine.py
import time
from collections import defaultdict

class LogicEngine:
    def __init__(self):
        # --- CONFIGURATION ---
        self.FLOOD_THRESHOLD = 180       # packets in scanning window (Standard)
        self.SCAN_THRESHOLD  = 15        # unique ports (Standard)
        self.WINDOW_SECONDS  = 3.0       # Standard window

        # --- MEMORY (sliding window style) ---
        self.ip_traffic = defaultdict(list)          # list of timestamps per IP
        self.port_hits  = defaultdict(lambda: defaultdict(list))  # ip → port → timestamps

    def check_packet(self, packet_data):
        """
        Returns alert string if anomaly detected, else None
        """
        now = time.time()
        src_ip = packet_data.get('src')
        dst_port = packet_data.get('dst_port')

        if not src_ip:
            return None

        # --- 1. UPDATE STATE (Always run updates first) ---
        
        # A. Update IP Traffic (Flood tracking)
        self.ip_traffic[src_ip] = [
            t for t in self.ip_traffic[src_ip]
            if now - t < self.WINDOW_SECONDS
        ]
        self.ip_traffic[src_ip].append(now)
        pkt_count = len(self.ip_traffic[src_ip])

        # B. Update Port Hits (Scan tracking)
        unique_port_count = 0
        if dst_port is not None and dst_port != 0:
            flag = packet_data.get('flag', '')
            # Filter: Only count SYN packets (Connection Initiation)
            is_syn = 'S' in str(flag) and 'A' not in str(flag)
            
            if is_syn:
                self.port_hits[src_ip][dst_port].append(now)
            
            # Clean old accesses for this active port
            # (We only clean ports we touch or iterate all? Iterating all is slow.
            # Lazy cleaning: Clean when accessed or when checking)
            self.port_hits[src_ip][dst_port] = [
                t for t in self.port_hits[src_ip][dst_port]
                if now - t < self.WINDOW_SECONDS
            ]

            # Count currently active unique ports
            active_ports = [
                port for port in self.port_hits[src_ip]
                if any(now - t < self.WINDOW_SECONDS for t in self.port_hits[src_ip][port])
            ]
            unique_port_count = len(active_ports)

        # --- 2. CHECK RULES (Priority: Scan > Flood) ---

        # RULE 1: Possible Port Scan (Check FIRST to correctly identify scans)
        # Debug print
        # if unique_port_count > 1: print(f"[RULE DEBUG] {src_ip} touched {unique_port_count} ports")
        if unique_port_count >= self.SCAN_THRESHOLD:
            return f"[!] PORT SCAN DETECTED: {src_ip} touched {unique_port_count} unique ports in last {self.WINDOW_SECONDS:.1f}s"

        # RULE 2: Possible Flood / DDoS
        # Debug print
        # print(f"[RULE DEBUG] {src_ip} sent {pkt_count} pkts in window")
        if pkt_count >= self.FLOOD_THRESHOLD:
            return f"[!] FLOOD DETECTED: {src_ip} → {pkt_count} pkts in last {self.WINDOW_SECONDS:.1f}s"

        return None