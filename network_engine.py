import threading
import time
import queue
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf



class TrafficMonitor:
    def __init__(self):
        self.lock = threading.Lock()
        
        # --- Fast O(1) Sliding Window Data Structures ---
        # 1. Source IP Tracking
        self.src_history = defaultdict(deque) # src -> deque of (time, service)
        self.src_service_counts = defaultdict(lambda: defaultdict(int)) # src -> service -> count

        # 2. Destination Host Tracking 
        self.dst_history = defaultdict(deque) # dst -> deque of packets
        self.dst_host_count = defaultdict(int) # dst -> count
        self.dst_host_srv_count = defaultdict(lambda: defaultdict(int)) # dst -> service -> count
        self.dst_host_src_count = defaultdict(lambda: defaultdict(int)) # dst -> src -> count
        self.dst_syn_err = defaultdict(int) # dst -> count
        self.dst_srv_syn_err = defaultdict(lambda: defaultdict(int)) # dst -> service -> count

    def update_and_get_features(self, packet_info):
        current_time = time.time()
        src = packet_info['src_ip']
        dst = packet_info['dst_ip']
        dport = packet_info['dst_port']
        service = dport
        flag = str(packet_info.get('flag', ''))
        
        # Determine if packet is a SYN error (SYN without ACK)
        is_syn_err = 'S' in flag and 'A' not in flag

        with self.lock:
            # --- PHASE 1: Eviction (O(1) amortized) ---
            src_q = self.src_history[src]
            src_srv_counts = self.src_service_counts[src]
            
            while src_q and current_time - src_q[0][0] > 2.0:
                old_time, old_srv = src_q.popleft()
                src_srv_counts[old_srv] -= 1
                if src_srv_counts[old_srv] <= 0:
                    del src_srv_counts[old_srv]

            dst_q = self.dst_history[dst]
            dst_srv_counts = self.dst_host_srv_count[dst]
            dst_src_counts = self.dst_host_src_count[dst]
            
            while dst_q and current_time - dst_q[0]['time'] > 2.0:
                old_p = dst_q.popleft()
                old_srv = old_p['service']
                old_src = old_p['src']
                old_syn_err = old_p['is_syn_err']
                
                self.dst_host_count[dst] -= 1
                dst_srv_counts[old_srv] -= 1
                dst_src_counts[old_src] -= 1
                if old_syn_err:
                    self.dst_syn_err[dst] -= 1
                    self.dst_srv_syn_err[dst][old_srv] -= 1
                
                if dst_srv_counts[old_srv] <= 0: del dst_srv_counts[old_srv]
                if dst_src_counts[old_src] <= 0: del dst_src_counts[old_src]

            # --- PHASE 2: Addition ---
            src_q.append((current_time, service))
            src_srv_counts[service] += 1
            
            dst_q.append({
                'time': current_time,
                'src': src,
                'service': service,
                'is_syn_err': is_syn_err
            })
            self.dst_host_count[dst] += 1
            dst_srv_counts[service] += 1
            dst_src_counts[src] += 1
            if is_syn_err:
                self.dst_syn_err[dst] += 1
                self.dst_srv_syn_err[dst][service] += 1

            # --- PHASE 3: O(1) Feature Calculation ---
            f_duration = 0.0
            f_src_bytes = packet_info['length']
            f_dst_bytes = 0.0
            
            f_count = len(src_q)
            f_srv_count = src_srv_counts.get(service, 0)
            f_same_srv_rate = f_srv_count / f_count if f_count > 0 else 0.0
            f_diff_srv_rate = (f_count - f_srv_count) / f_count if f_count > 0 else 0.0

            f_dst_host_count = self.dst_host_count[dst]
            f_dst_host_srv_count = dst_srv_counts.get(service, 0)
            
            f_dst_host_same_srv_rate = f_dst_host_srv_count / f_dst_host_count if f_dst_host_count > 0 else 0.0
            f_dst_host_diff_srv_rate = (f_dst_host_count - f_dst_host_srv_count) / f_dst_host_count if f_dst_host_count > 0 else 0.0
            f_dst_host_same_src_port_rate = dst_src_counts.get(src, 0) / f_dst_host_count if f_dst_host_count > 0 else 0.0
            
            f_dst_host_serror_rate = self.dst_syn_err[dst] / f_dst_host_count if f_dst_host_count > 0 else 0.0
            f_dst_host_srv_serror_rate = self.dst_srv_syn_err[dst].get(service, 0) / f_dst_host_srv_count if f_dst_host_srv_count > 0 else 0.0

            return [
                f_duration, f_src_bytes, f_dst_bytes,
                f_count, f_srv_count,
                f_same_srv_rate, f_diff_srv_rate,
                f_dst_host_count, f_dst_host_srv_count,
                f_dst_host_same_srv_rate, f_dst_host_diff_srv_rate,
                f_dst_host_same_src_port_rate,
                f_dst_host_serror_rate, f_dst_host_srv_serror_rate
            ]  # 14 features

class SnifferThread(threading.Thread):
    def __init__(self, data_queue):
        super().__init__()
        self.data_queue = data_queue
        self.stop_event = threading.Event()
        self.daemon = True

        # Internal bounded buffer: producer (capture) -> consumer (ML+rules)
        self._raw_queue = queue.Queue(maxsize=10000)

        self.monitor = TrafficMonitor()
        self.logic_engine = None  # Injected by main.py
        self.detector = None      # will be set by manager

    def process_packet(self, packet):
        if not packet.haslayer(IP):
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Ignore DHCP/Bootstrap traffic
        if src_ip == '0.0.0.0':
            return None
        protocol = packet[IP].proto
        length = len(packet)

        src_port = 0
        dst_port = 0
        flag = ''  # Default to empty, NOT 'SF' (which contains 'S' and triggers SYN check)

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flag = str(packet[TCP].flags)
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        packet_info = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'length': length,
            'flag': flag
        }

        ml_features = self.monitor.update_and_get_features(packet_info)

        features = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'src_port': src_port,
            'dst_port': dst_port,
            'timestamp': time.time(),
            'ml_features': ml_features,
            'flag': flag
        }
        return features

    # ------------------------------------------------------------------ #
    # PRODUCER: runs inside Scapy's sniff loop — must be ultra-fast        #
    # ------------------------------------------------------------------ #
    def packet_callback(self, packet):
        """Only captures & queues — never blocks Scapy's sniff loop."""
        if self.stop_event.is_set():
            return
        if packet.haslayer(IP):
            try:
                self._raw_queue.put_nowait(packet)
            except queue.Full:
                pass  # Drop packet rather than block capture

    # ------------------------------------------------------------------ #
    # CONSUMER: separate thread — does all heavy work at its own pace      #
    # ------------------------------------------------------------------ #
    def _consumer_worker(self):
        """Pulls packets from internal queue, runs ML + Rules."""
        while not self.stop_event.is_set():
            try:
                packet = self._raw_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                features = self.process_packet(packet)
                if not features:
                    continue

                # ML check
                if self.detector:
                    anomaly_score = self.detector.predict(features)
                    features['anomaly'] = anomaly_score

                # Rule check
                if self.logic_engine:
                    simple_data = {
                        'src':      features['src_ip'],
                        'dst':      features['dst_ip'],
                        'dst_port': features['dst_port'],
                        'flag':     features.get('flag', ''),
                        'time':     float(packet.time),
                    }
                    alert_msg = self.logic_engine.check_packet(simple_data)
                    if alert_msg:
                        features['rule_alert'] = alert_msg

                self.data_queue.put(features)

            except Exception as e:
                print(f"Consumer error: {e}")

    # ------------------------------------------------------------------ #
    # Interface detection & lifecycle                                       #
    # ------------------------------------------------------------------ #
    def _get_best_iface(self):
        """
        Auto-detect the best interface to sniff on:
        Picks the one with a real LAN IP (192.168.x.x / 10.x.x.x / 172.x.x.x).
        Falls back to Scapy's default if none found.
        """
        import socket
        from scapy.all import get_if_list, get_if_addr
        for iface in get_if_list():
            try:
                addr = get_if_addr(iface)
                if addr and not addr.startswith('0.') and not addr.startswith('127.'):
                    if (addr.startswith('192.168.') or
                        addr.startswith('10.')     or
                        addr.startswith('172.')):
                        return iface, addr
            except Exception:
                continue
        return None, None

    def run(self):
        print("Sniffer thread started...")

        # Start the consumer BEFORE sniffing
        worker = threading.Thread(target=self._consumer_worker, daemon=True)
        worker.start()
        print("[*] Consumer worker started (capture decoupled from ML/rules)")

        iface, addr = self._get_best_iface()
        if iface:
            print(f"[*] Sniffing on interface: {iface}  ({addr})")
        else:
            print("[*] No LAN interface found — using Scapy default interface")

        try:
            sniff(iface=iface,
                  prn=self.packet_callback,
                  store=0,
                  stop_filter=lambda x: self.stop_event.is_set(),
                  promisc=True)
        except Exception as e:
            print(f"Sniffer failed: {e}")
            print("Tip: Run the program as Administrator")

    def stop(self):
        self.stop_event.set()
