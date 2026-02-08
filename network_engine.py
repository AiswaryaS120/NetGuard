import threading
import time
import queue
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf



class TrafficMonitor:
    def __init__(self):
        self.lock = threading.Lock()
        self.ip_history = defaultdict(list)
        self.service_history = defaultdict(list)
        self.connection_window = deque(maxlen=300)  # increased a bit

    def update_and_get_features(self, packet_info):
        current_time = time.time()
        src = packet_info['src_ip']
        dst = packet_info['dst_ip']
        dport = packet_info['dst_port']
        service = dport

        with self.lock:
            # Clean old - NSL-KDD uses 2 second window
            self.ip_history[src] = [t for t in self.ip_history[src] if current_time - t <= 2.0]
            self.ip_history[src].append(current_time)

            self.service_history[src] = [p for p in self.service_history[src] if current_time - p['time'] <= 2.0]
            self.service_history[src].append({'time': current_time, 'dst': dst, 'service': service})

            self.connection_window.append({
                'src': src,
                'dst': dst,
                'service': service,
                'flag': packet_info.get('flag', 'SF')
            })

            f_duration = 0
            f_src_bytes = packet_info['length']
            f_dst_bytes = 0
            f_count = len(self.ip_history[src])
            f_srv_count = sum(1 for p in self.service_history[src] if p['service'] == service)
            f_same_srv_rate = f_srv_count / f_count if f_count > 0 else 0.0
            f_diff_srv_rate = (f_count - f_srv_count) / f_count if f_count > 0 else 0.0

            host_traffic = [c for c in self.connection_window if c['dst'] == dst]
            f_dst_host_count = len(host_traffic)
            f_dst_host_srv_count = sum(1 for c in host_traffic if c['service'] == service)
            f_dst_host_same_srv_rate = f_dst_host_srv_count / f_dst_host_count if f_dst_host_count > 0 else 0.0
            f_dst_host_diff_srv_rate = (f_dst_host_count - f_dst_host_srv_count) / f_dst_host_count if f_dst_host_count > 0 else 0.0
            f_dst_host_same_src_port_rate = sum(1 for c in host_traffic if c['src'] == src) / f_dst_host_count if f_dst_host_count > 0 else 0.0

            # Still dummy values - improve later if needed
            f_dst_host_serror_rate = 0.0
            f_dst_host_srv_serror_rate = 0.0

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

        self.monitor = TrafficMonitor()
        self.logic_engine = None # Injected by main.py
        self.detector = None   # will be set by manager

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
            flag = packet[TCP].flags
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

    def packet_callback(self, packet):
        if self.stop_event.is_set():
            return

        try:
             # DEBUG: Print packet info to console to verify capture
            # if packet.haslayer(IP):
            #     print(f"[DEBUG] Packet: {packet[IP].src} -> {packet[IP].dst} ({packet[IP].proto})")

            features = self.process_packet(packet)
            if not features:
                return

            # ML check
            if self.detector:
                anomaly_score = self.detector.predict(features)
                features['anomaly'] = anomaly_score

            # Rule check
            if self.logic_engine:
                simple_data = {
                    'src': features['src_ip'],
                    'dst_port': features['dst_port'],
                    'flag': features.get('flag', '')
                }
                alert_msg = self.logic_engine.check_packet(simple_data)
                if alert_msg:
                    features['rule_alert'] = alert_msg

            self.data_queue.put(features)

        except Exception as e:
            print(f"Error processing packet: {e}")

    def run(self):
        print("Sniffer thread started...")

        try:
            # You can set specific interface here:
            # conf.iface = "Wi-Fi"   # Windows example
            # conf.iface = "wlan0"   # Linux example

            sniff(prn=self.packet_callback,
                  store=0,
                  stop_filter=lambda x: self.stop_event.is_set(),
                  promisc=True)  # Try to enable promiscuous mode
        except Exception as e:
            print(f"Sniffer failed: {e}")
            print("Tip: Try running the program with administrator privileges")

    def stop(self):
        self.stop_event.set()