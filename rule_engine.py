
import time
import statistics
from collections import defaultdict, deque

class LogicEngine:
    def __init__(self):
        # --- CONFIGURATION ---
        self.LEARNING_WINDOW = 20       # Seconds of history to keep per IP

        # Dynamic threshold equation: T = Mean + (K * StdDev)
        self.SYN_K  = 3.0              # 3-sigma => 99.7% confidence
        self.DDOS_K = 3.0

        # --- SYN Flood defaults (used when history < 2 samples) ---
        self.DEFAULT_SYN_MEAN = 10.0   # Normal ~10 SYN/sec
        self.DEFAULT_SYN_STD  = 3.0

        # --- DDoS / Volume defaults ---
        self.DEFAULT_DDOS_MEAN = 1000.0  # Normal ~1000 pkt/sec
        self.DEFAULT_DDOS_STD  = 300.0

        # Safety floors — never alert below these absolute minimums
        # Lowered so simulated/test attacks are catchable despite network_engine ML bottleneck packet dropping.
        self.MIN_DDOS_THRESHOLD = 50
        self.MIN_SYN_THRESHOLD  = 30

        # --- Port Scan config ---
        # Raised to avoid false positives from normal Windows background traffic.
        self.SCAN_THRESHOLD = 20        # unique ports within window
        self.SCAN_WINDOW    = 3.0       # seconds
        # Define Common Web Ports used only for port scan suppression
        self.COMMON_WEB_PORTS = {80, 443, 8080, 8443}


        # --- Alert cooldown (seconds per IP per attack type) ---
        # Prevents alert storms: once fired, won't re-fire for this many seconds
        self.ALERT_COOLDOWN = 5.0

        # --- Scan-hits cleanup: evict IPs inactive for this long (seconds) ---
        self.SCAN_EVICT_AFTER = 60.0

        # ------------------------------------------------------------------ #
        # --- STATE ---
        # ip_stats: src_ip -> {
        #   'syn_history':   deque(maxlen=LEARNING_WINDOW),
        #   'pkt_history':   deque(maxlen=LEARNING_WINDOW),
        #   'last_sec_time': float,
        #   'current_syn':   int,
        #   'current_pkt':   int,
        # }
        self.ip_stats = defaultdict(lambda: {
            'syn_history':   deque(maxlen=self.LEARNING_WINDOW),
            'pkt_history':   deque(maxlen=self.LEARNING_WINDOW),
            'last_sec_time': time.time(),
            'current_syn':   0,
            'current_pkt':   0,
            'current_flows': set(),
            'dos_consecutive': 0,
        })

        # Port scan sliding window:
        # (src_ip, dst_ip) -> list of (timestamp, dst_port)
        # A real port scan = one src hitting many ports on the SAME dst.
        # This avoids false positives from browsers (many sites, same ports).
        self.scan_hits      = defaultdict(list)
        self.scan_last_seen = {}          # (src_ip, dst_ip) -> last packet timestamp

        # Alert cooldown tracking: (src_ip, alert_type) -> last_alert_time
        self.last_alert_at  = {}

    # ---------------------------------------------------------------------- #
    # Public API                                                               #
    # ---------------------------------------------------------------------- #

    def check_packet(self, packet_data):
        """
        Ingest one packet, update per-IP stats, and return an alert string
        if any anomaly is detected.  Returns None when traffic looks normal.
        """
        now      = packet_data.get('time', time.time())
        src_ip   = packet_data.get('src')
        dst_ip   = packet_data.get('dst')
        dst_port = packet_data.get('dst_port')
        flag     = packet_data.get('flag', '')

        if not src_ip:
            return None

        stats = self.ip_stats[src_ip]

        # ------------------------------------------------------------------ #
        # 1. TIME WINDOW MANAGEMENT                                            #
        #    Handle gaps of >1 second correctly (fill missed seconds with 0)   #
        # ------------------------------------------------------------------ #
        elapsed = now - stats['last_sec_time']
        if elapsed >= 1.0:
            missed_seconds = int(elapsed)   # e.g. 3 seconds of silence => 3 zeros

            # -- Evaluate the completed second for DoS (add context) --
            prev_ddos_thresh = self._calculate_threshold(
                stats['pkt_history'],
                self.DEFAULT_DDOS_MEAN,
                self.DEFAULT_DDOS_STD,
                self.DDOS_K,
                self.MIN_DDOS_THRESHOLD,
            )
            div_ratio = len(stats['current_flows']) / max(1, stats['current_pkt'])
            if stats['current_pkt'] > prev_ddos_thresh and div_ratio < 0.2:
                stats['dos_consecutive'] += 1
            else:
                stats['dos_consecutive'] = 0

            if missed_seconds > 1:
                stats['dos_consecutive'] = 0

            # Commit the previous in-progress second
            stats['syn_history'].append(stats['current_syn'])
            stats['pkt_history'].append(stats['current_pkt'])

            # Fill any fully-missed seconds with zeros
            for _ in range(missed_seconds - 1):
                stats['syn_history'].append(0)
                stats['pkt_history'].append(0)

            # Reset counters for the new current second
            stats['current_syn'] = 0
            stats['current_pkt'] = 0
            stats['current_flows'] = set()
            stats['last_sec_time'] = now

        # ------------------------------------------------------------------ #
        # 2. UPDATE CURRENT-SECOND COUNTERS                                   #
        # ------------------------------------------------------------------ #
        stats['current_pkt'] += 1
        if dst_ip and dst_port:
            stats['current_flows'].add((dst_ip, dst_port))

        # Pure SYN = 'S' flag present, ACK flag absent
        is_syn = 'S' in str(flag) and 'A' not in str(flag)
        if is_syn:
            stats['current_syn'] += 1

        # ------------------------------------------------------------------ #
        # 3. ANOMALY DETECTION                                                #
        # ------------------------------------------------------------------ #
        alerts = []

        # A. SYN Flood -------------------------------------------------------
        syn_thresh = self._calculate_threshold(
            stats['syn_history'],
            self.DEFAULT_SYN_MEAN,
            self.DEFAULT_SYN_STD,
            self.SYN_K,
            self.MIN_SYN_THRESHOLD,
        )
        if is_syn and stats['current_syn'] > syn_thresh:
            if self._can_alert(src_ip, 'SYN', now):
                alerts.append(
                    f"[!] DYNAMIC SYN FLOOD: {src_ip} -> "
                    f"{stats['current_syn']} SYN/s (Threshold: {syn_thresh:.1f})"
                )

        # B. DDoS / Volume ---------------------------------------------------
        ddos_thresh = self._calculate_threshold(
            stats['pkt_history'],
            self.DEFAULT_DDOS_MEAN,
            self.DEFAULT_DDOS_STD,
            self.DDOS_K,
            self.MIN_DDOS_THRESHOLD,
        )
        
        # Exclude Web Ports ONLY for DoS (Smartly) by raising threshold
        if dst_port in self.COMMON_WEB_PORTS:
            ddos_thresh = max(ddos_thresh, 300)
            
        if stats['current_pkt'] > ddos_thresh:
            diversity_ratio = len(stats['current_flows']) / stats['current_pkt']
            
            # Contextual filters: Low diversity AND sustained for at least 2 prior windows
            if diversity_ratio < 0.2 and stats['dos_consecutive'] >= 2:
                # Use a generic 'VOLUME' key for cooldown to avoid expensive checks every packet
                if self._can_alert(src_ip, 'VOLUME', now):
                    # Count active IPs to differentiate DoS vs DDoS
                    active_ips = sum(1 for ip, data in self.ip_stats.items() if now - data['last_sec_time'] < 2.0)
                    attack_type = 'DDoS' if active_ips > 10 else 'DoS'
                    
                    alerts.append(
                        f"[!] DYNAMIC {attack_type} FLOOD: {src_ip} -> "
                        f"{stats['current_pkt']} pkt/s (Threshold: {ddos_thresh:.1f}, Div: {diversity_ratio:.2f})"
                    )

        # C. Port Scan -------------------------------------------------------
        
        # Avoid false positives from established connection replies and browser tabs.
        # Restrict scan detection to SYN-only packets and exclude common web ports.
        if dst_port and dst_port != 0 and dst_ip and is_syn:
            if dst_port in self.COMMON_WEB_PORTS:
                # Debug Logging - confirm browser traffic is suppressed (uncomment to use)
                # print(f"[DEBUG] Suppressed port scan check for web port {dst_port} from {src_ip}")
                pass
            else:
                key = (src_ip, dst_ip)
                self._update_scan_hits(key, dst_port, now)
                # Count unique ports THIS src hit on THIS specific dst
                unique_ports = len(set(p for _, p in self.scan_hits.get(key, [])))

                if unique_ports > self.SCAN_THRESHOLD:
                    if self._can_alert(src_ip, 'SCAN', now):
                        print(f"[DEBUG] Real scan triggered from {src_ip} on {unique_ports} ports")
                        alerts.append(
                            f"[!] PORT SCAN: {src_ip} -> {dst_ip} "
                            f"hit {unique_ports} ports in {self.SCAN_WINDOW}s"
                        )

        return " | ".join(alerts) if alerts else None

    # ---------------------------------------------------------------------- #
    # Private helpers                                                          #
    # ---------------------------------------------------------------------- #

    def _calculate_threshold(self, history, def_mean, def_std, k, min_floor):
        """
        Threshold = mean + k * std_dev
        Falls back to supplied defaults when there are fewer than 2 samples.
        Always respects the safety floor (min_floor).
        """
        if len(history) < 2:
            mean = def_mean
            std  = def_std
        else:
            mean = statistics.mean(history)
            std  = statistics.stdev(history)

        threshold = mean + (k * std)
        return max(threshold, min_floor)

    def _can_alert(self, src_ip, alert_type, now):
        """
        Returns True only if the cooldown period has elapsed since the last
        alert of this type for this IP.  Records the alert time when True.
        """
        key = (src_ip, alert_type)
        last = self.last_alert_at.get(key, 0.0)
        if now - last >= self.ALERT_COOLDOWN:
            self.last_alert_at[key] = now
            return True
        return False

    def _update_scan_hits(self, key, dst_port, now):
        """
        key = (src_ip, dst_ip)
        Tracks unique dst_ports that src hit on ONE specific dst within
        SCAN_WINDOW seconds. Evicts stale keys to prevent memory leaks.
        """
        self.scan_hits[key].append((now, dst_port))
        self.scan_last_seen[key] = now

        # Prune hits outside the time window
        self.scan_hits[key] = [
            (t, p) for t, p in self.scan_hits[key]
            if now - t < self.SCAN_WINDOW
        ]

        # Periodic eviction of stale (src, dst) pairs
        stale = [
            k for k, last_t in self.scan_last_seen.items()
            if now - last_t > self.SCAN_EVICT_AFTER
        ]
        for k in stale:
            del self.scan_hits[k]
            del self.scan_last_seen[k]