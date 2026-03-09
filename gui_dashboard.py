import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, filedialog
import psutil
import time
import csv
import threading
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime
from collections import deque
import random
import queue

# ─────────────────────────────────────────────────────────────
# PREMIUM DESIGN SYSTEM — Modern, Minimalistic, No Neon
# ─────────────────────────────────────────────────────────────
COLOR_BG       = "#0f1117"       # Deep slate — primary background
COLOR_SURFACE  = "#181c25"       # Card/panel surface
COLOR_SIDEBAR  = "#141821"       # Sidebar — slightly cooler tone
COLOR_CARD     = "#1e2330"       # Elevated surface for HUD cards
COLOR_BORDER   = "#2a3040"       # Subtle borders
COLOR_BORDER_L = "#353d50"       # Lighter border (hover states)

COLOR_PRIMARY  = "#6C8EFF"       # Soft blue — primary accent (buttons, highlights)
COLOR_PRIMARY_H= "#5577DD"       # Primary hover state
COLOR_SECONDARY= "#4A9EFF"       # Brighter blue — graph line 1
COLOR_DANGER   = "#E5484D"       # Muted red — clean, not neon
COLOR_DANGER_H = "#CC3D42"       # Danger hover
COLOR_WARN     = "#E5A340"       # Warm amber — warnings
COLOR_WARN_H   = "#CC9138"       # Warn hover
COLOR_SUCCESS  = "#46A758"       # Muted green — success/secure
COLOR_SUCCESS_H= "#3D9650"       # Success hover

COLOR_TEXT     = "#E8ECF4"       # High contrast text
COLOR_TEXT_2   = "#9BA4B5"       # Secondary text / labels
COLOR_TEXT_3   = "#5C6578"       # Muted text / disabled
COLOR_GRID     = "#252B38"       # Chart gridlines

# Fonts — clean, modern hierarchy
FONT_BRAND     = ("Segoe UI",  22, "bold")   # Brand/logo
FONT_METRIC    = ("Segoe UI",  26, "bold")   # Big metric values
FONT_HEADING   = ("Segoe UI",  11, "bold")   # Section headers
FONT_BODY      = ("Segoe UI",  11)           # Body text
FONT_SMALL     = ("Segoe UI",  10)           # Small labels
FONT_MONO      = ("Cascadia Mono", 11)       # Monospace (alerts, code)
FONT_MONO_SM   = ("Cascadia Mono", 10)       # Smaller mono
FONT_BTN       = ("Segoe UI",  11, "bold")   # Button text


class NetGuardDashboard(ctk.CTk):
    def __init__(self, start_callback, stop_callback, log_queue):
        super().__init__()

        self.start_callback = start_callback
        self.stop_callback = stop_callback
        self.log_queue = log_queue
        self.is_running = False
        self.traffic_log = deque(maxlen=10000)
        self.sim_active = False  # Track if simulation is running
        
        # --- DATA STREAMS ---
        self.max_data_points = 60
        self.traffic_history = deque([0]*self.max_data_points, maxlen=self.max_data_points)
        self.threat_history = deque([0]*self.max_data_points, maxlen=self.max_data_points)
        
        # State
        self.last_anomaly_time = 0
        self.last_anomaly_type = "low"
        self.packet_count = 0
        self.start_time = 0
        self.pulse_state = False   # For CRITICAL pulse animation
        self.row_counter = 0       # For alternating row colors

        # --- WINDOW ---
        self.title("NetGuard  —  Network Monitor")
        self.geometry("1450x920")
        self.configure(fg_color=COLOR_BG)
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("dark-blue")
        
        # Grid
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self.create_sidebar()
        self.create_header()
        self.create_main_view()
        self.create_status_bar()
        
        self.update_ui_loop()

    # ═══════════════════════════════════════════════════════════
    #  SIDEBAR
    # ═══════════════════════════════════════════════════════════
    def create_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=230, corner_radius=0, fg_color=COLOR_SIDEBAR,
                                    border_width=0)
        self.sidebar.grid(row=0, column=0, rowspan=5, sticky="nsew")
        self.sidebar.grid_propagate(False)
        self.sidebar.grid_rowconfigure(12, weight=1)

        # ── Brand ──
        lbl_logo = ctk.CTkLabel(self.sidebar, text="NetGuard", font=FONT_BRAND, text_color=COLOR_TEXT)
        lbl_logo.grid(row=0, column=0, padx=24, pady=(32, 2), sticky="w")

        lbl_ver = ctk.CTkLabel(self.sidebar, text="v2.1  Pro", font=FONT_SMALL, text_color=COLOR_TEXT_3)
        lbl_ver.grid(row=1, column=0, padx=24, pady=(0, 24), sticky="w")

        # ── Divider ──
        div1 = ctk.CTkFrame(self.sidebar, height=1, fg_color=COLOR_BORDER)
        div1.grid(row=2, column=0, padx=16, sticky="ew", pady=(0, 16))

        # ── Controls ──
        self.btn_start = ctk.CTkButton(
            self.sidebar, text="Start Monitoring", command=self.on_start,
            fg_color=COLOR_PRIMARY, text_color="white", hover_color=COLOR_PRIMARY_H,
            font=FONT_BTN, corner_radius=8, height=38)
        self.btn_start.grid(row=3, column=0, padx=16, pady=(0, 6), sticky="ew")

        self.btn_stop = ctk.CTkButton(
            self.sidebar, text="Stop", command=self.on_stop,
            fg_color="transparent", border_width=1, border_color=COLOR_BORDER_L,
            text_color=COLOR_TEXT_2, state="disabled", hover_color=COLOR_CARD,
            font=FONT_BODY, corner_radius=8, height=34)
        self.btn_stop.grid(row=4, column=0, padx=16, pady=(0, 16), sticky="ew")

        # ── Divider ──
        div2 = ctk.CTkFrame(self.sidebar, height=1, fg_color=COLOR_BORDER)
        div2.grid(row=5, column=0, padx=16, sticky="ew", pady=(0, 12))

        # ── Simulations ──
        lbl_sim = ctk.CTkLabel(self.sidebar, text="Simulations", text_color=COLOR_TEXT_3, font=FONT_SMALL)
        lbl_sim.grid(row=6, column=0, padx=24, pady=(0, 8), sticky="w")

        sim_btn_style = dict(
            fg_color="transparent", border_width=1, corner_radius=8, height=32,
            font=FONT_BODY
        )

        self.btn_sim_dos = ctk.CTkButton(
            self.sidebar, text="DoS Flood", command=lambda: self.simulate_attack("dos"),
            border_color=COLOR_DANGER, text_color=COLOR_DANGER, hover_color="#2a1a1e", **sim_btn_style)
        self.btn_sim_dos.grid(row=7, column=0, padx=16, pady=3, sticky="ew")

        self.btn_sim_scan = ctk.CTkButton(
            self.sidebar, text="Port Scan", command=lambda: self.simulate_attack("portscan"),
            border_color=COLOR_WARN, text_color=COLOR_WARN, hover_color="#2a2318", **sim_btn_style)
        self.btn_sim_scan.grid(row=8, column=0, padx=16, pady=3, sticky="ew")

        self.btn_sim_brute = ctk.CTkButton(
            self.sidebar, text="Brute Force", command=lambda: self.simulate_attack("bruteforce"),
            border_color="#C08040", text_color="#C08040", hover_color="#261e14", **sim_btn_style)
        self.btn_sim_brute.grid(row=9, column=0, padx=16, pady=3, sticky="ew")

        self.btn_sim_normal = ctk.CTkButton(
            self.sidebar, text="Normal Traffic", command=lambda: self.simulate_attack("normal"),
            border_color=COLOR_SUCCESS, text_color=COLOR_SUCCESS, hover_color="#1a2a1e", **sim_btn_style)
        self.btn_sim_normal.grid(row=10, column=0, padx=16, pady=(3, 16), sticky="ew")

        # ── Export (bottom) ──
        self.btn_export = ctk.CTkButton(
            self.sidebar, text="Export Logs", command=self.generate_report,
            fg_color=COLOR_CARD, text_color=COLOR_TEXT_2, hover_color=COLOR_BORDER,
            font=FONT_BODY, corner_radius=8, height=34)
        self.btn_export.grid(row=13, column=0, padx=16, pady=(0, 20), sticky="sew")

    # ═══════════════════════════════════════════════════════════
    #  HEADER — HUD Metric Cards
    # ═══════════════════════════════════════════════════════════
    def create_header(self):
        self.header = ctk.CTkFrame(self, height=100, corner_radius=0, fg_color=COLOR_BG)
        self.header.grid(row=0, column=1, sticky="ew", padx=(0, 20), pady=(12, 0))

        self.card_cpu    = self._hud_card(self.header, "CPU",          "0%",       COLOR_TEXT)
        self.card_mem    = self._hud_card(self.header, "Memory",       "0%",       COLOR_TEXT)
        self.card_net    = self._hud_card(self.header, "Net Flow",     "0/s",      COLOR_TEXT)
        self.card_threat = self._hud_card(self.header, "Threat Level", "Secure",   COLOR_SUCCESS)

    def _hud_card(self, parent, title, value, color):
        frame = ctk.CTkFrame(parent, fg_color=COLOR_CARD, corner_radius=10,
                             border_width=1, border_color=COLOR_BORDER)
        frame.pack(side="left", expand=True, fill="both", padx=6, pady=6)

        lbl_title = ctk.CTkLabel(frame, text=title.upper(), font=FONT_SMALL, text_color=COLOR_TEXT_3)
        lbl_title.pack(anchor="w", padx=16, pady=(12, 0))

        lbl_val = ctk.CTkLabel(frame, text=value, font=FONT_METRIC, text_color=color)
        lbl_val.pack(anchor="w", padx=16, pady=(2, 12))

        frame.lbl_val = lbl_val
        frame.lbl_title = lbl_title
        return frame

    # ═══════════════════════════════════════════════════════════
    #  MAIN VIEW — Charts + Logs
    # ═══════════════════════════════════════════════════════════
    def create_main_view(self):
        # ── GRAPHS ──
        self.graph_container = ctk.CTkFrame(self, fg_color="transparent")
        self.graph_container.grid(row=1, column=1, sticky="nsew", padx=(0, 20), pady=(8, 4))
        self.grid_rowconfigure(1, weight=0)

        self.fig = Figure(figsize=(12, 3.5), dpi=90, facecolor=COLOR_BG)
        self.fig.subplots_adjust(left=0.06, right=0.98, top=0.85, bottom=0.15, wspace=0.25)

        # Traffic Plot
        self.ax1 = self.fig.add_subplot(121)
        self.ax1.set_facecolor(COLOR_BG)
        self.ax1.set_title("Traffic Volume", color=COLOR_TEXT_2, fontsize=10, fontweight='bold', pad=10)
        self.ax1.set_ylabel("pkts/tick", color=COLOR_TEXT_3, fontsize=8)
        self.line1, = self.ax1.plot([], [], color=COLOR_SECONDARY, linewidth=2.5, alpha=0.9)
        self.fill1 = None
        self.ax1.grid(True, color=COLOR_GRID, linestyle='-', alpha=0.5)
        self.ax1.tick_params(colors=COLOR_TEXT_3, labelsize=8)
        for spine in self.ax1.spines.values():
            spine.set_color(COLOR_GRID)

        # Threat Plot
        self.ax2 = self.fig.add_subplot(122)
        self.ax2.set_facecolor(COLOR_BG)
        self.ax2.set_title("Threat Score", color=COLOR_TEXT_2, fontsize=10, fontweight='bold', pad=10)
        self.ax2.set_ylabel("score", color=COLOR_TEXT_3, fontsize=8)
        self.line2, = self.ax2.plot([], [], color=COLOR_DANGER, linewidth=2.5, alpha=0.9)
        self.fill2 = None
        self.ax2.set_ylim(0, 1)
        self.ax2.grid(True, color=COLOR_GRID, linestyle='-', alpha=0.5)
        self.ax2.tick_params(colors=COLOR_TEXT_3, labelsize=8)
        for spine in self.ax2.spines.values():
            spine.set_color(COLOR_GRID)

        # Threat Zone Background Bands
        self.ax2.axhspan(0, 0.3, facecolor=COLOR_SUCCESS, alpha=0.04)
        self.ax2.axhspan(0.3, 0.8, facecolor=COLOR_WARN, alpha=0.04)
        self.ax2.axhspan(0.8, 1.0, facecolor=COLOR_DANGER, alpha=0.06)
        self.ax2.axhline(0.8, color=COLOR_DANGER, linestyle=':', alpha=0.25, linewidth=1)
        self.ax2.axhline(0.3, color=COLOR_WARN, linestyle=':', alpha=0.25, linewidth=1)

        self.canvas = FigureCanvasTkAgg(self.fig, master=self.graph_container)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

        # ── LOGS ──
        self.logs_container = ctk.CTkFrame(self, fg_color="transparent")
        self.logs_container.grid(row=2, column=1, sticky="nsew", padx=(0, 20), pady=(4, 4))
        self.logs_container.grid_columnconfigure(0, weight=3)
        self.logs_container.grid_columnconfigure(1, weight=2)

        # Packet Stream (Treeview)
        self.frame_log = ctk.CTkFrame(self.logs_container, fg_color=COLOR_SURFACE, corner_radius=10,
                                      border_width=1, border_color=COLOR_BORDER)
        self.frame_log.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        ctk.CTkLabel(self.frame_log, text="Packet Stream", font=FONT_HEADING,
                     text_color=COLOR_TEXT_2).pack(anchor="w", padx=14, pady=(10, 4))

        # Treeview styling
        style = tk.ttk.Style()
        style.theme_use("default")
        style.configure("Treeview",
                        background=COLOR_BG,
                        foreground=COLOR_TEXT,
                        fieldbackground=COLOR_BG,
                        borderwidth=0,
                        rowheight=28,
                        font=("Segoe UI", 10))
        style.configure("Treeview.Heading",
                        background=COLOR_SURFACE,
                        foreground=COLOR_TEXT_2,
                        relief="flat",
                        font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[('selected', COLOR_CARD)])

        columns = ("time", "proto", "src", "dst", "len")
        self.tree = tk.ttk.Treeview(self.frame_log, columns=columns, show="headings")

        self.tree.heading("time", text="TIME")
        self.tree.heading("proto", text="PROTO")
        self.tree.heading("src", text="SOURCE")
        self.tree.heading("dst", text="DESTINATION")
        self.tree.heading("len", text="SIZE")

        self.tree.column("time",  width=80,  anchor="center")
        self.tree.column("proto", width=60,  anchor="center")
        self.tree.column("src",   width=160, anchor="w")
        self.tree.column("dst",   width=160, anchor="w")
        self.tree.column("len",   width=60,  anchor="center")

        # Alternating row colors
        self.tree.tag_configure('row_even', background=COLOR_BG)
        self.tree.tag_configure('row_odd',  background="#13161e")

        self.tree.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # Alert Log
        self.frame_alerts = ctk.CTkFrame(self.logs_container, fg_color=COLOR_SURFACE, corner_radius=10,
                                         border_width=1, border_color=COLOR_BORDER)
        self.frame_alerts.grid(row=0, column=1, sticky="nsew")

        ctk.CTkLabel(self.frame_alerts, text="Intrusion Alerts", font=FONT_HEADING,
                     text_color=COLOR_DANGER).pack(anchor="w", padx=14, pady=(10, 4))

        self.txt_alerts = ctk.CTkTextbox(self.frame_alerts, font=FONT_MONO,
                                         text_color=COLOR_DANGER, fg_color="#161019",
                                         corner_radius=6)
        self.txt_alerts.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    # ═══════════════════════════════════════════════════════════
    #  STATUS BAR
    # ═══════════════════════════════════════════════════════════
    def create_status_bar(self):
        self.statusbar = ctk.CTkFrame(self, height=28, corner_radius=0, fg_color=COLOR_SIDEBAR)
        self.statusbar.grid(row=4, column=0, columnspan=2, sticky="ew")

        self.lbl_status = ctk.CTkLabel(
            self.statusbar, text="Ready", font=FONT_MONO_SM, text_color=COLOR_TEXT_3)
        self.lbl_status.pack(side="left", padx=16)

        self.lbl_status_right = ctk.CTkLabel(
            self.statusbar, text="", font=FONT_MONO_SM, text_color=COLOR_TEXT_3)
        self.lbl_status_right.pack(side="right", padx=16)

    # ═══════════════════════════════════════════════════════════
    #  SIMULATION ENGINE
    # ═══════════════════════════════════════════════════════════
    def simulate_attack(self, attack_type):
        if not self.is_running:
            messagebox.showwarning("Not Running", "Start monitoring before running simulations.")
            return
        if self.sim_active:
            return  # Prevent overlapping simulations

        scenarios = {
            "dos": {
                "label": "DoS Attack", "src_ip": "10.0.0.66", "dst_ip": "192.168.1.5",
                "dst_port": 80, "protocol": 6, "count": 80, "delay": 0.05,
                "rule_msg": "[!] DoS FLOOD DETECTED: 10.0.0.66 -> port 80 (SYN flood)",
                "desc": "DoS SYN Flood",
            },
            "portscan": {
                "label": "Port Scan", "src_ip": "172.16.0.99", "dst_ip": "192.168.1.5",
                "dst_port": 0, "protocol": 6, "count": 40, "delay": 0.1,
                "rule_msg": "[!] PORT SCAN DETECTED: 172.16.0.99 scanning multiple ports",
                "desc": "Port Scan",
            },
            "bruteforce": {
                "label": "Brute Force/Malware", "src_ip": "192.168.1.200", "dst_ip": "192.168.1.5",
                "dst_port": 22, "protocol": 6, "count": 60, "delay": 0.08,
                "rule_msg": "[!] BRUTE FORCE DETECTED: 192.168.1.200 -> SSH port 22",
                "desc": "Brute Force",
            },
            "normal": {
                "label": "normal", "src_ip": "192.168.1.10", "dst_ip": "142.250.190.14",
                "dst_port": 443, "protocol": 6, "count": 30, "delay": 0.15,
                "rule_msg": None, "desc": "Normal Traffic",
            },
        }

        scenario = scenarios.get(attack_type)
        if not scenario:
            return

        # Disable sim buttons during injection
        self.sim_active = True
        self._set_sim_buttons_state("disabled")
        self.log_interface(f"Simulation: {scenario['desc']}")

        def inject_packets():
            for i in range(scenario["count"]):
                if not self.is_running:
                    break
                dst_port = scenario["dst_port"]
                if attack_type == "portscan":
                    dst_port = 20 + (i * 7) % 1000

                fake_data = {
                    'timestamp': time.time(), 'protocol': scenario["protocol"],
                    'src_ip': scenario["src_ip"], 'dst_ip': scenario["dst_ip"],
                    'src_port': random.randint(40000, 65000), 'dst_port': dst_port,
                    'ml_features': [], 'anomaly': scenario["label"],
                }
                if i == 0 and scenario["rule_msg"]:
                    fake_data['rule_alert'] = scenario["rule_msg"]
                try:
                    self.log_queue.put_nowait(fake_data)
                except queue.Full:
                    pass
                time.sleep(scenario["delay"])

            # Re-enable buttons after injection completes
            self.sim_active = False
            self.after(0, lambda: self._set_sim_buttons_state("normal"))

        threading.Thread(target=inject_packets, daemon=True).start()

    def _set_sim_buttons_state(self, state):
        for btn in (self.btn_sim_dos, self.btn_sim_scan, self.btn_sim_brute, self.btn_sim_normal):
            btn.configure(state=state)

    # ═══════════════════════════════════════════════════════════
    #  CALLBACKS
    # ═══════════════════════════════════════════════════════════
    def on_start(self):
        self.is_running = True
        self.btn_start.configure(state="disabled", text="Monitoring...")
        self.btn_stop.configure(state="normal")
        self.start_time = time.time()
        self.packet_count = 0
        self.start_callback()
        self.log_interface("System initialized. Listening on interface...")
        self.lbl_status.configure(text="Monitoring active", text_color=COLOR_SUCCESS)

    def on_stop(self):
        self.is_running = False
        self.btn_start.configure(state="normal", text="Start Monitoring")
        self.btn_stop.configure(state="disabled")
        self.stop_callback()
        self.log_interface("Monitoring stopped.")
        self.lbl_status.configure(text="Stopped", text_color=COLOR_TEXT_3)

    def log_interface(self, msg, is_alert=False, data=None):
        timestamp = datetime.now().strftime("%H:%M:%S")

        if is_alert:
            self.txt_alerts.insert("0.0", f"[{timestamp}] {msg}\n")
        elif data:
            tag = 'row_even' if self.row_counter % 2 == 0 else 'row_odd'
            self.row_counter += 1
            self.tree.insert("", 0, values=(
                timestamp,
                data.get('protocol', '?'),
                data.get('src_ip', '?'),
                data.get('dst_ip', '?'),
                data.get('len', '?')
            ), tags=(tag,))
            if len(self.tree.get_children()) > 100:
                self.tree.delete(self.tree.get_children()[-1])

    def update_hud_val(self, card_frame, value, color=None):
        card_frame.lbl_val.configure(text=value)
        if color:
            card_frame.lbl_val.configure(text_color=color)

    # ═══════════════════════════════════════════════════════════
    #  MAIN UPDATE LOOP (500ms interval)
    # ═══════════════════════════════════════════════════════════
    def update_ui_loop(self):
        if self.is_running:
            current_time = time.time()

            # 1. System Resources
            cpu_p = psutil.cpu_percent()
            mem_p = psutil.virtual_memory().percent
            self.update_hud_val(self.card_cpu, f"{cpu_p}%")
            self.update_hud_val(self.card_mem, f"{mem_p}%")

            # 2. Process Packet Queue
            packets_this_tick = 0
            while not self.log_queue.empty():
                try:
                    data = self.log_queue.get_nowait()
                    packets_this_tick += 1
                    self.packet_count += 1
                    self.traffic_log.append(data)

                    src = data.get('src_ip', '?')
                    rule_msg = data.get('rule_alert')

                    data['len'] = random.randint(40, 1500)
                    self.log_interface("", is_alert=False, data=data)

                    # Rule alerts
                    if rule_msg:
                        self.log_interface(f"RULE: {rule_msg}", is_alert=True)
                        self.last_anomaly_time = current_time
                        if "FLOOD" in rule_msg.upper() or "DDOS" in rule_msg.upper():
                            self.last_anomaly_type = "high"
                        else:
                            self.last_anomaly_type = "low"

                    # ML anomalies
                    anomaly_label = data.get('anomaly')
                    if anomaly_label and anomaly_label != 'normal' and anomaly_label != 1:
                        self.log_interface(f"ML: {anomaly_label} detected [{src}]", is_alert=True)
                        self.last_anomaly_time = current_time
                        if anomaly_label in ("DoS Attack", "Brute Force/Malware", "Privilege Escalation"):
                            self.last_anomaly_type = "high"
                        else:
                            self.last_anomaly_type = "low"

                except Exception:
                    break

            # 3. Threat Assessment
            time_since_anomaly = current_time - self.last_anomaly_time
            max_threat = 0.0
            if time_since_anomaly < 5.0 and self.last_anomaly_time > 0:
                if self.last_anomaly_type == "high" or packets_this_tick > 50:
                    max_threat = 1.0
                else:
                    max_threat = 0.5

            # 4. Traffic Stats
            elapsed = current_time - self.start_time
            if elapsed > 0:
                rate = self.packet_count / elapsed
                self.update_hud_val(self.card_net, f"{rate:.1f}/s")

            # 5. Update Charts
            self.traffic_history.append(packets_this_tick)
            # Smooth decay — 0.92 for premium feel
            prev = self.threat_history[-1] if self.threat_history else 0.0
            self.threat_history.append(max_threat if max_threat > 0.0 else prev * 0.92)

            x = list(range(len(self.traffic_history)))
            y1 = list(self.traffic_history)
            y2 = list(self.threat_history)

            self.line1.set_data(x, y1)
            self.line2.set_data(x, y2)

            # Area fills — remove old, draw new
            if self.fill1:
                self.fill1.remove()
            if self.fill2:
                self.fill2.remove()
            self.fill1 = self.ax1.fill_between(x, y1, alpha=0.12, color=COLOR_SECONDARY)
            self.fill2 = self.ax2.fill_between(x, y2, alpha=0.12, color=COLOR_DANGER)

            # Rescale
            max_y = max(self.traffic_history) if self.traffic_history else 10
            self.ax1.set_ylim(0, max(10, max_y * 1.2))
            self.ax1.set_xlim(0, self.max_data_points)
            self.ax2.set_xlim(0, self.max_data_points)

            self.canvas.draw()

            # 6. Threat Level Display + Micro-interactions
            current_threat = self.threat_history[-1] if self.threat_history else 0.0

            if current_threat >= 0.8:
                self.update_hud_val(self.card_threat, "Critical", COLOR_DANGER)
                self.line2.set_color(COLOR_DANGER)
                # ── PULSE ANIMATION ──
                self.pulse_state = not self.pulse_state
                pulse_border = COLOR_DANGER if self.pulse_state else "#3a1520"
                self.card_threat.configure(border_color=pulse_border)
            elif current_threat >= 0.3:
                self.update_hud_val(self.card_threat, "Moderate", COLOR_WARN)
                self.line2.set_color(COLOR_WARN)
                self.card_threat.configure(border_color=COLOR_WARN)
            else:
                self.update_hud_val(self.card_threat, "Secure", COLOR_SUCCESS)
                self.line2.set_color(COLOR_SUCCESS)
                self.card_threat.configure(border_color=COLOR_BORDER)

            # 7. Status Bar
            uptime_s = int(elapsed)
            m, s = divmod(uptime_s, 60)
            h, m = divmod(m, 60)
            self.lbl_status_right.configure(
                text=f"Packets: {self.packet_count:,}    Uptime: {h:02d}:{m:02d}:{s:02d}")

        self.after(500, self.update_ui_loop)

    # ═══════════════════════════════════════════════════════════
    #  EXPORT
    # ═══════════════════════════════════════════════════════════
    def generate_report(self):
        if not self.traffic_log:
            messagebox.showinfo("Info", "No data available.")
            return
        filename = filedialog.asksaveasfilename(defaultextension=".csv")
        if filename:
            pd.DataFrame(self.traffic_log).to_csv(filename, index=False)
