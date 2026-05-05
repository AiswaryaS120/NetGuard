import threading
import queue
import time
import sys
import os

from network_engine import SnifferThread
from gui_dashboard import NetGuardDashboard

# --- UPDATE 1: IMPORT YOUR MODULE ---

try:
    from rule_engine import LogicEngine
    print("[+] Logic Engine loaded successfully.")
except ImportError:
    print("[-] Logic Engine not found. Rules will be disabled.")
    LogicEngine = None

# Validation of ML imports
try:
    from ml_engine import AnomalyDetector
except ImportError:
    print("[-] ML Engine not found")
    AnomalyDetector = None

def main():
    data_queue = queue.Queue()
    
    # Initialize Engines
    print("Initializing Engines...")
    detector = AnomalyDetector() if AnomalyDetector else None
    
    # --- UPDATE 2: INITIALIZE YOUR ENGINE ---
    logic_engine = LogicEngine() if LogicEngine else None
    
    # Initialize Sniffer Manager directly
    # The Manager will handle creating the SnifferThread when needed
    manager = SnifferManager(data_queue, detector, logic_engine)

    # Define Start/Stop callbacks for GUI using the manager
    def start_sniffing():
        manager.start()

    def stop_sniffing():
        manager.stop()

    print("Starting GUI...")
    app = NetGuardDashboard(
        start_callback=start_sniffing,
        stop_callback=stop_sniffing,
        log_queue=data_queue
    )
    
    app.protocol("WM_DELETE_WINDOW", lambda: (manager.stop(), app.quit()))
    app.mainloop()

class SnifferManager:
    def __init__(self, queue, detector, logic_engine):
        self.queue = queue
        self.detector = detector
        self.logic_engine = logic_engine # Store reference
        self.thread = None
            
    def start(self):
        if self.thread and self.thread.is_alive():
            return
        
        # Use default interface (Wi-Fi/Ethernet) which is more reliable on Windows
        # when targeting LAN IP
        self.thread = SnifferThread(self.queue)
        self.thread.detector = self.detector
        self.thread.logic_engine = self.logic_engine # Inject here too
        self.thread.start()
        
    def stop(self):
        if self.thread:
            self.thread.stop()

if __name__ == "__main__":
    main()