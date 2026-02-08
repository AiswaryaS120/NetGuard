# test_flood.py
# PURPOSE: Generate safe test traffic to verify NetGuard Flood Detection
# TARGET: 127.0.0.1 (Localhost)

from scapy.all import IP, TCP, send
import time
import sys

import socket

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def run_test():
    # target_ip = "127.0.0.1" 
    target_ip = get_local_ip() # Use actual LAN IP for visibility
    # target_ip = "127.0.0.1" # FORCE for Loopback Testing
    packet_count = 150

    
    print(f"[*] Starting Flood Simulation against {target_ip}...")
    print(f"[*] Sending {packet_count} packets...")

    # Create a harmless packet (TCP SYN to a random port)
    packet = IP(dst=target_ip)/TCP(dport=80, flags="S")

    start_time = time.time()
    
    # Send packets as fast as possible
    send(packet, count=packet_count, verbose=0)
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"[*] Done!")
    print(f"[*] Sent {packet_count} packets in {duration:.2f} seconds.")
    print(f"[*] Rate: {packet_count / duration:.2f} packets/sec")
    
    if (packet_count / duration) > 100:
        print("\n[SUCCESS] This speed SHOULD trigger your Flood Alert.")
    else:
        print("\n[WARNING] Too slow. Your PC logic might reset the counter before hitting 100.")

if __name__ == "__main__":
    # Safety confirmation
    confirm = input("This will generate traffic to Localhost. Type 'yes' to proceed: ")
    if confirm.lower() == "yes":
        run_test()
    else:
        print("Test cancelled.")