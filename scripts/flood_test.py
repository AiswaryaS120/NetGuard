"""
flood_test.py — NetGuard Self-Test Attack Simulator
Sends real packets to YOUR OWN LAN IP so NetGuard's sniffer captures them.

Run NetGuard first:  python main.py
Then run this:       python flood_test.py   (as Administrator)
"""

import socket
import time
from scapy.all import IP, TCP, sendp, Ether

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_local_ip():
    """Returns the machine's LAN IP (e.g. 192.168.x.x), NOT 127.0.0.1"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def get_best_iface():
    from scapy.all import get_if_list, get_if_addr
    for iface in get_if_list():
        try:
            addr = get_if_addr(iface)
            if addr and not addr.startswith('0.') and not addr.startswith('127.'):
                if (addr.startswith('192.168.') or addr.startswith('10.') or addr.startswith('172.')):
                    return iface
        except Exception:
            continue
    return None


def separator(title):
    print(f"\n{'='*50}")
    print(f"  {title}")
    print(f"{'='*50}")


# ─────────────────────────────────────────────────────────────────────────────
# Attack Simulations
# ─────────────────────────────────────────────────────────────────────────────

def syn_flood(target_ip, iface, count=300):
    """
    Sends rapid SYN packets to trigger DYNAMIC SYN FLOOD alert.
    Rule engine threshold: 30 SYN/s -> 300 in a burst will trigger instantly.
    """
    separator("TEST 1: SYN FLOOD")
    print(f"  Target : {target_ip}:80")
    print(f"  Packets: {count} SYN packets - rapid burst")
    print(f"  Expect : [!] DYNAMIC SYN FLOOD alert in NetGuard\n")

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst=target_ip) / TCP(dport=80, flags="S")
    start = time.time()
    sendp(pkt, iface=iface, count=count, inter=0, verbose=0)
    elapsed = time.time() - start
    rate = count / elapsed if elapsed > 0 else count

    print(f"  Done: {count} pkts in {elapsed:.2f}s = {rate:.0f} SYN/s")
    if rate > 30:
        print("  [SUCCESS] Rate exceeds 30 SYN/s threshold -> ALERT expected")
    else:
        print("  [WARNING] Rate too slow. Run as Administrator for full speed.")


def volume_flood(target_ip, iface, count=2000):
    """
    Sends large volume of TCP ACK packets to trigger DYNAMIC DDoS alert.
    Rule engine threshold: 50 pkt/s -> 2000 burst will trigger.
    """
    separator("TEST 2: DDoS VOLUME FLOOD")
    print(f"  Target : {target_ip}:80")
    print(f"  Packets: {count} TCP packets - rapid burst")
    print(f"  Expect : [!] DYNAMIC DDoS alert in NetGuard\n")

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst=target_ip) / TCP(dport=80, flags="A")
    start = time.time()
    sendp(pkt, iface=iface, count=count, inter=0, verbose=0)
    elapsed = time.time() - start
    rate = count / elapsed if elapsed > 0 else count

    print(f"  Done: {count} pkts in {elapsed:.2f}s = {rate:.0f} pkt/s")
    if rate > 50:
        print("  [SUCCESS] Rate exceeds 50 pkt/s threshold -> ALERT expected")
    else:
        print("  [WARNING] Rate too slow. Run as Administrator for full speed.")


def port_scan(target_ip, iface):
    """
    Sends SYN packets to 25 different ports within 1 second.
    Rule engine threshold: 20 unique ports/sec -> 25 ports will trigger.
    """
    separator("TEST 3: PORT SCAN")
    ports = list(range(100, 125)) # 25 distinct ports
    print(f"  Target : {target_ip}")
    print(f"  Ports  : {ports}")
    print(f"  Expect : [!] PORT SCAN alert in NetGuard\n")

    start = time.time()
    for port in ports:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst=target_ip) / TCP(dport=port, flags="S")
        sendp(pkt, iface=iface, verbose=0)

    elapsed = time.time() - start
    print(f"  Done: {len(ports)} unique ports in {elapsed:.3f}s")
    if elapsed < 3.0:
        print(f"  [SUCCESS] All ports within 3s window -> ALERT expected")
    else:
        print(f"  [WARNING] Took >1s, some ports may have been outside the scan window.")


# ─────────────────────────────────────────────────────────────────────────────
# Main Menu
# ─────────────────────────────────────────────────────────────────────────────

def main():
    target_ip = get_local_ip()
    iface = get_best_iface()

    print("\n" + "="*50)
    print("  NetGuard - Self-Attack Test Tool")
    print("="*50)
    print(f"  Your LAN IP : {target_ip}")
    print(f"  Adapter     : {iface}")
    print("  Make sure NetGuard (main.py) is running first!")
    print("="*50)
    print("\n  Choose test:")
    print("  [1] SYN Flood      -> triggers SYN FLOOD alert")
    print("  [2] DDoS / Volume  -> triggers DDoS alert")
    print("  [3] Port Scan      -> triggers PORT SCAN alert")
    print("  [4] Run ALL tests")
    print("  [0] Exit")

    choice = input("\nEnter choice: ").strip()

    if choice == '1':
        syn_flood(target_ip, iface)
    elif choice == '2':
        volume_flood(target_ip, iface)
    elif choice == '3':
        port_scan(target_ip, iface)
    elif choice == '4':
        syn_flood(target_ip, iface)
        time.sleep(2)   # brief pause between tests
        volume_flood(target_ip, iface)
        time.sleep(2)
        port_scan(target_ip, iface)
    elif choice == '0':
        print("Exiting.")
        return
    else:
        print("Invalid choice.")
        return

    print("\n  Check NetGuard GUI/console for alerts!")


if __name__ == "__main__":
    main()