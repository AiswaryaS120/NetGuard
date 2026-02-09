from scapy.all import get_if_list, get_working_if, show_interfaces

print("--- Scapy Interfaces ---")
show_interfaces()

print("\n--- Default Interface ---")
print(get_working_if())
