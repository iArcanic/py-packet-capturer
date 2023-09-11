from scapy.all import sniff
from scapy.layers.inet import IP as IPv4
import datetime
import os

# Define the network interface to capture packets from
iface = "en0"

# Function to create a packet filter based on user-defined rules
def create_packet_filter():
    print("Packet Filter Options:")
    print("1. Source IP")
    print("2. Destination IP")
    print("3. Source Port")
    print("4. Destination Port")
    print("5. Protocol (TCP/UDP/ICMP)")
    print("6. Clear Filter")

    filter_rules = []

    while True:
        choice = int(input("Enter your choice (1-6): "))

        if choice == 1:
            source_ip = input("Enter source IP address: ")
            filter_rules.append(f"ip src {source_ip}")
            break
        elif choice == 2:
            destination_ip = input("Enter destination IP address: ")
            filter_rules.append(f"ip dst {destination_ip}")
            break 
        elif choice == 3:
            source_port = input("Enter source port: ")
            filter_rules.append("tcp and src port " + str(source_port))
            break
        elif choice == 4:
            destination_port = input("Enter destination port: ")
            filter_rules.append("tcp and dst port " + str(destination_port))
            break
        elif choice == 5:
            protocol = input("Enter protocol (tcp/udp/icmp): ").lower()
            if protocol in ["tcp", "udp", "icmp"]:
                filter_rules.append(f"{protocol}")
                break
            else:
                print("Invalid protocol. Please enter 'tcp', 'udp', or 'icmp'.")
        elif choice == 6:
            filter_rules = []
            print("Filter cleared.")
        else:
            print("Invalid choice. Please enter a valid option (1-6).")

    return " and ".join(filter_rules)

# Function to filter packets by source IP address
def packet_filter(packet):
    return IPv4 in packet

def analyse_packet(packet):
    if IPv4 in packet:
        source_ip = packet[IPv4].src
        destination_ip = packet[IPv4].dst

        # Check if the packet matches the defined filter rules
        if filter_rule and not packet.haslayer(filter_rule):
            return

        # Generate a filename with current timestamp
        timestamp = datetime.datetime.now()
        filename = f"packet_log_{timestamp.strftime('%Y-%m-%d_%H-%M-%S')}.txt"

        # Define the folder path in the user's home directory
        log_folder = os.path.expanduser("~/packet_logs")

        # Ensure the folder exists; create it if not
        os.makedirs(log_folder, exist_ok=True)

        # Construct the full path to the saved file
        full_path = os.path.join(log_folder, filename)

        # Log packet information to a file in packet_logs folder
        with open(full_path, "a") as logfile:
            logfile.write(f"Source IP: {source_ip}, Destination IP: {destination_ip}\n")

        # Print information to console
        print(f"Source IP: {source_ip}, Destination IP: {destination_ip}")

        # Print a message indicating the saved filename
        print(f"Packet information saved to file: {full_path}")

while True:
    print("Packet Capture Options:")
    print("1. Filter Packets")
    print("2. Capture All Packets")
    choice = int(input("Enter your choice (1 or 2): "))

    if choice == 1:
        # User wants to filter packets
        filter_rule = create_packet_filter()
        break
    elif choice == 2:
        # User wants to capture all packets
        filter_rule = None
        break
    else:
        print("Invalid choice. Please enter 1 or 2.")

num_packets = int(input("Enter the number of packets to capture: "))

packets = sniff(iface=iface, filter=filter_rule, prn=analyse_packet, count=num_packets)

# Print or log the filtered packets
for packet in packets:
    print(packet.summary())
