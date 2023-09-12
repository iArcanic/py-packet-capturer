from scapy.all import sniff
from scapy.layers.inet import IP as IPv4
import datetime
import os
import time
import networkx as nx
import matplotlib.pyplot as plt

# Define the network interface to capture packets from
iface = "en0"

network_graph = nx.DiGraph()

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
        # Packet IP info
        source_ip = packet[IPv4].src
        destination_ip = packet[IPv4].dst

        # Add edges to network graph
        network_graph.add_edge(source_ip, destination_ip)

        # Check if the packet matches the defined filter rules
        if filter_rule and not packet.haslayer(filter_rule):

            # Generate a filename with current timestamp
            timestamp = datetime.datetime.now()
            filename = f"packet_log_{timestamp.strftime('%Y-%m-%d_%H-%M-%S')}.txt"

            # Define the folder path in the user's home directory
            log_folder = os.path.expanduser("~/packet_logs")

            # Ensure the folder exists; create it if not
            os.makedirs(log_folder, exist_ok=True)

            # Construct the full path to the saved file
            full_path = os.path.join(log_folder, filename)
            print(f"Full path to log file: {full_path}")

            # Log packet information to a file in packet_logs folder
            with open(full_path, "a") as logfile:
                logfile.write(f"Source IP: {source_ip}, Destination IP: {destination_ip}\n")

            # Print information to console
            print(f"Source IP: {source_ip}, Destination IP: {destination_ip}")

            # Print a message indicating the saved filename
            print(f"Packet information saved to file: {full_path}")

            return

def capture_packets_with_duration(duration):
    end_time = time.time() + duration
    packets = []
    while time.time() < end_time:
        packet = sniff(iface=iface, prn=analyse_packet, count = 1)[0]
        packets.append(packet)
    print(f"Capture duration of {duration} seconds completed.")

    # Save packets to log file
    for packet in packets:
        analyse_packet(packet)

# Function to visualize the network graph
def visualize_network_graph():
    plt.figure(figsize=(10, 10))
    pos = nx.spring_layout(network_graph, seed=42)  # Layout for the graph
    nx.draw(network_graph, pos, with_labels=True, node_size=100, node_color='skyblue', font_size=10, font_color='black')
    plt.title("Network Graph")
    plt.show()        

filter_rule = None

while True:
    print("Packet Capture Options:")
    print("1. Filter Packets")
    print("2. Capture All Packets")
    print("3. Specify Capture Duration")
    choice = int(input("Enter your choice (1, 2 or 3): "))

    if choice == 1:
        # User wants to filter packets
        filter_rule = create_packet_filter()

        # Ask the user to choose between duration and number of packets
        capture_option = int(input("Choose capture option:\n1. Capture by Duration\n2. Capture by Number of Packets\nEnter your choice (1 or 2): "))

        if capture_option == 1:
            # Capture by duration
            capture_duration = int(input("Enter the capture duration (in seconds): "))
            capture_packets_with_duration(capture_duration)

        elif capture_option == 2:
            # Capture by number of packets
            num_packets = int(input("Enter the number of packets to capture: "))
            packets = sniff(iface=iface, filter=filter_rule, prn=analyse_packet, count=num_packets)

        else:
            print("Invalid choice for capture option. Please enter 1 or 2.")

        break

    elif choice == 2:
        # User wants to capture all packets
        filter_rule = None
        num_packets = int(input("Enter the number of packets to capture: "))
        packets = sniff(iface=iface, prn=analyse_packet, count=num_packets)
        break

    elif choice == 3:
        # User wants so specify capture duration
        capture_duration = int(input("Enter the capture duration (in seconds): "))
        capture_packets_with_duration(capture_duration)
        break

    else:
        print("Invalid choice. Please enter 1, 2 or 3.")

while True:
    print("Options:")
    print("1. View Network Graph")
    print("2. Exit")
    
    choice = int(input("Enter your choice (1 or 2): "))
    
    if choice == 1:
        # View the network graph
        visualize_network_graph()
    elif choice == 2:
        # Exit the program
        break
    else:
        print("Invalid choice. Please enter 1 or 2.")
