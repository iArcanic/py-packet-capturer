from scapy.all import sniff
from scapy.layers.inet import IP as IPv4
import datetime
import os

# Define the network interface to capture packets from
iface = "en0"

# Function to filter packets by source IP address
def packet_filter(packet):
    return IPv4 in packet

def analyse_packet(packet):
    if IPv4 in packet:
        source_ip = packet[IPv4].src
        destination_ip = packet[IPv4].dst

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

# Sniff packets and apply the filter
packets = sniff(iface=iface, filter="ip", lfilter=packet_filter, prn=analyse_packet, count=10)

# Print or log the filtered packets
for packet in packets:
    print(packet.summary())
