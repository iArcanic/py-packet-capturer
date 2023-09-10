from scapy.all import sniff
from scapy.layers.inet import IP as IPv4

# Define the network interface to capture packets from
iface = "en0"

# Function to filter packets by source IP address
def packet_filter(packet):
    return IPv4 in packet

def analyse_packet(packet):
    if IPv4 in packet:
        source_ip = packet[IPv4].src
        destination_ip = packet[IPv4].dst
        print(f"Source IP: {source_ip}, Destination IP: {destination_ip}")

# Sniff packets and apply the filter
packets = sniff(iface=iface, filter="ip", lfilter=packet_filter, prn=analyse_packet, count=10)

# Print or log the filtered packets
for packet in packets:
    print(packet.summary())
