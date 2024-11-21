from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        if protocol == 6:
            proto_name = 'TCP'
        elif protocol == 17:
            proto_name = 'UDP'
        else:
            proto_name = 'Other'
    
        print(f"Source IP: {ip_src} | Destination IP: {ip_dst} | Protocol: {proto_name}")

        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = packet[TCP].payload if packet.haslayer(TCP) else packet[UDP].payload
            print(f"Payload Data: {payload}\n")
sniff(filter="ip", prn=packet_callback, store=0)
