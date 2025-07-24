from packet_logger import init_db, insert_packet
from scapy.all import sniff, IP, TCP, UDP, ARP
from datetime import datetime

def process_packet(packet):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "IP"
        length = len(packet)

        print(f"[{timestamp}] {proto} Packet: {src_ip} → {dst_ip} | Length: {length}")

    elif packet.haslayer(ARP):
        arp_layer = packet[ARP]
        print(f"[{timestamp}] ARP Packet: {arp_layer.psrc} is asking about {arp_layer.pdst}")

print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=process_packet, store=0)
