from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP, UDP

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        print(f"\n[+] Packet:")
        print(f"    Source IP      : {src_ip}")
        print(f"    Destination IP : {dst_ip}")

        if TCP in packet:
            print("    Protocol       : TCP")
            print(f"    Source Port    : {packet[TCP].sport}")
            print(f"    Destination Port: {packet[TCP].dport}")
        elif UDP in packet:
            print("    Protocol       : UDP")
            print(f"    Source Port    : {packet[UDP].sport}")
            print(f"    Destination Port: {packet[UDP].dport}")
        else:
            print(f"    Protocol       : {protocol}")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"    Payload (Raw)  : {payload[:50]}")  # Display first 50 bytes only

def start_sniffing():
    print("Starting packet sniffing... (Press CTRL+C to stop)")
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    start_sniffing()
